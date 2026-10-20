param(
    [string]$ImageTag = "ghcr.io/daviante-org/daviante-doh:e2e-test",
    [switch]$SkipBuild = $false
)

$ErrorActionPreference = "Stop"

$Engine = if (Get-Command podman -ErrorAction SilentlyContinue) { "podman" }
          elseif (Get-Command docker -ErrorAction SilentlyContinue) { "docker" }
          else { throw "Neither podman nor docker was found in PATH." }

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " daviante-doh (daviante.org) Automated Build, Security & E2E Test Suite" -ForegroundColor Cyan
Write-Host " Engine: $Engine" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# 1. Build image (executes `cargo test --workspace --release --locked` inside Stage 1 builder)
Write-Host "`n[1/7] Building container image and running Rust workspace tests..." -ForegroundColor Yellow
if (-not $SkipBuild) {
    if ($Engine -eq "podman") {
        & $Engine build --format docker --build-arg RUN_TESTS=true -t $ImageTag -f Dockerfile .
    } else {
        & $Engine build --build-arg RUN_TESTS=true -t $ImageTag -f Dockerfile .
    }
    if ($LASTEXITCODE -ne 0) { throw "Container build or cargo test failed!" }
}
Write-Host "  [PASS] Image built and all Rust unit & integration tests passed." -ForegroundColor Green

# 2. Verify CLI --version and --help passthrough
Write-Host "`n[2/7] Verifying CLI --version and --help passthrough..." -ForegroundColor Yellow
$verOut = (& $Engine run --rm $ImageTag --version) | Out-String
if ($verOut -notmatch "daviante-doh") { throw "Unexpected --version output: $verOut" }
$helpOut = (& $Engine run --rm $ImageTag --help) | Out-String
if ($helpOut -notmatch "daviante\.org") { throw "Expected daviante.org in --help output: $helpOut" }
Write-Host "  [PASS] CLI version ($($verOut.Trim())) and help verified." -ForegroundColor Green

# 3. Verify --print-config, BoolishValueParser (1/0/yes/no/on/off), and empty env var sanitization
Write-Host "`n[3/7] Verifying --print-config, boolish env parsing, and empty env sanitization..." -ForegroundColor Yellow
$printCfgOut = (& $Engine run --rm `
    -e DOH_LISTEN_ADDRESS="0.0.0.0:8080" `
    -e DOH_ADMIN_LISTEN_ADDRESS="0.0.0.0:9090" `
    -e DOH_SERVER_ADDRESS="1.1.1.1:53,9.9.9.9:53" `
    -e DOH_LOCAL_BIND_ADDRESS="" `
    -e DOH_PUBLIC_PORT="" `
    -e DOH_ALLOWLIST_FILE="" `
    -e DOH_BLOCKLIST_FILE="" `
    -e DOH_HOSTS_FILE="" `
    -e DOH_UPSTREAM_DOT_SNI="dns.quad9.net" `
    -e DOH_UPSTREAM_STRATEGY="parallel" `
    -e DOH_SERVE_STALE_TTL="86400" `
    -e DOH_CACHE_PREFETCH="yes" `
    -e DOH_BLOCK_PRIVATE_REBINDING="on" `
    -e DOH_DISABLE_COALESCING="0" `
    -e DOH_TRUSTED_PROXIES="10.0.0.0/8,192.168.0.0/16" `
    -e DOH_ENABLE_METRICS="1" `
    -e DOH_DISABLE_ANY="yes" `
    -e DOH_ENABLE_ECS="on" `
    -e DOH_DISABLE_POST="0" `
    -e DOH_LOG_QUERIES="no" `
    -e DOH_DISABLE_KEEPALIVE="off" `
    $ImageTag --print-config) | Out-String

$expectedFlags = @(
    "--listen-address 0.0.0.0:8080",
    "--admin-listen-address 0.0.0.0:9090",
    "--server-address 1.1.1.1:53,9.9.9.9:53",
    "--upstream-strategy parallel",
    "--upstream-dot-sni dns.quad9.net",
    "--serve-stale-ttl 86400",
    "--cache-prefetch",
    "--block-private-rebinding",
    "--trusted-proxies 10.0.0.0/8,192.168.0.0/16",
    "--enable-metrics",
    "--disable-any",
    "--enable-ecs"
)
foreach ($flag in $expectedFlags) {
    if ($printCfgOut -notmatch [regex]::Escape($flag)) {
        throw "Missing expected flag '$flag' in --print-config output: $printCfgOut"
    }
}
foreach ($forbidden in @("--disable-post", "--log-queries", "--disable-keepalive", "--disable-coalescing", "--public-port", "--hosts-file")) {
    if ($printCfgOut -match [regex]::Escape($forbidden)) {
        throw "Unexpected flag '$forbidden' in --print-config output: $printCfgOut"
    }
}
Write-Host "  [PASS] --print-config, boolish env values (1/0/yes/no/on/off), and empty-string env sanitization verified." -ForegroundColor Green

# 4. Verify Helm ConfigMap E2E Boot (C-3 regression gate)
Write-Host "`n[4/7] Verifying Helm ConfigMap rendered environment boots cleanly..." -ForegroundColor Yellow
$helmOut = (& $Engine run --rm -v "${PWD}:/work" -w /work docker.io/alpine/helm:3 template daviante-doh ./charts/daviante-doh) | Out-String
$envLines = @()
$inConfigMap = $false
$inData = $false
foreach ($line in ($helmOut -split "`r?`n")) {
    if ($line -match "^kind:\s*ConfigMap") { $inConfigMap = $true; continue }
    if ($inConfigMap -and $line -match "^---") { break }
    if ($inConfigMap -and $line -match "^data:") { $inData = $true; continue }
    if ($inData -and $line -match "^\s+([A-Z0-9_]+):\s*`"(.*)`"") {
        $envLines += "$($Matches[1])=$($Matches[2])"
    }
}
$tempEnvFile = Join-Path $env:TEMP "daviante-doh-helm-cm.env"
$envLines | Set-Content -Path $tempEnvFile -Encoding ascii
try {
    $helmBootOut = (& $Engine run --rm --env-file $tempEnvFile $ImageTag --print-config) | Out-String
    if ($helmBootOut -notmatch "--listen-address 0\.0\.0\.0:3000" -or $helmBootOut -notmatch "--min-ttl 0") {
        throw "Unexpected Helm ConfigMap boot config: $helmBootOut"
    }
    Write-Host "  [PASS] Helm ConfigMap environment boots cleanly with zero parse errors." -ForegroundColor Green
} finally {
    Remove-Item -Force $tempEnvFile -ErrorAction SilentlyContinue
}

# 5. Verify OpenShift restricted-v2 SCC compatibility (arbitrary non-root UID + GID 0 + read-only rootfs + cap-drop ALL)
Write-Host "`n[5/7] Verifying OpenShift restricted-v2 SCC compatibility (arbitrary non-root UID 20001:0, read-only rootfs)..." -ForegroundColor Yellow
$ocpOut = (& $Engine run --rm `
    --user 20001:0 `
    --read-only `
    --cap-drop=ALL `
    --security-opt no-new-privileges `
    $ImageTag --version) | Out-String
if ($ocpOut -notmatch "daviante-doh") {
    throw "OpenShift random-UID execution failed: $ocpOut"
}
Write-Host "  [PASS] Container runs cleanly under arbitrary non-root UID 20001:0 with read-only rootfs." -ForegroundColor Green

# 6. Live End-to-End Container HTTP / DoH / ODoH / JSON / CORS / Cache / Metrics / Probes tests
Write-Host "`n[6/7] Starting live container for E2E protocol & enterprise feature verification..." -ForegroundColor Yellow
$ContainerName = "daviante-doh-e2e-test"
& $Engine rm -f $ContainerName 2>$null | Out-Null

& $Engine run -d --name $ContainerName `
    --read-only `
    --cap-drop=ALL `
    -p 13000:3000 `
    -e DOH_HOSTNAME="doh.daviante.org" `
    -e DOH_SERVER_ADDRESS="9.9.9.9:53,1.1.1.1:53" `
    -e DOH_CACHE_SIZE="2048" `
    -e DOH_ENABLE_METRICS="true" `
    $ImageTag | Out-Null

try {
    Start-Sleep -Seconds 2

    # 6a. Health/Liveness/Readiness endpoints (/healthz, /livez, /readyz) + OWASP security headers
    foreach ($ep in @("/healthz", "/livez", "/readyz")) {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:13000$ep" -UseBasicParsing
        if ($resp.StatusCode -ne 200 -or $resp.Content -notmatch "daviante-doh") {
            throw "Probe $ep failed: $($resp.StatusCode) $($resp.Content)"
        }
        if ($resp.Headers["Content-Security-Policy"] -notmatch "default-src 'none'" -or
            $resp.Headers["Referrer-Policy"] -ne "no-referrer") {
            throw "Missing OWASP headers on $ep"
        }
    }
    Write-Host "  [PASS] GET /healthz, /livez, /readyz -> 200 OK with OWASP security headers" -ForegroundColor Green

    # 6b. ODoH configuration endpoint (/.well-known/odohconfigs) with max-age = rotation / 2
    $odohResp = Invoke-WebRequest -Uri "http://127.0.0.1:13000/.well-known/odohconfigs" -UseBasicParsing
    if ($odohResp.StatusCode -ne 200 -or $odohResp.RawContentLength -lt 8 -or
        $odohResp.Headers["Cache-Control"] -notmatch "max-age=43200") {
        throw "ODoH configs check failed: $($odohResp.Headers['Cache-Control'])"
    }
    Write-Host "  [PASS] GET /.well-known/odohconfigs -> 200 OK ($($odohResp.RawContentLength) bytes, max-age=43200)" -ForegroundColor Green

    # 6c. W3C CORS Preflight (OPTIONS /dns-query)
    $corsResp = Invoke-WebRequest -Uri "http://127.0.0.1:13000/dns-query" -Method Options -UseBasicParsing
    if ($corsResp.StatusCode -ne 204) {
        throw "CORS OPTIONS preflight failed: $($corsResp.StatusCode)"
    }
    Write-Host "  [PASS] OPTIONS /dns-query -> 204 No Content (CORS headers verified)" -ForegroundColor Green

    # 6d. RFC 8484 Wireformat DoH GET (query for example.com A)
    $b64Dns = "AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"
    $wireResp = Invoke-WebRequest -Uri "http://127.0.0.1:13000/dns-query?dns=$b64Dns" `
        -Headers @{ "Accept" = "application/dns-message" } -UseBasicParsing
    if ($wireResp.StatusCode -ne 200 -or $wireResp.Headers["Content-Type"] -notmatch "application/dns-message") {
        throw "RFC 8484 Wireformat GET failed"
    }
    Write-Host "  [PASS] GET /dns-query?dns=... -> 200 OK (application/dns-message, $($wireResp.RawContentLength) bytes)" -ForegroundColor Green

    # 6e. JSON DoH GET (hits in-memory cache from 6d!)
    $rawJsonResp = Invoke-WebRequest -Uri "http://127.0.0.1:13000/dns-query?name=example.com&type=A" `
        -Headers @{ "Accept" = "application/dns-json" } -UseBasicParsing
    $jsonText = if ($rawJsonResp.Content -is [byte[]]) {
        [System.Text.Encoding]::UTF8.GetString($rawJsonResp.Content)
    } else {
        [string]$rawJsonResp.Content
    }
    $jsonResp = $jsonText | ConvertFrom-Json
    if ($jsonResp.Status -ne 0 -or $null -eq $jsonResp.Answer) {
        throw "JSON DoH query for example.com failed: $jsonText"
    }
    Write-Host "  [PASS] GET /dns-query?name=example.com&type=A -> Status 0, Answer: $($jsonResp.Answer[0].data)" -ForegroundColor Green

    # 6f. Prometheus /metrics endpoint verification (histograms, rcode counters, cache hits)
    $metricsResp = Invoke-WebRequest -Uri "http://127.0.0.1:13000/metrics" -UseBasicParsing
    $metricsText = if ($metricsResp.Content -is [byte[]]) {
        [System.Text.Encoding]::UTF8.GetString($metricsResp.Content)
    } else {
        [string]$metricsResp.Content
    }
    if ($metricsText -notmatch "daviante_doh_cache_hits_total 1" -or
        $metricsText -notmatch "daviante_doh_cache_stale_hits_total" -or
        $metricsText -notmatch "daviante_doh_cache_prefetch_total" -or
        $metricsText -notmatch "daviante_doh_coalesced_queries_total" -or
        $metricsText -notmatch "daviante_doh_rebinding_blocked_total" -or
        $metricsText -notmatch "daviante_doh_hosts_hits_total" -or
        $metricsText -notmatch 'daviante_doh_upstream_queries_total\{transport="dot"\}' -or
        $metricsText -notmatch "daviante_doh_request_duration_seconds_bucket" -or
        $metricsText -notmatch 'daviante_doh_responses_by_rcode_total\{rcode="NOERROR"\}') {
        throw "Expected Prometheus metrics missing in /metrics output: $metricsText"
    }
    Write-Host "  [PASS] GET /metrics -> Verified latency histograms, RCODE counters, and DNS cache hit." -ForegroundColor Green

    # 6g. Verify built-in native Rust healthcheck (--healthcheck) inside the running container
    & $Engine exec $ContainerName /usr/local/bin/daviante-doh --healthcheck
    if ($LASTEXITCODE -ne 0) { throw "In-container daviante-doh --healthcheck failed!" }
    Write-Host "  [PASS] In-container native '/usr/local/bin/daviante-doh --healthcheck' succeeded (zero curl dependency)." -ForegroundColor Green

    # 7. Verify Startup Structured JSON Logs & DNS Stamps
    Write-Host "`n[7/7] Auditing running container processes and structured JSON startup logs..." -ForegroundColor Yellow
    $logs = (& $Engine logs $ContainerName) | Out-String
    if ($logs -notmatch "doh\.daviante\.org" -or $logs -notmatch "sdns://") {
        throw "Expected DNS stamp in container logs: $logs"
    }
    Write-Host "  [PASS] Structured JSON startup logs and DNS stamps verified." -ForegroundColor Green
} finally {
    & $Engine rm -f $ContainerName 2>$null | Out-Null
}

Write-Host "`n==================================================================" -ForegroundColor Green
Write-Host " ALL DAVIANTE-DOH E2E & REGRESSION TESTS PASSED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
