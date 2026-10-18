param(
    [string]$ImageName = "ghcr.io/daviante-org/daviante-doh",
    [string]$Tag = "latest",
    [switch]$MultiArchContainer,
    [switch]$ExportBinaries
)

$ErrorActionPreference = "Stop"

# Auto-detect container engine (Podman or Docker)
$Engine = if (Get-Command podman -ErrorAction SilentlyContinue) { "podman" }
          elseif (Get-Command docker -ErrorAction SilentlyContinue) { "docker" }
          else { throw "Neither podman nor docker was found in PATH." }

Write-Host "==> Using container engine: $Engine" -ForegroundColor Cyan

if ($MultiArchContainer) {
    $Platforms = "linux/amd64,linux/arm64"
    Write-Host "==> Building multi-arch container image ($Platforms) for ${ImageName}:${Tag}" -ForegroundColor Cyan
    if ($Engine -eq "podman") {
        & podman manifest rm "${ImageName}:${Tag}" 2>$null
        & podman manifest create "${ImageName}:${Tag}"
        & podman build --platform $Platforms --manifest "${ImageName}:${Tag}" -f Dockerfile .
    } else {
        & docker buildx build --platform $Platforms -t "${ImageName}:${Tag}" -f Dockerfile .
    }
} else {
    Write-Host "==> Building container image ${ImageName}:${Tag}" -ForegroundColor Cyan
    & $Engine build -t "${ImageName}:${Tag}" -f Dockerfile .
}

if ($ExportBinaries) {
    Write-Host "==> Cross-compiling standalone daviante-doh binaries for Linux & Windows via container builder..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path "dist" -Force | Out-Null

    $CrossDockerfile = @"
FROM rust:1-alpine3.21 AS cross
RUN apk add --no-cache musl-dev pkgconfig zig mingw-w64-gcc && \
    cargo install cargo-zigbuild && \
    rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-pc-windows-gnu
WORKDIR /build
COPY Cargo.toml LICENSE ./
COPY src ./src
RUN cargo zigbuild --release --target x86_64-unknown-linux-musl && \
    cargo zigbuild --release --target aarch64-unknown-linux-musl && \
    cargo zigbuild --release --target x86_64-pc-windows-gnu
"@
    $CrossDockerfile | Set-Content -Path "dist\Dockerfile.cross" -Encoding UTF8
    & $Engine build -t daviante-doh-cross-builder -f dist\Dockerfile.cross .
    $cid = (& $Engine create daviante-doh-cross-builder).Trim()
    try {
        & $Engine cp "${cid}:/build/target/x86_64-unknown-linux-musl/release/daviante-doh" "dist/daviante-doh-linux-amd64"
        & $Engine cp "${cid}:/build/target/aarch64-unknown-linux-musl/release/daviante-doh" "dist/daviante-doh-linux-arm64"
        & $Engine cp "${cid}:/build/target/x86_64-pc-windows-gnu/release/daviante-doh.exe" "dist/daviante-doh-windows-amd64.exe"
    } finally {
        & $Engine rm -f $cid | Out-Null
        Remove-Item "dist\Dockerfile.cross" -Force -ErrorAction SilentlyContinue
    }
    Write-Host "==> Binaries exported to ./dist/" -ForegroundColor Green
}
