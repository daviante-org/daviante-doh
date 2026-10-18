#!/usr/bin/env sh
# =============================================================================
# Automated Black-Box API & Protocol Tester CI Runner for daviante-doh
# Builds and boots daviante-doh with TLS/HTTP2 on https://127.0.0.1:8443/dns-query,
# executes the 73-case live protocol suite, and collects matrix & metrics files.
# =============================================================================
set -eu

IMAGE_TAG="${IMAGE_TAG:-daviante-doh:live-test}"
CONTAINER_NAME="${CONTAINER_NAME:-daviante-doh-live-qa}"
SKIP_BUILD="${SKIP_BUILD:-false}"
DOH_EVIDENCE_DIR="${DOH_EVIDENCE_DIR:-./test-evidence}"
export DOH_EVIDENCE_DIR

if [ -n "${CONTAINER_ENGINE:-}" ]; then
    ENGINE="$CONTAINER_ENGINE"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    ENGINE="docker"
elif command -v podman >/dev/null 2>&1; then
    ENGINE="podman"
else
    echo "Error: neither docker nor podman found in PATH" >&2
    exit 1
fi

echo "==> [1/4] Preparing ${IMAGE_TAG} image using ${ENGINE}..."
if [ "$SKIP_BUILD" != "true" ]; then
    if [ "$ENGINE" = "podman" ]; then
        "$ENGINE" build --format docker --build-arg BUILD_TLS=true --build-arg RUN_TESTS=false -t "$IMAGE_TAG" -f Dockerfile .
    else
        "$ENGINE" build --build-arg BUILD_TLS=true --build-arg RUN_TESTS=false -t "$IMAGE_TAG" -f Dockerfile .
    fi
fi

CERT_FILE="$(mktemp)"
KEY_FILE="$(mktemp)"

cleanup() {
    mkdir -p "$DOH_EVIDENCE_DIR"
    "$ENGINE" logs "$CONTAINER_NAME" > "${DOH_EVIDENCE_DIR}/container-logs.txt" 2>&1 || true
    "$ENGINE" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    rm -f "$CERT_FILE" "$KEY_FILE"
}
trap cleanup EXIT

cat > "$CERT_FILE" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBmDCCAT+gAwIBAgIUNkDcdb1ZlMu64/GJkM44GkERsaAwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAxNzIzNTE1NFoXDTM2MTAxNDIz
NTE1NFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAErWF7m21jDRyZr+u79nnigFHMXSBZVcsqDn/d0yqFsV8Ch4yNP2S/1XIa
kax2nnW3xeW+SsJi+sA/byCq12JoKaNvMG0wHQYDVR0OBBYEFO0UieoBWoaZqtEf
A2xv5ykf9V2rMB8GA1UdIwQYMBaAFO0UieoBWoaZqtEfA2xv5ykf9V2rMA8GA1Ud
EwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49
BAMCA0cAMEQCIGTM8ArzrRMwK9y1TKy+irluoIIF5as2qdFdSc/AgFEAAiBsPLDg
blVaU9jbWKRNgVekewSGO76v9Kqw7knea8HweA==
-----END CERTIFICATE-----
EOF

cat > "$KEY_FILE" <<'EOF'
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDDxGimCBITAIRnKd
tYIR6+QBODvchStEmUe21mRmAs2hRANCAAStYXubbWMNHJmv67v2eeKAUcxdIFlV
yyoOf93TKoWxXwKHjI0/ZL/VchqRrHaedbfF5b5KwmL6wD9vIKrXYmgp
-----END PRIVATE KEY-----
EOF
chmod 0644 "$CERT_FILE" "$KEY_FILE"

echo "==> [2/4] Starting live container ${CONTAINER_NAME} on https://127.0.0.1:8443/dns-query..."
mkdir -p "$DOH_EVIDENCE_DIR"
"$ENGINE" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

"$ENGINE" create --name "$CONTAINER_NAME" \
    --cap-drop=ALL \
    -p 8443:8443 \
    -e DOH_LISTEN_ADDRESS="0.0.0.0:8443" \
    -e DOH_SERVER_ADDRESS="1.1.1.1:53,8.8.8.8:53,9.9.9.9:53" \
    -e DOH_PATH="/dns-query" \
    -e DOH_TLS_CERT_PATH="/etc/daviante-doh/certs/tls.crt" \
    -e DOH_TLS_CERT_KEY_PATH="/etc/daviante-doh/certs/tls.key" \
    -e DOH_CACHE_SIZE="4096" \
    -e DOH_ENABLE_METRICS="true" \
    -e DOH_MAX_CLIENTS="2048" \
    -e DOH_MAX_CONCURRENT="1024" \
    -e DOH_RATE_LIMIT_RPS="100" \
    -e DOH_RATE_LIMIT_BURST="150" \
    "$IMAGE_TAG" >/dev/null

"$ENGINE" cp "$CERT_FILE" "${CONTAINER_NAME}:/etc/daviante-doh/certs/tls.crt"
"$ENGINE" cp "$KEY_FILE" "${CONTAINER_NAME}:/etc/daviante-doh/certs/tls.key"
"$ENGINE" start "$CONTAINER_NAME" >/dev/null

echo "==> [3/4] Waiting for HTTPS listener readiness (--healthcheck)..."
READY=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if "$ENGINE" exec "$CONTAINER_NAME" /usr/local/bin/daviante-doh --healthcheck >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done

if [ "$READY" -ne 1 ]; then
    echo "Error: daviante-doh container failed healthcheck within 10s" >&2
    "$ENGINE" logs "$CONTAINER_NAME" >&2 || true
    exit 1
fi
echo "    Container healthy and serving HTTP/2 over TLS."

echo "==> [4/4] Executing Live Black-Box API & Protocol Test Suite..."
node ./scripts/e2e/live-api-suite.mjs
