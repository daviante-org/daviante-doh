#!/usr/bin/env sh
set -eu

IMAGE_TAG="${IMAGE_TAG:-ghcr.io/daviante-org/daviante-doh:e2e-test}"
SKIP_BUILD="${SKIP_BUILD:-false}"
RUN_TESTS="${RUN_TESTS:-true}"

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

echo "==> [1/5] Preparing ${IMAGE_TAG} (SKIP_BUILD=${SKIP_BUILD}, RUN_TESTS=${RUN_TESTS})..."
if [ "$SKIP_BUILD" != "true" ]; then
    if [ "$ENGINE" = "podman" ]; then
        "$ENGINE" build --format docker --build-arg BUILD_TLS=true --build-arg RUN_TESTS="$RUN_TESTS" -t "$IMAGE_TAG" -f Dockerfile .
    else
        "$ENGINE" build --build-arg BUILD_TLS=true --build-arg RUN_TESTS="$RUN_TESTS" -t "$IMAGE_TAG" -f Dockerfile .
    fi
fi

echo "==> [2/5] Verifying --print-config, boolish env values, and empty env var sanitization..."
CFG_OUT=$("$ENGINE" run --rm \
    -e DOH_PATH="/custom" \
    -e DOH_LOCAL_BIND_ADDRESS="" \
    -e DOH_ALLOWLIST_FILE="" \
    -e DOH_ENABLE_ECS="1" \
    -e DOH_DISABLE_ANY="yes" \
    -e DOH_LOG_QUERIES="off" \
    "$IMAGE_TAG" --print-config)
echo "$CFG_OUT" | grep -q -- "--path /custom"
echo "$CFG_OUT" | grep -q -- "--enable-ecs"
echo "$CFG_OUT" | grep -q -- "--disable-any"
if echo "$CFG_OUT" | grep -q -- "--log-queries"; then
    echo "Unexpected --log-queries in output: $CFG_OUT" >&2
    exit 1
fi

echo "==> [3/5] Verifying OpenShift restricted-v2 arbitrary UID (20001:0)..."
"$ENGINE" run --rm --user 20001:0 --read-only --cap-drop=ALL "$IMAGE_TAG" --version

echo "==> [4/5] Running live E2E protocol, healthcheck, and metrics tests..."
CID="daviante-doh-e2e-sh"
"$ENGINE" rm -f "$CID" >/dev/null 2>&1 || true
"$ENGINE" run -d --name "$CID" --read-only --cap-drop=ALL -p 13000:3000 -e DOH_CACHE_SIZE=1024 -e DOH_ENABLE_METRICS=true "$IMAGE_TAG"
trap '"$ENGINE" rm -f "$CID" >/dev/null 2>&1 || true' EXIT
sleep 2

curl -fsS "http://127.0.0.1:13000/healthz" | grep -q "daviante-doh"
curl -fsS "http://127.0.0.1:13000/livez" | grep -q "daviante-doh"
curl -fsS "http://127.0.0.1:13000/readyz" | grep -q "daviante-doh"
curl -fsS "http://127.0.0.1:13000/.well-known/odohconfigs" >/dev/null
curl -fsS -H "Accept: application/dns-message" "http://127.0.0.1:13000/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE" >/dev/null
curl -fsS -H "Accept: application/dns-json" "http://127.0.0.1:13000/dns-query?name=example.com&type=A" | grep -q '"Status":0'
curl -fsS "http://127.0.0.1:13000/metrics" | grep -q "daviante_doh_request_duration_seconds_bucket"

echo "==> [5/5] Verifying native in-container daviante-doh --healthcheck..."
"$ENGINE" exec "$CID" /usr/local/bin/daviante-doh --healthcheck

echo "==> All E2E tests passed!"
