#!/usr/bin/env sh
set -eu

IMAGE_NAME="${IMAGE_NAME:-ghcr.io/daviante-org/daviante-doh}"
TAG="${TAG:-latest}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"

if command -v podman >/dev/null 2>&1; then
    ENGINE="podman"
elif command -v docker >/dev/null 2>&1; then
    ENGINE="docker"
else
    echo "Error: neither podman nor docker found in PATH" >&2
    exit 1
fi

echo "==> Building ${IMAGE_NAME}:${TAG} using ${ENGINE}..."

if [ "${MULTIARCH:-false}" = "true" ]; then
    if [ "$ENGINE" = "podman" ]; then
        podman manifest rm "${IMAGE_NAME}:${TAG}" 2>/dev/null || true
        podman manifest create "${IMAGE_NAME}:${TAG}"
        podman build --platform "$PLATFORMS" --manifest "${IMAGE_NAME}:${TAG}" -f Dockerfile .
    else
        docker buildx build --platform "$PLATFORMS" -t "${IMAGE_NAME}:${TAG}" -f Dockerfile .
    fi
else
    "$ENGINE" build -t "${IMAGE_NAME}:${TAG}" -f Dockerfile .
fi
