#!/usr/bin/env sh
# =============================================================================
# Dynamic Release Notes Generator for daviante-doh
#
# Resolves release highlights dynamically from (in priority order):
#   1. Explicit RELEASE_NOTES_BODY environment variable (e.g. workflow_dispatch)
#   2. Annotated Git tag message (`git tag -a vX.Y.Z -m "..."`)
#   3. Matching `## [X.Y.Z]` or `## [Unreleased]` section in CHANGELOG.md
# Plus dynamic supply-chain coordinates, commit log, and SHA-256 checksums.
# =============================================================================
set -eu

VERSION="${1:?Usage: generate-release-notes.sh <version> <image-digest> <helm-digest> <sha256sums-file> <output-file>}"
IMAGE_DIGEST="${2:-sha256:pending}"
HELM_DIGEST="${3:-sha256:pending}"
SHA256SUMS_FILE="${4:-./dist/SHA256SUMS}"
OUTPUT_FILE="${5:-./dist/RELEASE_NOTES.md}"
CHANGELOG_FILE="${CHANGELOG_FILE:-./CHANGELOG.md}"

TAG="v${VERSION}"
REPO="${GITHUB_REPOSITORY:-daviante-org/daviante-doh}"
REPO_OWNER="$(echo "${REPO}" | cut -d/ -f1 | tr '[:upper:]' '[:lower:]')"
REPO_NAME="$(echo "${REPO}" | cut -d/ -f2)"
IMAGE_REPO="${IMAGE_REPO:-ghcr.io/${REPO_OWNER}/${REPO_NAME}}"
HELM_OCI_URI="${HELM_OCI_URI:-oci://ghcr.io/${REPO_OWNER}/charts/${REPO_NAME}}"
RELEASE_DATE="$(date -u +%Y-%m-%d)"

# -----------------------------------------------------------------------------
# 1. Extract Annotated Git Tag Subject & Body (if tag exists and is annotated)
# -----------------------------------------------------------------------------
TAG_SUBJECT=""
TAG_BODY=""
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null 2>&1; then
    OBJ_TYPE="$(git for-each-ref "refs/tags/${TAG}" --format='%(objecttype)')"
    if [ "${OBJ_TYPE}" = "tag" ]; then
        RAW_SUBJ="$(git for-each-ref "refs/tags/${TAG}" --format='%(contents:subject)')"
        RAW_BODY="$(git for-each-ref "refs/tags/${TAG}" --format='%(contents:body)' | sed '/^-----BEGIN PGP SIGNATURE-----$/,$d' | sed '/^-----BEGIN SSH SIGNATURE-----$/,$d')"
        # Ignore default auto-generated placeholder messages like "Release v0.1.0"
        if [ -n "${RAW_SUBJ}" ] && [ "${RAW_SUBJ}" != "Release ${TAG}" ] && [ "${RAW_SUBJ}" != "${TAG}" ]; then
            TAG_SUBJECT="${RAW_SUBJ}"
        fi
        if [ -n "${RAW_BODY}" ]; then
            TAG_BODY="${RAW_BODY}"
        elif [ -n "${TAG_SUBJECT}" ]; then
            TAG_BODY="${TAG_SUBJECT}"
        fi
    fi
fi

# -----------------------------------------------------------------------------
# 2. Extract matching version section (or [Unreleased]) from CHANGELOG.md
# -----------------------------------------------------------------------------
CHANGELOG_SECTION=""
if [ -f "${CHANGELOG_FILE}" ]; then
    # Try exact version heading first: ## [X.Y.Z] or ## [vX.Y.Z]
    CHANGELOG_SECTION="$(awk -v ver="${VERSION}" '
        /^## \[/ {
            if (in_section) exit;
            if ($0 ~ "^## \\[v?" ver "\\]") {
                in_section = 1;
                next;
            }
        }
        /^---$/ {
            if (in_section) next;
        }
        in_section { print }
    ' "${CHANGELOG_FILE}" | sed -e '/./,$!d' -e :a -e '/^\n*$/{$d;N;ba' -e '}' || true)"

    # Fallback to ## [Unreleased] if exact version heading is not found
    if [ -z "${CHANGELOG_SECTION}" ]; then
        CHANGELOG_SECTION="$(awk '
            /^## \[Unreleased\]/ {
                in_section = 1;
                next;
            }
            /^## \[/ {
                if (in_section) exit;
            }
            /^---$/ {
                if (in_section) next;
            }
            in_section { print }
        ' "${CHANGELOG_FILE}" | sed -e '/./,$!d' -e :a -e '/^\n*$/{$d;N;ba' -e '}' || true)"
    fi
fi

# -----------------------------------------------------------------------------
# 3. Resolve Dynamic Release Title & Release Notes Body
# -----------------------------------------------------------------------------
if [ -n "${RELEASE_TITLE:-}" ]; then
    FINAL_TITLE="${RELEASE_TITLE}"
elif [ -n "${TAG_SUBJECT}" ]; then
    FINAL_TITLE="\`${REPO_NAME}\` \`${TAG}\` — ${TAG_SUBJECT}"
else
    FINAL_TITLE="\`${REPO_NAME}\` \`${TAG}\` — Enterprise Production Release"
fi

# Plain-text title (without markdown backticks) for GitHub Release UI title
PLAIN_TITLE="$(echo "${FINAL_TITLE}" | tr -d '`')"
if [ -n "${RELEASE_TITLE_FILE:-}" ]; then
    printf '%s\n' "${PLAIN_TITLE}" > "${RELEASE_TITLE_FILE}"
fi

HIGHLIGHTS_CONTENT=""
if [ -n "${RELEASE_NOTES_BODY:-}" ]; then
    HIGHLIGHTS_CONTENT="${RELEASE_NOTES_BODY}"
elif [ -n "${TAG_BODY}" ] && [ "${TAG_BODY}" != "${TAG_SUBJECT}" ]; then
    HIGHLIGHTS_CONTENT="${TAG_BODY}"
elif [ -n "${CHANGELOG_SECTION}" ]; then
    HIGHLIGHTS_CONTENT="${CHANGELOG_SECTION}"
elif [ -n "${TAG_SUBJECT}" ]; then
    HIGHLIGHTS_CONTENT="${TAG_SUBJECT}"
else
    HIGHLIGHTS_CONTENT="Production release \`${TAG}\` of \`${REPO_NAME}\`."
fi

# -----------------------------------------------------------------------------
# 4. Resolve Previous Tag & Git Commit Log
# -----------------------------------------------------------------------------
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null 2>&1; then
    END_REF="${TAG}"
else
    END_REF="HEAD"
fi

PREV_TAG="$(git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+' | grep -v "^${TAG}$" | head -n 1 || true)"
if [ -n "${PREV_TAG}" ]; then
    COMMIT_LOG="$(git log "${PREV_TAG}..${END_REF}" --pretty=format:'- `%h` %s (%an)' --no-merges || true)"
    COMPARE_URL="https://github.com/${REPO}/compare/${PREV_TAG}...${TAG}"
else
    COMMIT_LOG="$(git log -n 25 "${END_REF}" --pretty=format:'- `%h` %s (%an)' --no-merges || true)"
    COMPARE_URL="https://github.com/${REPO}/commits/${TAG}"
fi

if [ -z "${COMMIT_LOG}" ]; then
    COMMIT_LOG="- No new commits since \`${PREV_TAG:-initial}\`."
fi

if [ -f "${SHA256SUMS_FILE}" ]; then
    CHECKSUMS="$(cat "${SHA256SUMS_FILE}")"
else
    CHECKSUMS="No checksums file found at ${SHA256SUMS_FILE}"
fi

# -----------------------------------------------------------------------------
# 5. Render Markdown Release Document
# -----------------------------------------------------------------------------
cat > "${OUTPUT_FILE}" <<EOF
# ${FINAL_TITLE}

> **Release Date:** \`${RELEASE_DATE}\` • **Version:** \`${VERSION}\` • **License:** \`Apache-2.0\` • **Maintainer:** [Daviante](https://daviante.org)

---

## 1. What's New in \`${TAG}\`

${HIGHLIGHTS_CONTENT}

---

## 2. Published Artifacts & Supply-Chain Coordinates

| Artifact Type | Target Platform / Format | Registry / Download Coordinate | Digest / Integrity |
| :--- | :--- | :--- | :--- |
| **Multi-Arch Container Image** | \`linux/amd64\`, \`linux/arm64\` (Alpine 3.24 Rootless \`UID 10001:0\`) | \`${IMAGE_REPO}:${VERSION}\`<br/>\`${IMAGE_REPO}:latest\` | \`${IMAGE_DIGEST}\` |
| **Unified Helm Chart (OCI)** | Kubernetes \`1.24+\` & Red Hat OpenShift \`4.12+\` (\`restricted-v2\` SCC) | \`${HELM_OCI_URI}:${VERSION}\` | \`${HELM_DIGEST}\` |
| **Helm Chart Archive** | Helm v3 Package (\`.tgz\`) | [\`${REPO_NAME}-${VERSION}.tgz\`](https://github.com/${REPO}/releases/download/${TAG}/${REPO_NAME}-${VERSION}.tgz) | Verified in \`SHA256SUMS\` |
| **Linux Static Binary (x86_64)** | \`x86_64-unknown-linux-musl\` (Static ELF) | [\`${REPO_NAME}-linux-amd64\`](https://github.com/${REPO}/releases/download/${TAG}/${REPO_NAME}-linux-amd64) | Verified in \`SHA256SUMS\` |
| **Linux Static Binary (ARM64)** | \`aarch64-unknown-linux-musl\` (Static ELF) | [\`${REPO_NAME}-linux-arm64\`](https://github.com/${REPO}/releases/download/${TAG}/${REPO_NAME}-linux-arm64) | Verified in \`SHA256SUMS\` |
| **Windows Standalone Binary** | \`x86_64-pc-windows-gnu\` (PE32+ Executable) | [\`${REPO_NAME}-windows-amd64.exe\`](https://github.com/${REPO}/releases/download/${TAG}/${REPO_NAME}-windows-amd64.exe) | Verified in \`SHA256SUMS\` |

---

## 3. Quick-Start Deployment

### 3.1 Container Runtime (Docker / Rootless Podman)
\`\`\`bash
# Pull by version tag or immutable SHA-256 manifest digest
docker pull ${IMAGE_REPO}:${VERSION}
docker pull ${IMAGE_REPO}@${IMAGE_DIGEST}

# Run with hardened rootless flags
docker run -d --name ${REPO_NAME} \\
  --read-only --cap-drop=ALL --security-opt no-new-privileges:true \\
  -p 3000:3000 \\
  -e DOH_SERVER_ADDRESS="9.9.9.9:53,1.1.1.1:53" \\
  -e DOH_CACHE_SIZE="10000" \\
  -e DOH_SERVE_STALE_TTL="86400" \\
  -e DOH_CACHE_PREFETCH="true" \\
  -e DOH_ENABLE_METRICS="true" \\
  ${IMAGE_REPO}:${VERSION}
\`\`\`

### 3.2 Kubernetes & Red Hat OpenShift (GHCR OCI Helm Chart)
\`\`\`bash
helm upgrade --install ${REPO_NAME} ${HELM_OCI_URI} \\
  --version ${VERSION} \\
  --namespace ${REPO_NAME} --create-namespace \\
  --set config.serverAddress="9.9.9.9:53\\,1.1.1.1:53" \\
  --set config.cacheSize="10000" \\
  --set config.serveStaleTtl="86400" \\
  --set config.cachePrefetch="true"
\`\`\`

---

## 4. Commit Changelog

${COMMIT_LOG}

**Full Diff:** <${COMPARE_URL}>

---

## 5. SHA-256 Checksums (\`SHA256SUMS\`)

\`\`\`text
${CHECKSUMS}
\`\`\`
EOF
