#!/usr/bin/env bash
# Final MLX-90 consumer acceptance. Mutable image tags and caller-provided
# commands are deliberately unsupported.
set -euo pipefail

: "${IMAGE_REF:?IMAGE_REF must include an immutable @sha256 digest}"
: "${EXPECTED_COLLECTION:?EXPECTED_COLLECTION is required}"
: "${EXPECTED_VERSION:?EXPECTED_VERSION is required}"
: "${COSIGN_IDENTITY_REGEXP:?COSIGN_IDENTITY_REGEXP is required}"
: "${COSIGN_ISSUER:?COSIGN_ISSUER is required}"
: "${COSIGN_WORKFLOW_SHA:?COSIGN_WORKFLOW_SHA is required}"
: "${SIGNATURE_RECEIPT:?SIGNATURE_RECEIPT is required}"
: "${SBOM_FILE:?SBOM_FILE is required}"
: "${PROVENANCE_FILE:?PROVENANCE_FILE is required}"
: "${RELEASE_ASSET_DIRECTORY:?RELEASE_ASSET_DIRECTORY is required}"
: "${EXPECTED_REPOSITORY:?EXPECTED_REPOSITORY is required}"
: "${EXPECTED_RELEASE_TAG:?EXPECTED_RELEASE_TAG is required}"
: "${EXPECTED_SOURCE_SHA:?EXPECTED_SOURCE_SHA is required}"

if [[ ! "$IMAGE_REF" =~ @sha256:([0-9a-f]{64})$ ]]; then
  echo "ERROR: IMAGE_REF must end in a full immutable SHA-256 digest." >&2
  exit 1
fi
expected_digest="${BASH_REMATCH[1]}"
[[ "$EXPECTED_COLLECTION" == "lit.supplementary" ]] || {
  echo "ERROR: unsupported collection." >&2
  exit 1
}
[[ "$EXPECTED_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
  echo "ERROR: invalid collection version." >&2
  exit 1
}
[[ "$EXPECTED_REPOSITORY" == "lightning-it/container-ee-wunder-ansible-ubi9" ]] || {
  echo "ERROR: unsupported consumer repository." >&2
  exit 1
}
[[ "$EXPECTED_RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
  echo "ERROR: invalid release tag." >&2
  exit 1
}
[[ "$EXPECTED_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "ERROR: invalid release source SHA." >&2
  exit 1
}

jq -e --arg digest "sha256:${expected_digest}" '
  type == "array" and length > 0
  and all(.[]; .critical.image["docker-manifest-digest"] == $digest)
' "$SIGNATURE_RECEIPT" >/dev/null
jq -e \
  '.bomFormat == "CycloneDX"
   and (.specVersion | type == "string")
   and (.components | type == "array")' \
  "$SBOM_FILE" >/dev/null

script_source="${BASH_SOURCE[0]}"
if [[ "$script_source" == /dev/fd/* ]]; then
  : "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required for sealed policy execution}"
  provenance_validator="${GITHUB_WORKSPACE}/scripts/mlx90_release_provenance.py"
else
  script_directory="$(CDPATH='' cd -- "$(dirname -- "$script_source")" && pwd -P)"
  provenance_validator="${script_directory}/mlx90_release_provenance.py"
fi
[[ -f "$provenance_validator" && -x "$provenance_validator" \
  && ! -L "$provenance_validator" ]] || {
  echo "ERROR: tracked MLX-90 provenance validator is unavailable." >&2
  exit 1
}
python3 "$provenance_validator" verify \
  --provenance "$PROVENANCE_FILE" \
  --repository "$EXPECTED_REPOSITORY" \
  --release-tag "$EXPECTED_RELEASE_TAG" \
  --source-sha "$EXPECTED_SOURCE_SHA" \
  --image-ref "$IMAGE_REF" \
  --assets "$RELEASE_ASSET_DIRECTORY" \
  --sbom "$SBOM_FILE" \
  --signature "$SIGNATURE_RECEIPT"

docker pull "$IMAGE_REF"
resolved="$(docker image inspect "$IMAGE_REF" --format '{{join .RepoDigests "\n"}}')"
grep -Eq "@sha256:${expected_digest}$" <<<"$resolved" || {
  echo "ERROR: pulled digest differs: $resolved" >&2
  exit 1
}

live_signature="$(mktemp)"
trap 'rm -f "$live_signature"' EXIT
cosign verify \
  --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$COSIGN_ISSUER" \
  --certificate-github-workflow-sha "$COSIGN_WORKFLOW_SHA" \
  "$IMAGE_REF" >"$live_signature"
jq -e --arg digest "sha256:${expected_digest}" '
  type == "array" and length > 0
  and all(.[]; .critical.image["docker-manifest-digest"] == $digest)
' "$live_signature" >/dev/null

docker run --rm "$IMAGE_REF" \
  ansible-galaxy collection list "$EXPECTED_COLLECTION" --format json |
  python3 -c '
import json
import sys

collection, expected = sys.argv[1:]
payload = json.load(sys.stdin)
if not isinstance(payload, dict):
    raise SystemExit("ansible-galaxy output must be an object")
versions = [
    data[collection]["version"]
    for data in payload.values()
    if isinstance(data, dict) and collection in data
]
if versions != [expected]:
    raise SystemExit(
        f"installed {collection} versions {versions!r}, expected exactly {expected!r}"
    )
' "$EXPECTED_COLLECTION" "$EXPECTED_VERSION"

printf '%s\n' "MLX-90 immutable acceptance passed for $IMAGE_REF"
