#!/usr/bin/env bash
# Final MLX-90 acceptance. Never invoke with a mutable tag.
set -euo pipefail

: "${IMAGE_REF:?IMAGE_REF must include an immutable @sha256 digest}"
: "${EXPECTED_COLLECTION:?EXPECTED_COLLECTION is required}"
: "${EXPECTED_VERSION:?EXPECTED_VERSION is required}"
: "${ACCEPTANCE_COMMAND:?ACCEPTANCE_COMMAND is required}"
: "${COSIGN_IDENTITY_REGEXP:?COSIGN_IDENTITY_REGEXP is required}"
: "${COSIGN_ISSUER:?COSIGN_ISSUER is required}"

[[ "$IMAGE_REF" =~ @sha256:([0-9a-f]{64})$ ]] || { echo "ERROR: IMAGE_REF must end in a full immutable SHA-256 digest" >&2; exit 1; }
expected_digest="${BASH_REMATCH[1]}"

docker pull "$IMAGE_REF"
resolved="$(docker image inspect "$IMAGE_REF" --format '{{join .RepoDigests "\n"}}')"
grep -Eq "@sha256:${expected_digest}$" <<<"$resolved" || { echo "ERROR: pulled digest differs: $resolved" >&2; exit 1; }

cosign verify --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$COSIGN_ISSUER" "$IMAGE_REF" >/dev/null
cosign verify-attestation --type cyclonedx \
  --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$COSIGN_ISSUER" "$IMAGE_REF" >/dev/null
cosign verify-attestation --type slsaprovenance \
  --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$COSIGN_ISSUER" "$IMAGE_REF" >/dev/null

docker run --rm "$IMAGE_REF" ansible-galaxy collection list "$EXPECTED_COLLECTION" --format json |
python3 -c '
import json, sys
collection, expected = sys.argv[1:]
try:
    payload = json.load(sys.stdin)
    versions = [data[collection]["version"] for data in payload.values() if collection in data]
except (json.JSONDecodeError, KeyError, TypeError) as exc:
    raise SystemExit(f"invalid ansible-galaxy collection output: {exc}") from exc
if versions != [expected]:
    raise SystemExit(f"installed {collection} versions {versions!r}, expected exactly {expected!r}")
' "$EXPECTED_COLLECTION" "$EXPECTED_VERSION"

docker run --rm "$IMAGE_REF" bash -euo pipefail -c "$ACCEPTANCE_COMMAND"
printf '%s\n' "MLX-90 final acceptance passed for $IMAGE_REF"
