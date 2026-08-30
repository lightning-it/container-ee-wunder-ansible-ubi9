#!/usr/bin/env bash
set -euo pipefail

readonly SBOM_MAX_BYTES=$((64 * 1024 * 1024))

: "${MLX90_TRUST_COMMIT:?exact devtools trust commit is required}"
[[ "$MLX90_TRUST_COMMIT" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || {
  echo "ERROR: invalid devtools trust commit." >&2
  exit 1
}
object_format="$(git rev-parse --show-object-format)"
case "$object_format" in
  sha1) oid_pattern='^[0-9a-f]{40}$' ;;
  sha256) oid_pattern='^[0-9a-f]{64}$' ;;
  *) echo "ERROR: unsupported Git object format." >&2; exit 1 ;;
esac
test "$(git rev-parse HEAD)" = "$MLX90_TRUST_COMMIT"
secure_blob="$(git rev-parse \
  "${MLX90_TRUST_COMMIT}:scripts/mlx90_secure_files.py")"
consumer_blob="$(git rev-parse \
  "${MLX90_TRUST_COMMIT}:scripts/security-release-consumer.py")"
for blob in "$secure_blob" "$consumer_blob"; do
  [[ "$blob" =~ $oid_pattern ]]
  test "$(git cat-file -t "$blob")" = blob
done

run_exact_python_tool() {
  local target="$1"
  shift
  python3 - \
    "$object_format" "$secure_blob" "$consumer_blob" "$target" "$@" \
    3< <(git cat-file blob "$secure_blob") \
    4< <(git cat-file blob "$consumer_blob") <<'PY'
import hashlib
import hmac
import os
import stat
import sys
import types

object_format, secure_oid, consumer_oid, target = sys.argv[1:5]
arguments = sys.argv[5:]
expected_length = {"sha1": 40, "sha256": 64}.get(object_format)
if expected_length is None or target not in {"secure", "consumer"}:
    raise SystemExit("invalid exact Python tool request")


def exact_blob(descriptor, expected_oid, label):
    if (
        len(expected_oid) != expected_length
        or any(character not in "0123456789abcdef" for character in expected_oid)
    ):
        raise SystemExit(f"invalid {label} Git blob OID")
    metadata = os.fstat(descriptor)
    if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISFIFO(metadata.st_mode)):
        raise SystemExit(f"invalid {label} Git blob descriptor")
    chunks = []
    total = 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > 4 * 1024 * 1024:
            raise SystemExit(f"oversized {label} Git blob")
        chunks.append(chunk)
    payload = b"".join(chunks)
    if not payload:
        raise SystemExit(f"empty {label} Git blob")
    digest = hashlib.new(object_format)
    digest.update(f"blob {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    if not hmac.compare_digest(digest.hexdigest(), expected_oid):
        raise SystemExit(f"{label} Git blob OID mismatch")
    return payload


secure_payload = exact_blob(3, secure_oid, "secure helper")
consumer_payload = exact_blob(4, consumer_oid, "consumer")
secure_name = f"git:{secure_oid}"
secure_module = types.ModuleType("mlx90_secure_files")
secure_module.__file__ = secure_name
sys.modules[secure_module.__name__] = secure_module
exec(compile(secure_payload, secure_name, "exec"), secure_module.__dict__)
if target == "secure":
    sys.argv = [secure_name, *arguments]
    raise SystemExit(secure_module.main())

consumer_name = f"git:{consumer_oid}"
sys.argv = [consumer_name, *arguments]
scope = {
    "__name__": "__main__",
    "__file__": consumer_name,
    "__package__": None,
}
exec(compile(consumer_payload, consumer_name, "exec"), scope)
PY
}

detect_targetarch() {
  case "$(uname -m)" in
    x86_64) echo "amd64" ;;
    aarch64 | arm64) echo "arm64" ;;
    *) echo "ERROR: unsupported verification architecture: $(uname -m)" >&2; exit 1 ;;
  esac
}

require_digest_pinned_image() {
  local name="$1" reference="$2"
  [[ "$reference" =~ ^[^[:space:]@]+@sha256:[a-f0-9]{64}$ ]] || {
    echo "ERROR: ${name} must be an immutable image reference with a sha256 digest." >&2
    exit 1
  }
}

capture_generated_file() {
  local source="$1" max_bytes="$2" label="$3" capture
  capture="$(
    run_exact_python_tool secure capture \
      --source "$source" \
      --max-bytes "$max_bytes" \
      --label "$label"
  )"
  jq -e '
    type == "object"
    and keys == ["digest", "payloadBase64", "size"]
    and (.digest | test("^sha256:[0-9a-f]{64}$"))
    and (.payloadBase64 | type == "string" and test("^[A-Za-z0-9+/]*={0,2}$"))
    and (.size | type == "number" and . > 0 and floor == .)
    and ((.payloadBase64 | @base64d | utf8bytelength) == .size)
  ' <<<"$capture" >/dev/null
  printf '%s' "$capture"
}

captured_payload() {
  jq -er '.payloadBase64' <<<"$1" | base64 --decode
}

captured_digest() {
  jq -er '.digest' <<<"$1"
}

required_env=(
  IMAGE_NAME
  IMAGE_DIGEST
  RELEASE_TAG
  VERSION
  SHORT_SHA
  GITHUB_REPOSITORY
  FULL_SHA
  GITHUB_RUN_ID
  GITHUB_RUN_ATTEMPT
  EVIDENCE_NAME
  SECURITY_RELEASE
)
for name in "${required_env[@]}"; do
  [ -n "${!name:-}" ] || { echo "ERROR: ${name} is required." >&2; exit 1; }
done
[[ "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]] || {
  echo "ERROR: GITHUB_RUN_ATTEMPT must be a positive integer." >&2
  exit 1
}
case "$EVIDENCE_NAME" in
  public | certified | bootstrap) ;;
  *) echo "ERROR: invalid EVIDENCE_NAME." >&2; exit 1 ;;
esac
case "$SECURITY_RELEASE" in
  true | false) ;;
  *) echo "ERROR: SECURITY_RELEASE must be true or false." >&2; exit 1 ;;
esac
if [ "$EVIDENCE_NAME" != bootstrap ]; then
  : "${EXPECTED_COLLECTION_VERSION:?EXPECTED_COLLECTION_VERSION is required}"
fi
case "${VERIFY_CONVENIENCE_TAGS:-}" in
  true | false) ;;
  *) echo "ERROR: VERIFY_CONVENIENCE_TAGS must be true or false." >&2; exit 1 ;;
esac
case "${VERIFY_RELEASE_TAGS:-}" in
  true | false) ;;
  *) echo "ERROR: VERIFY_RELEASE_TAGS must be true or false." >&2; exit 1 ;;
esac
if [ "$VERIFY_CONVENIENCE_TAGS" = true ] && [ "$VERIFY_RELEASE_TAGS" != true ]; then
  echo "ERROR: convenience tags cannot be verified without release tags." >&2
  exit 1
fi

image_ref="${IMAGE_NAME}@${IMAGE_DIGEST}"
workflow_identity="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/container-build-publish.yml@refs/tags/${RELEASE_TAG}"
workflow_identity_regexp="^https://github\\.com/${GITHUB_REPOSITORY}/\\.github/workflows/container-build-publish\\.yml@refs/tags/${RELEASE_TAG}$"
case "$(detect_targetarch)" in
  amd64) trivy_default="docker.io/aquasec/trivy:0.74.0@sha256:ee940acbf1f58ebadb42d01434ce4609530bf1b52536afbd1eee66cd7123c5c9" ;;
  arm64) trivy_default="docker.io/aquasec/trivy:0.74.0@sha256:55ad20f8a239a3e95427e60b8aaea38788550c18a3f1772976bebf732e6ae166" ;;
esac
trivy_image="${TRIVY_IMAGE:-$trivy_default}"
require_digest_pinned_image trivy "$trivy_image"
trivy_workspace_args=(-v "$(pwd -P):/repo:ro" -w /repo)
trivy_container_args=(
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges=true
  --security-opt label=disable
  --pids-limit 256
  --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=8g"
)
trivy_ignore_args=()
[ ! -f .trivyignore ] || trivy_ignore_args=(--ignorefile .trivyignore)

verify_tag_digest() {
  local tag="$1" ref digest
  ref="${IMAGE_NAME}:${tag}"
  digest="$(docker buildx imagetools inspect "$ref" --format '{{ .Manifest.Digest }}')"
  [ "$digest" = "$IMAGE_DIGEST" ] || {
    echo "ERROR: ${ref} points to ${digest}, expected ${IMAGE_DIGEST}." >&2
    exit 1
  }
  echo "${ref} -> ${digest}"
}

mkdir -p dist
if [ "$VERIFY_RELEASE_TAGS" = true ]; then
  verify_tag_digest "$RELEASE_TAG"
  verify_tag_digest "$VERSION"
  verify_tag_digest "sha-${SHORT_SHA}"
fi
if [ "$VERIFY_CONVENIENCE_TAGS" = true ]; then
  verify_tag_digest latest
fi

echo "Recording the immutable multi-platform index for ${image_ref}..."
docker buildx imagetools inspect "$image_ref" --raw >"dist/manifest-${EVIDENCE_NAME}.json"
manifest_capture="$(
  capture_generated_file \
    "dist/manifest-${EVIDENCE_NAME}.json" \
    $((16 * 1024 * 1024)) \
    "generated container manifest"
)"
[ "$(captured_digest "$manifest_capture")" = "$IMAGE_DIGEST" ] || {
  echo "ERROR: raw manifest bytes do not match the immutable image digest." >&2
  exit 1
}
captured_payload "$manifest_capture" | jq -e '
  .manifests as $all
  | [$all[] | select(.platform.os == "linux" and (.platform.architecture == "amd64" or .platform.architecture == "arm64"))] as $images
  | ($images | length) == 2
  and ([$images[].platform.architecture] | sort) == ["amd64", "arm64"]
  and all($images[]; (.digest | test("^sha256:[0-9a-f]{64}$")))
  and ([$all[] | select(.platform.os == "unknown") and .digest] | length) >= 2
' >/dev/null

echo "Verifying BuildKit provenance binds the exact source and release run..."
docker buildx imagetools inspect "$image_ref" \
  --format '{{json .Provenance}}' >"${RUNNER_TEMP:?}/provenance-${EVIDENCE_NAME}.json"
provenance_capture="$(
  capture_generated_file \
    "${RUNNER_TEMP:?}/provenance-${EVIDENCE_NAME}.json" \
    $((16 * 1024 * 1024)) \
    "generated BuildKit provenance"
)"
captured_payload "$provenance_capture" | jq -e \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg run_id "$GITHUB_RUN_ID" \
  --arg run_attempt "$GITHUB_RUN_ATTEMPT" \
  --arg source_sha "$FULL_SHA" \
  --arg version "$VERSION" '
    keys == ["linux/amd64", "linux/arm64"]
    and all(.[];
      .SLSA.buildDefinition.externalParameters.request.args[
        "label:org.opencontainers.image.revision"
      ] == $source_sha
      and .SLSA.buildDefinition.externalParameters.request.args[
        "label:org.opencontainers.image.version"
      ] == $version
      and .SLSA.runDetails.builder.id == (
        "https://github.com/" + $repository
        + "/actions/runs/" + $run_id + "/attempts/" + $run_attempt
      )
    )
  ' >/dev/null

echo "Scanning ${IMAGE_NAME}:${RELEASE_TAG} for HIGH and CRITICAL findings (release gate)..."
docker run --rm \
  "${trivy_container_args[@]}" \
  "${trivy_workspace_args[@]}" \
  "$trivy_image" image \
  --cache-dir /tmp/trivy-cache \
  --scanners vuln \
  --ignore-unfixed \
  "${trivy_ignore_args[@]}" \
  --severity HIGH,CRITICAL \
  --exit-code 1 \
  "$image_ref"

echo "Generating the ${EVIDENCE_NAME} CycloneDX component/license SBOM..."
docker run --rm \
  "${trivy_container_args[@]}" \
  "${trivy_workspace_args[@]}" \
  "$trivy_image" image \
  --cache-dir /tmp/trivy-cache \
  --scanners license \
  --format cyclonedx \
  "${trivy_ignore_args[@]}" \
  "$image_ref" >"dist/sbom-${EVIDENCE_NAME}.cdx.json"
sbom_capture="$(
  capture_generated_file \
    "dist/sbom-${EVIDENCE_NAME}.cdx.json" \
    "$SBOM_MAX_BYTES" \
    "generated container SBOM"
)"
captured_payload "$sbom_capture" | jq -e '
  .bomFormat == "CycloneDX"
  and (.specVersion | type == "string")
  and (.components | type == "array")
' >/dev/null

echo "Signing and independently verifying ${image_ref}..."
cosign sign --yes "$image_ref"
cosign verify \
  --certificate-identity-regexp "$workflow_identity_regexp" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-sha "$FULL_SHA" \
  "$image_ref" >"dist/signature-${EVIDENCE_NAME}.json"
signature_capture="$(
  capture_generated_file \
    "dist/signature-${EVIDENCE_NAME}.json" \
    $((16 * 1024 * 1024)) \
    "generated image signature verification"
)"
captured_payload "$signature_capture" | jq -e --arg digest "$IMAGE_DIGEST" '
  type == "array" and length > 0
  and all(.[]; .critical.image["docker-manifest-digest"] == $digest)
' >/dev/null

echo "Recording the installed collection set from the immutable amd64 image..."
docker run --rm --platform linux/amd64 "$image_ref" \
  ansible-galaxy collection list --format json \
  >"dist/installed-collections-${EVIDENCE_NAME}.json"
installed_capture="$(
  capture_generated_file \
    "dist/installed-collections-${EVIDENCE_NAME}.json" \
    $((16 * 1024 * 1024)) \
    "generated installed collection inventory"
)"
captured_payload "$installed_capture" | jq -e 'type == "object"' >/dev/null
if [ "$EVIDENCE_NAME" = bootstrap ]; then
  captured_payload "$installed_capture" | jq -e '
    [to_entries[].value | select(type == "object") | .["lit.supplementary"]?] |
    map(select(. != null)) | length == 0
  ' >/dev/null
else
  captured_payload "$installed_capture" | jq -e --arg expected "$EXPECTED_COLLECTION_VERSION" '
    [to_entries[].value | select(type == "object") | .["lit.supplementary"].version?] |
    map(select(. != null)) == [$expected]
  ' >/dev/null
  if [ "$SECURITY_RELEASE" = true ]; then
    : "${VERIFIED_COLLECTION_ARTIFACT:?verified producer artifact is required for a security release}"
    : "${VERIFIED_COLLECTION_ARTIFACT_DIGEST:?verified producer artifact digest is required for a security release}"
    [[ "$VERIFIED_COLLECTION_ARTIFACT_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || {
      echo "ERROR: verified producer artifact digest is invalid." >&2
      exit 1
    }
    [ -f "$VERIFIED_COLLECTION_ARTIFACT" ] || {
      echo "ERROR: verified producer artifact is unavailable." >&2
      exit 1
    }
    installed_tree="${RUNNER_TEMP:?}/installed-collection-${EVIDENCE_NAME}.tar"
    docker run --rm --platform linux/amd64 "$image_ref" \
      tar -C /usr/share/ansible/collections/ansible_collections/lit/supplementary \
      -cf - . >"$installed_tree"
    run_exact_python_tool consumer verify-installed-tree \
      --artifact "$VERIFIED_COLLECTION_ARTIFACT" \
      --artifact-digest "$VERIFIED_COLLECTION_ARTIFACT_DIGEST" \
      --installed "$installed_tree"
  fi
fi

manifest_digest="$(captured_digest "$manifest_capture")"
signature_digest="$(captured_digest "$signature_capture")"
sbom_digest="$(captured_digest "$sbom_capture")"
installed_digest="$(captured_digest "$installed_capture")"
manifest_json="$(captured_payload "$manifest_capture")"
jq -n \
  --arg image "$IMAGE_NAME" \
  --arg manifest_digest "$IMAGE_DIGEST" \
  --arg manifest_file "manifest-${EVIDENCE_NAME}.json" \
  --arg manifest_file_digest "$manifest_digest" \
  --arg signature_file "signature-${EVIDENCE_NAME}.json" \
  --arg signature_digest "$signature_digest" \
  --arg sbom_file "sbom-${EVIDENCE_NAME}.cdx.json" \
  --arg sbom_digest "$sbom_digest" \
  --arg installed_file "installed-collections-${EVIDENCE_NAME}.json" \
  --arg installed_digest "$installed_digest" \
  --arg expected_version "${EXPECTED_COLLECTION_VERSION:-}" \
  --argjson index "$manifest_json" '
    ($index.manifests
      | map(select(.platform.os == "linux" and (.platform.architecture == "amd64" or .platform.architecture == "arm64")))
      | map({key: (.platform.os + "/" + .platform.architecture), value: .digest})
      | from_entries) as $platforms
    | ($index.manifests
      | map(select(.platform.os == "unknown") | .digest)
      | unique) as $attestations
    | {
        image: $image,
        manifestDigest: $manifest_digest,
        platforms: $platforms,
        attestationDigests: $attestations,
        manifest: {file: $manifest_file, digest: $manifest_file_digest},
        signature: {file: $signature_file, digest: $signature_digest},
        sbom: {file: $sbom_file, digest: $sbom_digest},
        installedCollections: {file: $installed_file, digest: $installed_digest},
        installedCollection: (
          if $expected_version == "" then null
          else {name: "lit.supplementary", version: $expected_version}
          end
        )
      }
  ' >"dist/assurance-${EVIDENCE_NAME}.json"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### ${IMAGE_NAME}"
    echo
    echo "- Manifest digest: \`${IMAGE_DIGEST}\`"
    echo "- Signing identity: \`${workflow_identity}\`"
    echo "- Platforms: \`linux/amd64\`, \`linux/arm64\`"
    echo "- Evidence profile: \`${EVIDENCE_NAME}\`"
    echo
  } >>"$GITHUB_STEP_SUMMARY"
fi
