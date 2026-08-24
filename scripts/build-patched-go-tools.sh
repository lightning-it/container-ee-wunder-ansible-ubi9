#!/usr/bin/env bash
set -euo pipefail

readonly OUT_DIR=/out
readonly SOURCE_DIR=/src
readonly REBUILD_METADATA=lit.1

require_value() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "Error: required build argument ${name} is empty" >&2
    exit 1
  fi
}

clone_exact() {
  local repository="$1"
  local commit="$2"
  local destination="$3"

  git init --quiet "$destination"
  git -C "$destination" remote add origin "$repository"
  git -C "$destination" fetch --quiet --depth=1 origin "$commit"
  git -C "$destination" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
  test "$(git -C "$destination" rev-parse HEAD)" = "$commit"
  test -z "$(git -C "$destination" status --porcelain=v1)"
}

verify_release_tag() {
  local destination="$1"
  local tag="$2"
  local commit="$3"

  git -C "$destination" fetch --quiet --depth=1 origin \
    "refs/tags/${tag}:refs/tags/lit-release"
  test "$(git -C "$destination" rev-list -n 1 refs/tags/lit-release)" = "$commit"
}

for name in \
  TERRAFORM_VERSION TERRAFORM_COMMIT \
  TERRAGRUNT_VERSION TERRAGRUNT_COMMIT TERRAGRUNT_X_MOD_VERSION \
  HELM_VERSION HELM_COMMIT HELM_ORAS_VERSION; do
  require_value "$name"
done

test "$(go env GOVERSION)" = "go1.26.6"
export CGO_ENABLED=0 GOTOOLCHAIN=local
install -d -m 0755 "$OUT_DIR" "$SOURCE_DIR"

clone_exact \
  https://github.com/hashicorp/terraform.git \
  "$TERRAFORM_COMMIT" \
  "$SOURCE_DIR/terraform"
verify_release_tag "$SOURCE_DIR/terraform" "v${TERRAFORM_VERSION}" "$TERRAFORM_COMMIT"
(
  cd "$SOURCE_DIR/terraform"
  go build \
    -buildvcs=false \
    -trimpath \
    -ldflags='-s -w -X github.com/hashicorp/terraform/version.dev=no' \
    -o "$OUT_DIR/terraform" \
    .
)

clone_exact \
  https://github.com/gruntwork-io/terragrunt.git \
  "$TERRAGRUNT_COMMIT" \
  "$SOURCE_DIR/terragrunt"
verify_release_tag "$SOURCE_DIR/terragrunt" "v${TERRAGRUNT_VERSION}" "$TERRAGRUNT_COMMIT"
(
  cd "$SOURCE_DIR/terragrunt"
  go get "golang.org/x/mod@v${TERRAGRUNT_X_MOD_VERSION}"
  test "$(go list -m -f '{{.Version}}' golang.org/x/mod)" = "v${TERRAGRUNT_X_MOD_VERSION}"
  go build \
    -buildvcs=false \
    -trimpath \
    -ldflags="-s -w -X github.com/gruntwork-io/terragrunt/internal/version.Version=v${TERRAGRUNT_VERSION}+${REBUILD_METADATA}" \
    -o "$OUT_DIR/terragrunt" \
    .
)

clone_exact \
  https://github.com/helm/helm.git \
  "$HELM_COMMIT" \
  "$SOURCE_DIR/helm"
verify_release_tag "$SOURCE_DIR/helm" "v${HELM_VERSION}" "$HELM_COMMIT"
(
  cd "$SOURCE_DIR/helm"
  go get "oras.land/oras-go/v2@v${HELM_ORAS_VERSION}"
  test "$(go list -m -f '{{.Version}}' oras.land/oras-go/v2)" = "v${HELM_ORAS_VERSION}"
  make build \
    BINDIR="$OUT_DIR" \
    VERSION="v${HELM_VERSION}" \
    VERSION_METADATA="$REBUILD_METADATA" \
    GIT_COMMIT="$HELM_COMMIT" \
    GIT_DIRTY=clean \
    CGO_ENABLED=0
)

chmod 0755 "$OUT_DIR/terraform" "$OUT_DIR/terragrunt" "$OUT_DIR/helm"
"$OUT_DIR/terraform" -version | grep -F "Terraform v${TERRAFORM_VERSION}"
"$OUT_DIR/terragrunt" --version | grep -F "v${TERRAGRUNT_VERSION}+${REBUILD_METADATA}"
"$OUT_DIR/helm" version --short | grep -F "v${HELM_VERSION}+${REBUILD_METADATA}"
