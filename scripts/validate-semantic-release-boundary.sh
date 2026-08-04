#!/usr/bin/env bash

set -euo pipefail

SOURCE_SHA="${1:-}"
REPOSITORY="${GITHUB_REPOSITORY:-}"

[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]
test "$REPOSITORY" = lightning-it/container-ee-wunder-ansible-ubi9

repository="$(gh api "repos/${REPOSITORY}")"
test "$(jq -er .default_branch <<<"$repository")" = develop
live_main="$(gh api "repos/${REPOSITORY}/git/ref/heads/main" --jq .object.sha)"
live_develop="$(gh api "repos/${REPOSITORY}/git/ref/heads/develop" --jq .object.sha)"

comparison="$(gh api "repos/${REPOSITORY}/compare/${SOURCE_SHA}...${live_main}")"
jq -e --arg source_sha "$SOURCE_SHA" '
  (.status == "ahead" or .status == "identical")
  and .behind_by == 0
  and .merge_base_commit.sha == $source_sha
' <<<"$comparison" >/dev/null

tree_for_commit() {
  local commit_sha="$1"
  local tree_sha
  local tree
  tree_sha="$(gh api "repos/${REPOSITORY}/git/commits/${commit_sha}" --jq .tree.sha)"
  tree="$(gh api "repos/${REPOSITORY}/git/trees/${tree_sha}?recursive=1")"
  jq -e '.truncated == false' <<<"$tree" >/dev/null
  printf '%s' "$tree"
}

source_tree="$(tree_for_commit "$SOURCE_SHA")"
main_tree="$(tree_for_commit "$live_main")"
develop_tree="$(tree_for_commit "$live_develop")"
critical_filter='[
  .tree[]
  | select(
      (.path | startswith(".github/workflows/"))
      or .path == ".npmrc"
      or .path == ".releaserc"
      or .path == "npm-shrinkwrap.json"
      or .path == "package.json"
      or .path == "package-lock.json"
      or .path == "scripts/semantic-release-plan.mjs"
      or .path == "scripts/validate-semantic-release-boundary.sh"
    )
  | {mode, path, sha, size, type}
] | sort_by(.path)'
receipt_filter='[
  .tree[]
  | select(.path == ".lit/security-release-receipt.json")
  | {mode, path, sha, size, type}
]'

for required_path in \
  .releaserc \
  package.json \
  package-lock.json \
  scripts/semantic-release-plan.mjs \
  scripts/validate-semantic-release-boundary.sh; do
  test "$(jq --arg path "$required_path" '[
    .tree[] | select(.path == $path and .type == "blob")
  ] | length' <<<"$source_tree")" -eq 1
done

source_critical="$(jq -ce "$critical_filter" <<<"$source_tree")"
main_critical="$(jq -ce "$critical_filter" <<<"$main_tree")"
develop_critical="$(jq -ce "$critical_filter" <<<"$develop_tree")"
test "$source_critical" = "$main_critical"
test "$source_critical" = "$develop_critical"

source_receipt="$(jq -ce "$receipt_filter" <<<"$source_tree")"
main_receipt="$(jq -ce "$receipt_filter" <<<"$main_tree")"
test "$(jq length <<<"$source_receipt")" -le 1
test "$(jq length <<<"$main_receipt")" -le 1
test "$source_receipt" = "$main_receipt"
