#!/usr/bin/env python3
"""Classify an exact main-targeting PR for protected promotion authorization."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SHA = re.compile(r"^[0-9a-f]{40}$")
SUPPLEMENTARY_SECURITY_BRANCH = re.compile(
    r"^security-release/MLX90-[A-Z0-9][A-Z0-9._-]{2,127}$"
)
CONTAINER_SECURITY_BRANCH = re.compile(
    r"^security/mlx90-(?:cleanup-)?[a-z0-9][a-z0-9._-]*$"
)
RELEASE_APP_LOGIN = "lightning-it-release-automation[bot]"
RELEASE_APP_USER_ID = 307565056
RELEASE_TEAM_ID = 15545798
NORMAL_ENVIRONMENT = "normal-release-promotion-approval"
SECURITY_ENVIRONMENT = "mlx90-security-promotion-authorization"
SUPPLEMENTARY = "lightning-it/ansible-collection-supplementary"
CONTAINER = "lightning-it/container-ee-wunder-ansible-ubi9"
ALLOWED_REPOSITORIES = {
    "lightning-it/shared-assets-lit",
    "lightning-it/github-management-lit",
    SUPPLEMENTARY,
    CONTAINER,
    "lightning-it/modulix-validation",
}


class AuthorizationError(ValueError):
    """Raised when live pull-request state is not safe to authorize."""


@dataclass(frozen=True)
class Authorization:
    mode: str
    environment: str
    head_sha: str
    head_ref: str


def fail(message: str) -> None:
    raise AuthorizationError(message)


def require_dict(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a non-empty string")
    return value


def load_pull(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        fail("pull-request payload must be a regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuthorizationError("pull-request payload is not valid UTF-8 JSON") from exc
    return require_dict(payload, "pull-request payload")


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuthorizationError(f"{label} is not valid UTF-8 JSON") from exc
    return require_dict(payload, label)


def validate_environment(payload: dict[str, Any], result: Authorization) -> None:
    """Fail closed unless the selected live environment has the exact trust model."""

    name = require_string(payload.get("name"), "environment.name")
    if name != result.environment:
        fail("live environment does not match the classified promotion mode")
    if payload.get("can_admins_bypass") is not False:
        fail("live environment must prohibit administrator bypass")

    protection_rules = payload.get("protection_rules")
    if not isinstance(protection_rules, list):
        fail("environment.protection_rules must be an array")
    reviewer_rules = [
        require_dict(rule, "environment protection rule")
        for rule in protection_rules
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    wait_rules = [
        rule
        for rule in protection_rules
        if isinstance(rule, dict) and rule.get("type") == "wait_timer"
    ]
    if wait_rules:
        fail("live environment must not substitute a wait timer for authorization")

    if result.mode == "security":
        if reviewer_rules:
            fail("MLX-90 Security environment must remain reviewer-free")
        return

    if len(reviewer_rules) != 1:
        fail("normal promotion environment must have one reviewer rule")
    reviewer_rule = reviewer_rules[0]
    if reviewer_rule.get("prevent_self_review") is not True:
        fail("normal promotion environment must prevent self-review")
    reviewers = reviewer_rule.get("reviewers")
    if not isinstance(reviewers, list) or len(reviewers) != 1:
        fail("normal promotion environment must have exactly one reviewer")
    reviewer = require_dict(reviewers[0], "environment reviewer")
    reviewer_identity = require_dict(
        reviewer.get("reviewer"), "environment reviewer identity"
    )
    if (
        reviewer.get("type") != "BusinessTeam"
        or reviewer_identity.get("id") != RELEASE_TEAM_ID
    ):
        fail("normal promotion environment reviewer must be the release team")


def classify(
    payload: dict[str, Any],
    repository: str,
    expected_base: str,
    expected_head: str,
) -> Authorization:
    if repository not in ALLOWED_REPOSITORIES:
        fail("repository is outside the MLX-90 promotion allowlist")
    for label, value in (("expected base SHA", expected_base), ("expected head SHA", expected_head)):
        if SHA.fullmatch(value) is None:
            fail(f"{label} is invalid")

    if payload.get("state") != "open" or payload.get("draft") is not False:
        fail("pull request must be open and ready for review")
    base = require_dict(payload.get("base"), "base")
    head = require_dict(payload.get("head"), "head")
    author = require_dict(payload.get("user"), "user")
    head_repo = require_dict(head.get("repo"), "head.repo")
    base_ref = require_string(base.get("ref"), "base.ref")
    base_sha = require_string(base.get("sha"), "base.sha")
    head_ref = require_string(head.get("ref"), "head.ref")
    head_sha = require_string(head.get("sha"), "head.sha")
    author_login = require_string(author.get("login"), "user.login")
    author_id = author.get("id")
    author_type = require_string(author.get("type"), "user.type")
    head_repository = require_string(head_repo.get("full_name"), "head.repo.full_name")

    if base_ref != "main" or base_sha != expected_base:
        fail("live base is not the exact expected main revision")
    if head_sha != expected_head or SHA.fullmatch(head_sha) is None:
        fail("live head is not the exact expected revision")
    if head_repository != repository:
        fail("cross-repository main promotion is not authorized")

    reserved_security_prefix = False
    security_branch = False
    if repository == SUPPLEMENTARY:
        reserved_security_prefix = head_ref.startswith("security-release/")
        security_branch = SUPPLEMENTARY_SECURITY_BRANCH.fullmatch(head_ref) is not None
    elif repository == CONTAINER:
        reserved_security_prefix = head_ref.startswith("security/mlx90-")
        security_branch = CONTAINER_SECURITY_BRANCH.fullmatch(head_ref) is not None

    if reserved_security_prefix:
        if not security_branch:
            fail("reserved MLX-90 Security branch name is malformed")
        if (
            author_login != RELEASE_APP_LOGIN
            or author_id != RELEASE_APP_USER_ID
            or author_type != "Bot"
        ):
            fail("MLX-90 Security promotion must be authored by the release App")
        return Authorization(
            mode="security",
            environment=SECURITY_ENVIRONMENT,
            head_sha=head_sha,
            head_ref=head_ref,
        )

    return Authorization(
        mode="normal",
        environment=NORMAL_ENVIRONMENT,
        head_sha=head_sha,
        head_ref=head_ref,
    )


def write_output(result: Authorization, output: Path | None) -> None:
    values = {
        "mode": result.mode,
        "environment": result.environment,
        "head_sha": result.head_sha,
        "head_ref": result.head_ref,
    }
    if output is not None:
        if output.exists() and (output.is_symlink() or not output.is_file()):
            fail("GitHub output must be a regular file")
        with output.open("a", encoding="utf-8") as stream:
            for key, value in values.items():
                stream.write(f"{key}={value}\n")
    print(json.dumps(values, sort_keys=True, separators=(",", ":")))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pull", type=Path, required=True)
    parser.add_argument("--environment", type=Path)
    parser.add_argument("--classification-only", action="store_true")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--expected-base", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-mode", choices=("normal", "security"))
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        result = classify(
            load_pull(args.pull),
            args.repository,
            args.expected_base,
            args.expected_head,
        )
        if args.expected_mode is not None and result.mode != args.expected_mode:
            fail("live promotion mode changed after environment authorization")
        if not args.classification_only:
            if args.environment is None:
                fail("live environment payload is required")
            validate_environment(
                load_json_object(args.environment, "environment payload"),
                result,
            )
        write_output(result, args.github_output)
    except AuthorizationError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
