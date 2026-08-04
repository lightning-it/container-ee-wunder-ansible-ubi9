#!/usr/bin/env python3
"""Verify accepted digests or promote legacy ``latest`` after release.

The MLX-90 security path is deliberately verification-only: Quay does not
offer an atomic create-if-absent tag operation, so a client-side inspect/write
sequence cannot safely create permanent aliases.  ``latest`` remains available
only to the legacy non-security caller, where its separate policy still
applies.
"""

from __future__ import annotations

import argparse
import json
import re
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Sequence


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
EVIDENCE_ID = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,127}$")
IMAGE = re.compile(r"^quay\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$")
SHA = re.compile(r"^[0-9a-f]{40}$")
STABLE_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
NOT_FOUND = re.compile(r"manifest unknown|name unknown|not found", re.IGNORECASE)
VARIANT_COUNT = 3
ROLLBACK_ATTEMPTS = 3


class PromotionError(RuntimeError):
    """A fail-closed promotion error."""


@dataclass(frozen=True)
class Target:
    image: str
    digest: str


Run = Callable[..., subprocess.CompletedProcess[str]]
Inspect = Callable[[str], str | None]
Write = Callable[[str, str], None]
PolicyCheck = Callable[[], None]


def parse_stable_tag(tag: object) -> tuple[int, int, int] | None:
    if not isinstance(tag, str):
        return None
    match = STABLE_TAG.fullmatch(tag)
    if match is None:
        return None
    return tuple(int(value) for value in match.groups())  # type: ignore[return-value]


def parse_target(value: str) -> Target:
    image, separator, digest = value.partition("=")
    if separator != "=" or not IMAGE.fullmatch(image) or not DIGEST.fullmatch(digest):
        raise PromotionError(
            "each --variant must be quay.io/<namespace>/<image>=sha256:<64 hex>"
        )
    return Target(image=image, digest=digest)


def flatten_pages(raw: str, *, name: str) -> list[dict[str, object]]:
    try:
        pages = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PromotionError(f"{name} pagination returned invalid JSON") from exc
    if not isinstance(pages, list) or not all(isinstance(page, list) for page in pages):
        raise PromotionError(f"{name} pagination must be an array of page arrays")
    flattened: list[dict[str, object]] = []
    for page in pages:
        for item in page:
            if not isinstance(item, dict):
                raise PromotionError(f"{name} pagination contains a non-object item")
            flattened.append(item)
    return flattened


def require_highest_stable_release(
    releases: Sequence[dict[str, object]],
    *,
    release_id: int,
    release_tag: str,
) -> None:
    if release_id <= 0 or parse_stable_tag(release_tag) is None:
        raise PromotionError(
            "the target release must use a canonical stable SemVer tag"
        )
    ids = [release.get("id") for release in releases]
    if not all(isinstance(item, int) and item > 0 for item in ids):
        raise PromotionError("the release inventory contains an invalid release ID")
    if len(ids) != len(set(ids)):
        raise PromotionError("the paginated release inventory contains duplicate IDs")
    matching = [
        release
        for release in releases
        if release.get("id") == release_id and release.get("tag_name") == release_tag
    ]
    if len(matching) != 1:
        raise PromotionError("the target release is missing or ambiguous")
    target = matching[0]
    if (
        target.get("draft") is not False
        or target.get("prerelease") is not False
        or not isinstance(target.get("published_at"), str)
        or not target.get("published_at")
    ):
        raise PromotionError("the target release is not a published stable release")
    eligible: list[tuple[tuple[int, int, int], int, str]] = []
    for release in releases:
        version = parse_stable_tag(release.get("tag_name"))
        if (
            version is not None
            and release.get("draft") is False
            and release.get("prerelease") is False
            and isinstance(release.get("published_at"), str)
            and release.get("published_at")
        ):
            eligible.append((version, int(release["id"]), str(release["tag_name"])))
    if not eligible:
        raise PromotionError("no published stable release exists")
    highest = max(eligible, key=lambda item: (item[0], item[1]))
    if highest != (parse_stable_tag(release_tag), release_id, release_tag):
        raise PromotionError(
            f"refusing non-monotonic latest promotion: {release_tag} is not the "
            f"highest stable release ({highest[2]})"
        )


def run_checked(command: Sequence[str], *, run: Run) -> str:
    completed = run(
        list(command),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        if detail:
            raise PromotionError(f"command failed: {command[0]}: {detail}")
        raise PromotionError(f"command failed: {command[0]}")
    return completed.stdout


def fetch_releases(
    repository: str, *, run: Run = subprocess.run
) -> list[dict[str, object]]:
    if not REPOSITORY.fullmatch(repository):
        raise PromotionError("invalid GitHub repository")
    raw = run_checked(
        [
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"repos/{repository}/releases?per_page=100",
        ],
        run=run,
    )
    return flatten_pages(raw, name="release inventory")


def require_tag_commit(
    *,
    repository: str,
    release_tag: str,
    expected_source_sha: str,
    run: Run = subprocess.run,
) -> None:
    if (
        not REPOSITORY.fullmatch(repository)
        or parse_stable_tag(release_tag) is None
        or not SHA.fullmatch(expected_source_sha)
    ):
        raise PromotionError("invalid release source identity")
    commit_raw = run_checked(
        ["gh", "api", f"repos/{repository}/commits/{release_tag}"],
        run=run,
    )
    try:
        commit = json.loads(commit_raw)
    except json.JSONDecodeError as exc:
        raise PromotionError("release tag lookup returned invalid JSON") from exc
    if not isinstance(commit, dict) or commit.get("sha") != expected_source_sha:
        raise PromotionError("release tag no longer points to the accepted source SHA")


def require_not_revoked(
    *,
    producer_repository: str,
    producer_release_tag: str,
    evidence_id: str,
    run: Run = subprocess.run,
) -> None:
    if (
        not REPOSITORY.fullmatch(producer_repository)
        or parse_stable_tag(producer_release_tag) is None
        or not EVIDENCE_ID.fullmatch(evidence_id)
    ):
        raise PromotionError("invalid producer revocation identity")
    release_raw = run_checked(
        [
            "gh",
            "api",
            f"repos/{producer_repository}/releases/tags/{producer_release_tag}",
        ],
        run=run,
    )
    try:
        release = json.loads(release_raw)
    except json.JSONDecodeError as exc:
        raise PromotionError("producer release lookup returned invalid JSON") from exc
    if not isinstance(release, dict):
        raise PromotionError("producer release lookup returned a non-object")
    release_id = release.get("id")
    if (
        release.get("tag_name") != producer_release_tag
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or not isinstance(release_id, int)
        or release_id <= 0
    ):
        raise PromotionError(
            "producer release is not an exact published stable release"
        )
    asset_raw = run_checked(
        [
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"repos/{producer_repository}/releases/{release_id}/assets?per_page=100",
        ],
        run=run,
    )
    assets = flatten_pages(asset_raw, name="producer release assets")
    names = [asset.get("name") for asset in assets]
    revocations = {
        "security-release-revocation.json",
        f"security-release-revocation-{evidence_id}.json",
    }
    if any(name in revocations for name in names):
        raise PromotionError("producer evidence was revoked before tag promotion")


def inspect_latest(image: str, *, run: Run = subprocess.run) -> str | None:
    completed = run(
        [
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            f"{image}:latest",
            "--format",
            "{{ .Manifest.Digest }}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        digest = completed.stdout.strip()
        if not DIGEST.fullmatch(digest):
            raise PromotionError(
                f"registry returned an invalid digest for {image}:latest"
            )
        return digest
    detail = (completed.stderr or completed.stdout).strip()
    if NOT_FOUND.search(detail):
        return None
    raise PromotionError(
        f"unable to inspect {image}:latest: {detail or 'unknown error'}"
    )


def write_latest(image: str, digest: str, *, run: Run = subprocess.run) -> None:
    run_checked(
        [
            "docker",
            "buildx",
            "imagetools",
            "create",
            "--tag",
            f"{image}:latest",
            f"{image}@{digest}",
        ],
        run=run,
    )


def verify_security_release(
    targets: Sequence[Target], *, policy_check: PolicyCheck
) -> None:
    """Validate the exact accepted digest set without mutating registry tags."""

    if (
        len(targets) != VARIANT_COUNT
        or len({target.image for target in targets}) != VARIANT_COUNT
    ):
        raise PromotionError("exactly three unique image variants are required")
    if any(
        not IMAGE.fullmatch(target.image) or not DIGEST.fullmatch(target.digest)
        for target in targets
    ):
        raise PromotionError("invalid accepted digest target")
    policy_check()


def restore_snapshot(
    targets: Sequence[Target],
    snapshot: Sequence[str],
    *,
    inspect: Inspect,
    write: Write,
) -> None:
    errors: list[str] = []
    for target, previous in zip(targets, snapshot, strict=True):
        restored = False
        last_error = "rollback did not run"
        for _attempt in range(ROLLBACK_ATTEMPTS):
            try:
                current = inspect(target.image)
                if current == previous:
                    restored = True
                    break
                if current != target.digest:
                    raise PromotionError(
                        f"refusing to overwrite divergent {target.image}:latest during rollback"
                    )
                write(target.image, previous)
                if inspect(target.image) == previous:
                    restored = True
                    break
                last_error = "rollback verification did not restore the snapshot"
            except Exception as exc:  # noqa: BLE001 - aggregate every rollback failure
                last_error = str(exc)
        if not restored:
            errors.append(f"{target.image}: {last_error}")
    if errors:
        raise PromotionError("rollback failed: " + "; ".join(errors))


def promote(
    targets: Sequence[Target],
    *,
    inspect: Inspect,
    write: Write,
    policy_check: PolicyCheck,
) -> None:
    if (
        len(targets) != VARIANT_COUNT
        or len({target.image for target in targets}) != VARIANT_COUNT
    ):
        raise PromotionError("exactly three unique image variants are required")
    if any(
        not IMAGE.fullmatch(target.image) or not DIGEST.fullmatch(target.digest)
        for target in targets
    ):
        raise PromotionError("invalid image promotion target")
    policy_check()
    snapshot = [inspect(target.image) for target in targets]
    if any(value is None for value in snapshot):
        raise PromotionError(
            "all three latest tags must already exist; refusing a non-rollbackable first promotion"
        )
    previous = [str(value) for value in snapshot]
    try:
        for target, before in zip(targets, previous, strict=True):
            policy_check()
            current = inspect(target.image)
            if current not in {before, target.digest}:
                raise PromotionError(
                    f"compare-and-swap rejected divergent {target.image}:latest"
                )
            if current != target.digest:
                write(target.image, target.digest)
                if inspect(target.image) != target.digest:
                    raise PromotionError(
                        f"promotion verification failed for {target.image}:latest"
                    )
        policy_check()
        final = [inspect(target.image) for target in targets]
        expected = [target.digest for target in targets]
        if final != expected:
            raise PromotionError(
                "the three latest tags do not form the expected complete set"
            )
        policy_check()
    except BaseException as exc:
        try:
            restore_snapshot(
                targets,
                previous,
                inspect=inspect,
                write=write,
            )
        except Exception as rollback_exc:
            raise PromotionError(f"{exc}; {rollback_exc}") from exc
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release-id", required=True, type=int)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--verify-digests-only", action="store_true")
    parser.add_argument("--variant", action="append", required=True)
    parser.add_argument("--producer-repository")
    parser.add_argument("--producer-release-tag")
    parser.add_argument("--producer-source-sha")
    parser.add_argument("--evidence-id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        targets = [parse_target(value) for value in args.variant]
        producer_values = (
            args.producer_repository,
            args.producer_release_tag,
            args.producer_source_sha,
            args.evidence_id,
        )
        if any(value is not None for value in producer_values) and not all(
            value is not None for value in producer_values
        ):
            raise PromotionError(
                "producer revocation arguments must be supplied together"
            )

        def policy_check() -> None:
            releases = fetch_releases(args.repository)
            require_highest_stable_release(
                releases,
                release_id=args.release_id,
                release_tag=args.release_tag,
            )
            require_tag_commit(
                repository=args.repository,
                release_tag=args.release_tag,
                expected_source_sha=args.source_sha,
            )
            if all(value is not None for value in producer_values):
                require_tag_commit(
                    repository=str(args.producer_repository),
                    release_tag=str(args.producer_release_tag),
                    expected_source_sha=str(args.producer_source_sha),
                )
                require_not_revoked(
                    producer_repository=str(args.producer_repository),
                    producer_release_tag=str(args.producer_release_tag),
                    evidence_id=str(args.evidence_id),
                )

        def interrupted(signum: int, _frame: object) -> None:
            raise PromotionError(f"promotion interrupted by signal {signum}")

        signal.signal(signal.SIGINT, interrupted)
        signal.signal(signal.SIGTERM, interrupted)
        if args.verify_digests_only:
            if not all(value is not None for value in producer_values):
                raise PromotionError(
                    "digest-only security verification requires producer revocation arguments"
                )
            verify_security_release(targets, policy_check=policy_check)
        else:
            promote(
                targets,
                inspect=inspect_latest,
                write=write_latest,
                policy_check=policy_check,
            )
    except PromotionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
