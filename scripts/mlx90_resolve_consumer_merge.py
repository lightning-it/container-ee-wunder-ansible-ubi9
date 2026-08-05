#!/usr/bin/env python3
"""Resolve the unique MLX-90 security merge beneath a release source commit."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


SHA = re.compile(r"^[0-9a-f]{40}$")


def git(repository: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    result = subprocess.run(
        ["git", *args],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or "no stderr"
        raise ValueError(
            f"git {' '.join(args)} failed with exit {result.returncode}: {detail}"
        )
    return result


def resolve_consumer_merge(
    repository: Path, base_sha: str, source_sha: str
) -> dict[str, str]:
    if not SHA.fullmatch(base_sha) or not SHA.fullmatch(source_sha):
        raise ValueError("base and source must be full lowercase GitHub SHAs")
    if not repository.is_dir():
        raise ValueError("repository path is not a directory")
    git(repository, "cat-file", "-e", f"{base_sha}^{{commit}}")
    git(repository, "cat-file", "-e", f"{source_sha}^{{commit}}")
    if (
        git(
            repository,
            "merge-base",
            "--is-ancestor",
            base_sha,
            source_sha,
            check=False,
        ).returncode
        != 0
    ):
        raise ValueError("receipt base is not an ancestor of the release source")

    history = git(
        repository,
        "rev-list",
        "--ancestry-path",
        "--merges",
        "--parents",
        f"{base_sha}..{source_sha}",
    ).stdout.splitlines()
    candidates: list[tuple[str, str]] = []
    for line in history:
        fields = line.split()
        if len(fields) == 3 and fields[1] == base_sha:
            candidates.append((fields[0], fields[2]))
    if len(candidates) != 1:
        raise ValueError(
            "release ancestry must contain exactly one two-parent merge "
            "whose first parent is the receipt base"
        )

    security_merge_sha, consumer_head_sha = candidates[0]
    if not SHA.fullmatch(security_merge_sha) or not SHA.fullmatch(consumer_head_sha):
        raise ValueError("resolved merge ancestry contains an invalid SHA")
    if (
        git(
            repository,
            "merge-base",
            "--is-ancestor",
            security_merge_sha,
            source_sha,
            check=False,
        ).returncode
        != 0
    ):
        raise ValueError("resolved security merge is not in release ancestry")
    return {
        "baseSha": base_sha,
        "consumerHeadSha": consumer_head_sha,
        "releaseSourceSha": source_sha,
        "securityMergeSha": security_merge_sha,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    try:
        result = resolve_consumer_merge(
            args.repository, args.base_sha, args.source_sha
        )
    except (OSError, ValueError) as exc:
        print(f"MLX-90 consumer merge resolution rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
