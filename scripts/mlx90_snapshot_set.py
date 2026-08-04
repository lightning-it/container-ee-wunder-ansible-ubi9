#!/usr/bin/env python3
"""Create a private, descriptor-bound snapshot set for MLX-90 workflows."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from mlx90_secure_files import (
    persistent_snapshot_directory,
    secure_directory,
    snapshot_regular_file,
)


NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def parse_file(value: str) -> tuple[str, int, str | None]:
    parts = value.split(":", maxsplit=2)
    if len(parts) not in {2, 3}:
        raise ValueError("--file must be NAME:MAX_BYTES[:SHA256_DIGEST]")
    name, raw_limit = parts[:2]
    digest = parts[2] if len(parts) == 3 else None
    if not NAME.fullmatch(name) or Path(name).name != name:
        raise ValueError("snapshot file name is unsafe")
    try:
        limit = int(raw_limit)
    except ValueError as exc:
        raise ValueError("snapshot byte limit must be an integer") from exc
    if limit <= 0 or limit > 512 * 1024 * 1024:
        raise ValueError("snapshot byte limit is outside the allowed range")
    if digest is not None and not DIGEST.fullmatch(digest):
        raise ValueError("snapshot expected digest is invalid")
    return name, limit, digest


def snapshot_set(
    source: Path,
    output: Path,
    files: list[tuple[str, int, str | None]],
) -> dict[str, dict[str, object]]:
    if not files or len({name for name, _, _ in files}) != len(files):
        raise ValueError("snapshot set must contain unique files")
    result: dict[str, dict[str, object]] = {}
    with secure_directory(source, create=False) as source_directory:
        with persistent_snapshot_directory(output, create=True) as destination:
            if os.listdir(destination.descriptor):
                raise ValueError("snapshot destination must start empty")
            for name, limit, expected_digest in files:
                snapshot = snapshot_regular_file(
                    source / name,
                    destination,
                    name,
                    max_bytes=limit,
                    label=f"MLX-90 asset {name}",
                    expected_digest=expected_digest,
                    source_directory=source_directory,
                )
                result[name] = {
                    "digest": snapshot.digest,
                    "path": str(snapshot.path),
                    "size": snapshot.size,
                }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--file", action="append", required=True)
    args = parser.parse_args()
    try:
        result = snapshot_set(
            args.source,
            args.output,
            [parse_file(value) for value in args.file],
        )
    except (OSError, ValueError) as exc:
        print(f"MLX-90 snapshot set rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
