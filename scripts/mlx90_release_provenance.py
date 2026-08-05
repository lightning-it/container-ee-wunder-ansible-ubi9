#!/usr/bin/env python3
"""Validate the exact MLX-90 container release provenance contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from mlx90_secure_files import (
    held_directory,
    private_snapshot_directory,
    read_regular_bytes,
    snapshot_regular_file,
)


REPOSITORY = "lightning-it/container-ee-wunder-ansible-ubi9"
IMAGE_REPOSITORIES = {
    "public": "quay.io/l-it/ee-wunder-ansible-ubi9",
    "certified": "quay.io/l-it/ee-wunder-ansible-ubi9-certified",
    "bootstrap": "quay.io/l-it/ee-wunder-ansible-ubi9-bootstrap",
}
FILE_SUBJECTS = {
    "sbom.cdx.json",
    *(f"assurance-{profile}.json" for profile in ("bootstrap", "certified", "public")),
    *(f"manifest-{profile}.json" for profile in ("bootstrap", "certified", "public")),
    *(f"signature-{profile}.json" for profile in ("bootstrap", "certified", "public")),
    *(f"sbom-{profile}.cdx.json" for profile in ("bootstrap", "certified", "public")),
    *(
        f"installed-collections-{profile}.json"
        for profile in ("bootstrap", "certified", "public")
    ),
}
CONTAINER_SBOM_SUBJECTS = {
    "sbom.cdx.json",
    *(f"sbom-{profile}.cdx.json" for profile in ("bootstrap", "certified", "public")),
}
SBOM_SUBJECT = "sbom-public.cdx.json"
SIGNATURE_SUBJECT = "signature-public.json"
SHA = re.compile(r"\A[0-9a-f]{40}\Z")
DIGEST = re.compile(r"\A[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"\A[1-9][0-9]*\Z")
TAG = re.compile(r"\Av[0-9]+\.[0-9]+\.[0-9]+(?:[+-][0-9A-Za-z.-]+)?\Z")
IMAGE_REF = re.compile(
    r"\A(?P<repository>quay\.io/l-it/ee-wunder-ansible-ubi9"
    r"(?:-certified|-bootstrap)?)@sha256:(?P<digest>[0-9a-f]{64})\Z"
)
RFC3339 = re.compile(
    r"\A(?P<date_time>[0-9]{4}-(?:0[1-9]|1[0-2])-"
    r"(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):"
    r"[0-5][0-9]:[0-5][0-9])(?:\.(?P<fraction>[0-9]{1,6}))?"
    r"(?P<offset>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z"
)
FD_PATH = re.compile(r"\A/dev/fd/(?P<descriptor>[0-9]+)\Z")
PROVENANCE_MAX_BYTES = 16 * 1024 * 1024
ASSET_MAX_BYTES = 16 * 1024 * 1024
SBOM_MAX_BYTES = 64 * 1024 * 1024
SIGNATURE_MAX_BYTES = 4 * 1024 * 1024
FILE_SUBJECT_MAX_BYTES = {
    name: (
        SIGNATURE_MAX_BYTES
        if name.startswith("signature-")
        else SBOM_MAX_BYTES
        if name in CONTAINER_SBOM_SUBJECTS
        else ASSET_MAX_BYTES
    )
    for name in FILE_SUBJECTS
}


def fail(message: str) -> None:
    raise ValueError(message)


def require_object(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{name} must be an object")
    return value


def require_exact_object(
    value: object, keys: set[str], name: str
) -> dict[str, Any]:
    result = require_object(value, name)
    if set(result) != keys:
        fail(f"{name} fields are not exact")
    return result


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"release provenance contains duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    fail(f"release provenance contains invalid JSON constant {value}")


def parse_rfc3339(value: object, name: str) -> datetime:
    match = RFC3339.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        fail(f"{name} must be an RFC3339 timestamp")
    fraction = match.group("fraction")
    normalized = match.group("date_time")
    if fraction is not None:
        normalized += f".{fraction.ljust(6, '0')}"
    offset = match.group("offset")
    normalized += "+00:00" if offset == "Z" else offset
    try:
        return datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{name} must be an RFC3339 timestamp") from exc


def read_bounded_descriptor(descriptor: int, *, max_bytes: int, label: str) -> bytes:
    try:
        duplicate = os.dup(descriptor)
    except OSError as exc:
        raise ValueError(f"cannot open sealed {label} descriptor") from exc
    try:
        before = os.fstat(duplicate)
        if not stat.S_ISREG(before.st_mode):
            fail(f"{label} is not a regular file")
        if before.st_size <= 0:
            fail(f"{label} is empty")
        if before.st_size > max_bytes:
            fail(f"{label} exceeds the {max_bytes}-byte verification limit")
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(duplicate, min(1024 * 1024, before.st_size - offset), offset)
            if not chunk:
                fail(f"{label} changed while it was being read")
            chunks.append(chunk)
            offset += len(chunk)
        after = os.fstat(duplicate)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(before) != identity(after):
            fail(f"{label} changed while it was being read")
        return b"".join(chunks)
    except OSError as exc:
        raise ValueError(f"cannot read sealed {label} descriptor") from exc
    finally:
        os.close(duplicate)


def read_input(path: Path, *, max_bytes: int, label: str) -> bytes:
    descriptor_match = FD_PATH.fullmatch(str(path))
    if descriptor_match is not None:
        return read_bounded_descriptor(
            int(descriptor_match.group("descriptor")),
            max_bytes=max_bytes,
            label=label,
        )
    return read_regular_bytes(path, max_bytes=max_bytes, label=label)


def load_statement(path: Path) -> dict[str, Any]:
    payload = read_input(
        path,
        max_bytes=PROVENANCE_MAX_BYTES,
        label="release provenance",
    )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("release provenance must be UTF-8") from exc
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0]:
        fail("release provenance must contain exactly one statement")
    try:
        value = json.loads(
            lines[0],
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except json.JSONDecodeError as exc:
        raise ValueError("release provenance is not valid JSON") from exc
    return require_exact_object(
        value,
        {"_type", "subject", "predicateType", "predicate"},
        "release provenance statement",
    )


def file_digest(path: Path, *, max_bytes: int, label: str) -> str:
    return hashlib.sha256(
        read_input(path, max_bytes=max_bytes, label=label)
    ).hexdigest()


def snapshot_file_subject_digests(asset_directory: Path) -> dict[str, str]:
    """Capture every declared file subject once through one held source directory."""

    if not isinstance(asset_directory, Path):
        fail("release asset directory must be a filesystem path")
    digests: dict[str, str] = {}
    with (
        held_directory(asset_directory) as source_directory,
        private_snapshot_directory("mlx90-provenance-subjects-") as snapshots,
    ):
        for index, name in enumerate(sorted(FILE_SUBJECTS)):
            snapshot = snapshot_regular_file(
                asset_directory / name,
                snapshots,
                f"subject-{index}",
                max_bytes=FILE_SUBJECT_MAX_BYTES[name],
                label=f"release provenance subject {name}",
                source_directory=source_directory,
            )
            digests[name] = snapshot.digest.removeprefix("sha256:")
    return digests


def expected_image_subjects(file_digests: dict[str, str]) -> set[str]:
    """Derive immutable image subjects from the exact raw manifest snapshots."""

    if set(file_digests) != FILE_SUBJECTS:
        fail("release provenance file digest set is incomplete")
    return {
        f"{repository}@sha256:{file_digests[f'manifest-{profile}.json']}"
        for profile, repository in IMAGE_REPOSITORIES.items()
    }


def validate_subjects(
    subjects_value: object,
    *,
    image_ref: str,
    file_digests: dict[str, str],
) -> None:
    if not isinstance(subjects_value, list):
        fail("release provenance subjects must be an array")
    subjects: dict[str, dict[str, Any]] = {}
    expected_images = expected_image_subjects(file_digests)
    for value in subjects_value:
        subject = require_object(value, "release provenance subject")
        name = subject.get("name")
        if not isinstance(name, str) or name in subjects:
            fail("release provenance subject name is invalid or duplicated")
        subjects[name] = subject
        if name in expected_images:
            if set(subject) != {"name"}:
                fail("release provenance image subject has mutable metadata")
            continue
        if IMAGE_REF.fullmatch(name) is not None:
            fail(f"release provenance contains unexpected image subject {name}")
        if name not in FILE_SUBJECTS:
            fail(f"release provenance contains unexpected subject {name}")
        file_subject = require_exact_object(
            subject, {"name", "digest"}, f"release provenance subject {name}"
        )
        digest = require_exact_object(
            file_subject["digest"], {"sha256"}, f"release provenance digest {name}"
        )["sha256"]
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            fail(f"release provenance digest {name} must be SHA-256")

    actual_images = set(subjects) & expected_images
    if actual_images != expected_images:
        fail("release provenance image subject set is incomplete")
    if set(subjects) != FILE_SUBJECTS | expected_images:
        fail("release provenance subject set is incomplete")
    if subjects.get(image_ref) != {"name": image_ref}:
        fail("release provenance does not bind the immutable public image")
    for name, expected in file_digests.items():
        if subjects.get(name) != {"name": name, "digest": {"sha256": expected}}:
            fail(f"release provenance does not bind {name}")


def validate_release_provenance(
    provenance_path: Path,
    repository: str,
    release_tag: str,
    source_sha: str,
    image_ref: str,
    asset_directory: Path,
    sbom_path: Path,
    signature_path: Path,
) -> None:
    if repository != REPOSITORY:
        fail("release provenance repository is not the canonical consumer")
    if not TAG.fullmatch(release_tag):
        fail("release provenance release tag is invalid")
    if not SHA.fullmatch(source_sha):
        fail("release provenance source SHA is invalid")
    image_match = IMAGE_REF.fullmatch(image_ref)
    if (
        image_match is None
        or image_match.group("repository")
        != IMAGE_REPOSITORIES["public"]
    ):
        fail("release provenance image is not the canonical public image")

    file_digests = snapshot_file_subject_digests(asset_directory)
    if image_ref not in expected_image_subjects(file_digests):
        fail("release provenance public image differs from its raw manifest digest")
    if file_digest(
        sbom_path,
        max_bytes=SBOM_MAX_BYTES,
        label="public SBOM",
    ) != file_digests[SBOM_SUBJECT]:
        fail("public SBOM differs from the release asset snapshot")
    if file_digest(
        signature_path,
        max_bytes=SIGNATURE_MAX_BYTES,
        label="public signature receipt",
    ) != file_digests[SIGNATURE_SUBJECT]:
        fail("public signature receipt differs from the release asset snapshot")

    statement = load_statement(provenance_path)
    if statement["_type"] != "https://in-toto.io/Statement/v1":
        fail("release provenance is not an in-toto v1 statement")
    if statement["predicateType"] != "https://slsa.dev/provenance/v1":
        fail("release provenance predicate type is invalid")
    predicate = require_exact_object(
        statement["predicate"],
        {"buildDefinition", "runDetails"},
        "release provenance predicate",
    )
    build = require_exact_object(
        predicate["buildDefinition"],
        {
            "buildType",
            "externalParameters",
            "internalParameters",
            "resolvedDependencies",
        },
        "release provenance build definition",
    )
    if build["buildType"] != "https://lightning-it.io/provenance/workflow-release":
        fail("release provenance build type is invalid")
    if build["externalParameters"] != {
        "repository": repository,
        "release": release_tag,
        "commit": source_sha,
    }:
        fail("release provenance external parameters do not match")
    if build["internalParameters"] != {}:
        fail("release provenance internal parameters must be empty")
    if build["resolvedDependencies"] != [
        {
            "uri": f"git+https://github.com/{repository}@{source_sha}",
            "digest": {"gitCommit": source_sha},
        }
    ]:
        fail("release provenance source dependency does not match")

    run = require_exact_object(
        predicate["runDetails"],
        {"builder", "metadata", "byproducts"},
        "release provenance run details",
    )
    if run["builder"] != {"id": f"https://github.com/{repository}/actions"}:
        fail("release provenance builder does not match")
    metadata = require_exact_object(
        run["metadata"],
        {"invocationId", "startedOn", "finishedOn"},
        "release provenance run metadata",
    )
    invocation_id = metadata["invocationId"]
    if not isinstance(invocation_id, str) or not RUN_ID.fullmatch(invocation_id):
        fail("release provenance invocation ID is invalid")
    if parse_rfc3339(metadata["startedOn"], "release provenance startedOn") != parse_rfc3339(
        metadata["finishedOn"], "release provenance finishedOn"
    ):
        fail("release provenance generation timestamps differ")
    if run["byproducts"] != [
        {
            "name": "workflow_run",
            "uri": f"https://github.com/{repository}/actions/runs/{invocation_id}",
        }
    ]:
        fail("release provenance workflow run byproduct does not match")

    validate_subjects(
        statement["subject"],
        image_ref=image_ref,
        file_digests=file_digests,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--provenance", type=Path, required=True)
    verify.add_argument("--repository", required=True)
    verify.add_argument("--release-tag", required=True)
    verify.add_argument("--source-sha", required=True)
    verify.add_argument("--image-ref", required=True)
    verify.add_argument("--assets", type=Path, required=True)
    verify.add_argument("--sbom", type=Path, required=True)
    verify.add_argument("--signature", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "verify":
            validate_release_provenance(
                args.provenance,
                args.repository,
                args.release_tag,
                args.source_sha,
                args.image_ref,
                args.assets,
                args.sbom,
                args.signature,
            )
            return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
