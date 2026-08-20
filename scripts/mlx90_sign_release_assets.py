#!/usr/bin/env python3
"""Snapshot, validate, and sign one exact MLX-90 release-asset set."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import io
import itertools
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from mlx90_secure_files import (
    open_exclusive_regular,
    persistent_snapshot_directory,
    read_regular_bytes,
    secure_directory,
    snapshot_regular_file,
)


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
EVIDENCE_ID = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,127}$")
SECURITY_ID = re.compile(
    r"^(?:CVE-[0-9]{4}-[0-9]{4,}|"
    r"GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}|"
    r"LIT-SEC-[A-Z0-9._-]+)$"
)
UUID_REFERENCE = re.compile(
    r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$", re.IGNORECASE
)
PROFILES = ("bootstrap", "certified", "public")
PROFILE_SUFFIXES = {"public": "", "certified": "-certified", "bootstrap": "-bootstrap"}
CONTAINER_SBOM_ASSETS = {
    "sbom.cdx.json",
    *(f"sbom-{profile}.cdx.json" for profile in PROFILES),
}
CONTAINER_SIGNATURE_ASSETS = {
    f"signature-{profile}.json" for profile in PROFILES
}
BASE_ASSETS = (
    "release-evidence.json",
    "release-evidence.md",
    "release-provenance.intoto.jsonl",
    "assurance-bootstrap.json",
    "assurance-certified.json",
    "assurance-public.json",
    "manifest-bootstrap.json",
    "manifest-certified.json",
    "manifest-public.json",
    "signature-bootstrap.json",
    "signature-certified.json",
    "signature-public.json",
    "sbom.cdx.json",
    "sbom-bootstrap.cdx.json",
    "sbom-certified.cdx.json",
    "sbom-public.cdx.json",
    "installed-collections-bootstrap.json",
    "installed-collections-certified.json",
    "installed-collections-public.json",
)
MAX_ASSET_BYTES = 16 * 1024 * 1024
MAX_SBOM_BYTES = 64 * 1024 * 1024
MAX_SIGNATURE_BYTES = 4 * 1024 * 1024
MAX_COLLECTION_BYTES = 256 * 1024 * 1024
MAX_INSTALLED_TREE_BYTES = 512 * 1024 * 1024
MAX_SBOM_CANONICAL_ASSIGNMENTS = 720
MAX_SBOM_CANONICAL_WORK_BYTES = 256 * 1024 * 1024
TRIVY_IMAGES = {
    "docker.io/aquasec/trivy:0.74.0@sha256:ee940acbf1f58ebadb42d01434ce4609530bf1b52536afbd1eee66cd7123c5c9",
    "docker.io/aquasec/trivy:0.74.0@sha256:55ad20f8a239a3e95427e60b8aaea38788550c18a3f1772976bebf732e6ae166",
}
FILE_PROVENANCE_SUBJECTS = {
    f"assurance-{profile}.json" for profile in PROFILES
} | {
    f"manifest-{profile}.json" for profile in PROFILES
} | {
    "sbom.cdx.json",
    *(f"sbom-{profile}.cdx.json" for profile in PROFILES),
    *(f"signature-{profile}.json" for profile in PROFILES),
    *(f"installed-collections-{profile}.json" for profile in PROFILES),
}


def release_asset_max_bytes(name: str) -> int:
    if name in CONTAINER_SBOM_ASSETS:
        return MAX_SBOM_BYTES
    if name in CONTAINER_SIGNATURE_ASSETS:
        return MAX_SIGNATURE_BYTES
    return MAX_ASSET_BYTES


RECEIPT_FIELDS = {
    "schemaVersion",
    "evidenceId",
    "evidenceUrl",
    "evidenceDigest",
    "securityIdentifiers",
    "producerRepository",
    "producerSourceSha",
    "producerWorkflowRepository",
    "producerWorkflowSha",
    "collection",
    "version",
    "collectionDigest",
    "signature",
    "sbom",
    "provenance",
    "consumerRepository",
    "baseSha",
}
GENERIC_FIELDS = {
    "generated_at",
    "repo",
    "type",
    "version",
    "tag",
    "sha",
    "release_url",
    "actions_run_url",
    "workflow_name",
    "job_names",
    "artifacts",
    "matrix",
    "tests",
    "publish",
    "security",
    "repository",
    "repository_type",
    "release_type",
    "artifact_type",
    "commit_sha",
    "workflow_run",
    "tested_matrix",
    "passed_jobs",
    "failed_jobs",
    "skipped_jobs",
    "skipped_reasons",
    "built_artifacts",
    "published_artifacts",
    "container_image_tags",
    "image_name",
    "registry",
    "quay_repository",
    "quay_image",
    "image_digest",
    "base_image",
    "build_context",
    "containerfile",
    "ansible_galaxy_artifact",
    "ansible_galaxy_version_url",
    "collection_namespace",
    "collection_name",
    "collection_version",
    "changelog",
    "security_scan",
    "trivy_status",
    "trivy_gate",
    "trivy_severity",
    "trivy_report",
    "sbom",
    "provenance",
    "signature",
}


def fail(message: str) -> None:
    raise ValueError(message)


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON field {key!r}")
        value[key] = item
    return value


def load_json(payload: bytes, name: str) -> Any:
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_pairs,
            parse_constant=lambda value: fail(f"invalid JSON constant {value}"),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{name} is not valid UTF-8 JSON") from exc


def require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{name} must contain a JSON object")
    return value


def require_exact_object(
    value: Any, fields: set[str], name: str
) -> dict[str, Any]:
    result = require_object(value, name)
    if set(result) != fields:
        fail(f"{name} fields are not exact")
    return result


def sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def read_bounded_fd(
    descriptor: int, *, max_bytes: int, label: str, expected_digest: str
) -> bytes:
    if type(descriptor) is not int or descriptor < 3:
        fail(f"{label} descriptor is invalid")
    duplicate = os.dup(descriptor)
    try:
        metadata = os.fstat(duplicate)
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISFIFO(metadata.st_mode)):
            fail(f"{label} descriptor is not a regular file or private pipe")
        chunks: list[bytes] = []
        total = 0
        digest = hashlib.sha256()
        while True:
            chunk = os.read(duplicate, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                fail(f"{label} exceeds the verification limit")
            digest.update(chunk)
            chunks.append(chunk)
    finally:
        os.close(duplicate)
    payload = b"".join(chunks)
    if not payload or f"sha256:{digest.hexdigest()}" != expected_digest:
        fail(f"{label} digest is invalid")
    return payload


def read_large_regular(
    path: Path, *, max_bytes: int, label: str, expected_digest: str
) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
            fail(f"{label} is not a non-empty regular file")
        if before.st_size > max_bytes:
            fail(f"{label} exceeds the verification limit")
        chunks: list[bytes] = []
        total = 0
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                fail(f"{label} exceeds the verification limit")
            digest.update(chunk)
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or total != before.st_size
        ):
            fail(f"{label} changed during verification")
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if sha256(payload) != expected_digest:
        fail(f"{label} digest does not match the producer receipt")
    return payload


def tar_manifest(payload: bytes, label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    total_size = 0
    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"{label} is not a readable tar archive") from exc
    with archive:
        for member in archive:
            candidate = PurePosixPath(member.name)
            parts = tuple(part for part in candidate.parts if part not in {"", "."})
            if candidate.is_absolute() or ".." in parts:
                fail(f"{label} contains an unsafe path")
            if not parts:
                if member.isdir():
                    continue
                fail(f"{label} contains an unsafe path")
            normalized = PurePosixPath(*parts).as_posix()
            if member.isdir():
                continue
            if not member.isfile() or normalized in result:
                fail(f"{label} contains a duplicate or non-regular entry")
            total_size += member.size
            if len(result) >= 100_000 or total_size > MAX_INSTALLED_TREE_BYTES:
                fail(f"{label} exceeds the archive verification limit")
            handle = archive.extractfile(member)
            if handle is None:
                fail(f"{label} cannot read {normalized}")
            digest = hashlib.sha256()
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
            result[normalized] = digest.hexdigest()
    if not result:
        fail(f"{label} contains no regular files")
    return result


def collection_version_from_tar(payload: bytes, label: str) -> str:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"{label} is not a readable tar archive") from exc
    manifests: list[bytes] = []
    with archive:
        for member in archive:
            normalized = PurePosixPath(member.name).as_posix().removeprefix("./")
            if not member.isfile() or normalized != "MANIFEST.json":
                continue
            handle = archive.extractfile(member)
            if handle is None:
                fail(f"{label} cannot read MANIFEST.json")
            manifests.append(handle.read(1024 * 1024 + 1))
    if len(manifests) != 1 or len(manifests[0]) > 1024 * 1024:
        fail(f"{label} must contain exactly one bounded MANIFEST.json")
    manifest = require_object(
        load_json(manifests[0], f"{label} MANIFEST.json"),
        f"{label} MANIFEST.json",
    )
    collection = require_object(
        manifest.get("collection_info"), f"{label} collection_info"
    )
    if collection.get("namespace") != "lit" or collection.get("name") != "supplementary":
        fail(f"{label} MANIFEST.json is not lit.supplementary")
    version = collection.get("version")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        fail(f"{label} MANIFEST.json version is invalid")
    return version


def require_collection_absent(payload: bytes, label: str) -> None:
    """Prove that a copied Ansible root has no target collection tree."""

    target = ("collections", "ansible_collections", "lit", "supplementary")

    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"{label} is not a readable tar archive") from exc
    with archive:
        for index, member in enumerate(archive):
            if index >= 100_000:
                fail(f"{label} exceeds the archive verification limit")
            candidate = PurePosixPath(member.name)
            parts = tuple(part for part in candidate.parts if part not in {"", "."})
            if candidate.is_absolute() or ".." in parts:
                fail(f"{label} contains an unsafe path")
            if parts[: len(target)] == target:
                fail("bootstrap image unexpectedly contains lit.supplementary")
            if member.issym() or member.islnk():
                if parts and parts == target[: len(parts)]:
                    fail("bootstrap collection path is not a verifiable directory")


def copy_collection_tree(
    reference: str, *, platform: str, expect_present: bool
) -> bytes | None:
    container_id = run_checked(
        ["docker", "create", "--platform", platform, reference], timeout=300
    ).decode("ascii", errors="strict").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", container_id):
        fail("docker create returned an invalid stopped-container ID")
    try:
        source = (
            "/usr/share/ansible/collections/ansible_collections/"
            "lit/supplementary/."
            if expect_present
            else "/usr/share/ansible/."
        )
        copied = subprocess.run(
            [
                "docker",
                "cp",
                f"{container_id}:{source}",
                "-",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=600,
        )
        if copied.returncode != 0 or not copied.stdout:
            detail = copied.stderr.decode("utf-8", errors="replace").strip()
            target = "installed collection tree" if expect_present else "Ansible root"
            fail(f"{target} is unavailable: {detail or 'no diagnostic'}")
        if len(copied.stdout) > MAX_INSTALLED_TREE_BYTES:
            fail("installed collection copy exceeds the verification limit")
        if expect_present:
            result: bytes | None = copied.stdout
        else:
            require_collection_absent(copied.stdout, "bootstrap Ansible root")
            result = None
    finally:
        removed = subprocess.run(
            ["docker", "rm", "--force", container_id],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=120,
        )
        if removed.returncode != 0:
            detail = removed.stderr.decode("utf-8", errors="replace").strip()
            fail(f"cannot remove stopped verification container: {detail or 'no diagnostic'}")
    return result


def validate_producer_materials(
    args: argparse.Namespace, receipt: dict[str, Any]
) -> dict[str, str]:
    inputs = {
        "artifact": (
            args.producer_artifact,
            args.producer_artifact_digest,
            MAX_COLLECTION_BYTES,
        ),
        "signature": (
            args.producer_signature,
            receipt["signature"]["digest"],
            MAX_ASSET_BYTES,
        ),
        "sbom": (args.producer_sbom, receipt["sbom"]["digest"], MAX_ASSET_BYTES),
        "provenance": (
            args.producer_provenance,
            receipt["provenance"]["digest"],
            MAX_ASSET_BYTES,
        ),
    }
    payloads: dict[str, bytes] = {}
    for name, (path, expected_digest, limit) in inputs.items():
        if path is None or not isinstance(expected_digest, str) or not DIGEST.fullmatch(
            expected_digest
        ):
            fail(f"security release producer {name} input is invalid")
        payloads[name] = read_large_regular(
            path,
            max_bytes=limit,
            label=f"authenticated producer {name}",
            expected_digest=expected_digest,
        )
    if receipt["collectionDigest"] != args.producer_artifact_digest:
        fail("producer artifact digest differs from the immutable receipt")
    verify_blob(
        payloads["artifact"],
        payloads["signature"],
        identity=(
            "https://github.com/lightning-it/ansible-collection-supplementary/"
            ".github/workflows/collection-ci.yml@refs/heads/main"
        ),
        source_sha=receipt["producerWorkflowSha"],
    )
    sbom = require_object(load_json(payloads["sbom"], "producer SBOM"), "producer SBOM")
    metadata = require_object(sbom.get("metadata"), "producer SBOM metadata")
    component = require_object(metadata.get("component"), "producer SBOM component")
    expected_hash = receipt["collectionDigest"].removeprefix("sha256:")
    if (
        sbom.get("bomFormat") != "CycloneDX"
        or component.get("version") != receipt["version"]
        or component.get("purl")
        != f"pkg:ansible/lit/supplementary@{receipt['version']}"
        or {"alg": "SHA-256", "content": expected_hash}
        not in component.get("hashes", [])
    ):
        fail("producer SBOM is not collection/version/digest bound")
    properties = component.get("properties")
    if not isinstance(properties, list):
        fail("producer SBOM component properties are missing")
    actual_properties = {
        (entry.get("name"), entry.get("value"))
        for entry in properties
        if isinstance(entry, dict)
    }
    expected_properties = {
        (
            "lit:candidate:filename",
            f"lit-supplementary-{receipt['version']}.tar.gz",
        ),
        ("lit:candidate:commit", receipt["producerSourceSha"]),
    }
    if not expected_properties <= actual_properties:
        fail("producer SBOM does not bind filename and source SHA")
    provenance = require_object(
        load_json(payloads["provenance"], "producer provenance"),
        "producer provenance",
    )
    expected_provenance = {
        "schema_version": 1,
        "repository": "lightning-it/ansible-collection-supplementary",
        "candidate": f"lit-supplementary-{receipt['version']}.tar.gz",
        "candidate_sha256": expected_hash,
        "commit_sha": receipt["producerSourceSha"],
        "ref": "refs/heads/main",
        "source_ref": "refs/heads/main",
        "workflow": "Collection CI",
        "workflow_event_sha": receipt["producerSourceSha"],
    }
    for field, expected in expected_provenance.items():
        if provenance.get(field) != expected:
            fail(f"producer provenance field {field} is invalid")
    return tar_manifest(payloads["artifact"], "authenticated producer collection artifact")


def write_exclusive(directory: Any, name: str, payload: bytes) -> Path:
    descriptor = open_exclusive_regular(directory, name)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o400:
            fail(f"generated {name} is not a read-only regular file")
    finally:
        os.close(descriptor)
    directory.snapshots.add(name)
    return directory.path / name


def sealed_payload_fd(payload: bytes, label: str) -> int:
    if not isinstance(payload, bytes) or not payload:
        fail(f"{label} immutable payload is empty")
    if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
        fail("release verifier requires Linux sealed-memory descriptors")
    descriptor = os.memfd_create(
        f"mlx90-{label}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(f"cannot snapshot {label}")
            view = view[written:]
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.fchmod(descriptor, 0o400)
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE,
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def run_cosign(
    command: list[str],
    *,
    payload: bytes,
    pass_fds: tuple[int, ...] = (),
) -> bytes:
    completed = subprocess.run(
        command,
        check=False,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        pass_fds=pass_fds,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"cosign failed: {detail or 'no diagnostic'}")
    return completed.stdout


def run_checked(
    command: list[str],
    *,
    timeout: int = 300,
    max_output_bytes: int = MAX_ASSET_BYTES,
) -> bytes:
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"live release reauthentication failed: {detail or 'no diagnostic'}")
    if len(completed.stdout) > max_output_bytes:
        fail("live release reauthentication output exceeds the verification limit")
    return completed.stdout


def verify_blob(
    payload: bytes,
    bundle: bytes,
    *,
    identity: str,
    source_sha: str,
) -> None:
    if not isinstance(bundle, bytes) or not bundle:
        fail("cosign returned an empty bundle")
    load_json(bundle, "Sigstore bundle")
    descriptor = sealed_payload_fd(bundle, "sigstore-bundle")
    try:
        run_cosign(
            [
                "cosign",
                "verify-blob",
                "--bundle",
                f"/dev/fd/{descriptor}",
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--certificate-github-workflow-sha",
                source_sha,
                "-",
            ],
            payload=payload,
            pass_fds=(descriptor,),
        )
    finally:
        os.close(descriptor)


def sign_blob(payload: bytes, *, identity: str, source_sha: str) -> bytes:
    bundle = run_cosign(
        [
            "cosign",
            "sign-blob",
            "--yes",
            "--bundle",
            "/dev/stdout",
            "-",
        ],
        payload=payload,
    )
    verify_blob(payload, bundle, identity=identity, source_sha=source_sha)
    return bundle


def parse_rfc3339(value: Any, name: str) -> datetime:
    if not isinstance(value, str):
        fail(f"{name} must be an RFC3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be RFC3339") from exc
    if parsed.tzinfo is None:
        fail(f"{name} must include a timezone")
    return parsed


def validate_receipt_ref(
    value: Any, *, version: str, field: str, asset: str
) -> dict[str, str]:
    reference = require_exact_object(value, {"url", "digest"}, f"receipt {field}")
    expected_url = (
        "https://github.com/lightning-it/ansible-collection-supplementary/"
        f"releases/download/v{version}/{asset}"
    )
    if reference["url"] != expected_url or not isinstance(reference["digest"], str):
        fail(f"receipt {field} is not the exact producer asset")
    if not DIGEST.fullmatch(reference["digest"]):
        fail(f"receipt {field} digest is invalid")
    return {"url": reference["url"], "digest": reference["digest"]}


def validate_receipt(
    payload: bytes, *, repository: str, collection_version: str
) -> dict[str, Any]:
    receipt = require_exact_object(
        load_json(payload, "receipt"), RECEIPT_FIELDS, "receipt"
    )
    if receipt["schemaVersion"] != 1 or type(receipt["schemaVersion"]) is not int:
        fail("receipt schema version is invalid")
    if (
        receipt["producerRepository"]
        != "lightning-it/ansible-collection-supplementary"
        or receipt["producerWorkflowRepository"]
        != "lightning-it/ansible-collection-supplementary"
        or receipt["consumerRepository"] != repository
        or receipt["collection"] != "lit.supplementary"
        or receipt["version"] != collection_version
    ):
        fail("receipt repository or collection identity is invalid")
    if not EVIDENCE_ID.fullmatch(str(receipt["evidenceId"])):
        fail("receipt evidence ID is invalid")
    identifiers = receipt["securityIdentifiers"]
    if (
        not isinstance(identifiers, list)
        or not identifiers
        or len(identifiers) != len(set(identifiers))
        or not all(isinstance(item, str) and SECURITY_ID.fullmatch(item) for item in identifiers)
    ):
        fail("receipt security identifiers are invalid")
    for field in ("producerSourceSha", "producerWorkflowSha", "baseSha"):
        if not isinstance(receipt[field], str) or not SHA.fullmatch(receipt[field]):
            fail(f"receipt {field} is invalid")
    if receipt["producerSourceSha"] != receipt["producerWorkflowSha"]:
        fail("receipt producer workflow SHA does not equal its source SHA")
    for field in ("evidenceDigest", "collectionDigest"):
        if not isinstance(receipt[field], str) or not DIGEST.fullmatch(receipt[field]):
            fail(f"receipt {field} is invalid")
    evidence = validate_receipt_ref(
        {"url": receipt["evidenceUrl"], "digest": receipt["evidenceDigest"]},
        version=collection_version,
        field="evidence",
        asset="security-release-evidence.json",
    )
    if receipt["evidenceUrl"] != evidence["url"]:
        fail("receipt evidence URL is invalid")
    expected_assets = {
        "signature": f"lit-supplementary-{collection_version}.tar.gz.sigstore.json",
        "sbom": "sbom.cdx.json",
        "provenance": "provenance.json",
    }
    for field, asset in expected_assets.items():
        validate_receipt_ref(
            receipt[field], version=collection_version, field=field, asset=asset
        )
    return receipt


def parse_variants(values: list[str]) -> dict[str, tuple[str, str]]:
    variants: dict[str, tuple[str, str]] = {}
    for value in values:
        profile, separator, reference = value.partition("=")
        image, at, digest = reference.rpartition("@")
        if (
            not separator
            or not at
            or profile not in PROFILES
            or profile in variants
            or not re.fullmatch(r"quay\.io/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", image)
            or not DIGEST.fullmatch(digest)
        ):
            fail("variant must be one exact profile=quay-image@sha256 reference")
        variants[profile] = (image, digest)
    if set(variants) != set(PROFILES):
        fail("exactly public, certified, and bootstrap variants are required")
    public_image = variants["public"][0]
    for profile in PROFILES:
        if variants[profile][0] != public_image + PROFILE_SUFFIXES[profile]:
            fail(f"{profile} image does not derive from the public image")
    return variants


def validate_file_ref(
    value: Any, *, expected_name: str, payloads: dict[str, bytes], label: str
) -> dict[str, str]:
    reference = require_exact_object(value, {"file", "digest"}, label)
    if reference["file"] != expected_name or not isinstance(reference["digest"], str):
        fail(f"{label} does not name the exact asset")
    if reference["digest"] != sha256(payloads[expected_name]):
        fail(f"{label} digest does not match the captured asset")
    return {"file": expected_name, "digest": reference["digest"]}


def validate_profile(
    profile: str,
    payloads: dict[str, bytes],
    json_values: dict[str, Any],
    *,
    collection_version: str,
    expected_image: str,
    expected_digest: str,
) -> dict[str, Any]:
    assurance = require_exact_object(
        json_values[f"assurance-{profile}.json"],
        {
            "image",
            "manifestDigest",
            "platforms",
            "attestationDigests",
            "manifest",
            "signature",
            "sbom",
            "installedCollections",
            "installedCollection",
        },
        f"{profile} assurance",
    )
    if assurance["image"] != expected_image or assurance["manifestDigest"] != expected_digest:
        fail(f"{profile} assurance image identity is invalid")
    platforms = require_exact_object(
        assurance["platforms"], {"linux/amd64", "linux/arm64"}, f"{profile} platforms"
    )
    if (
        not all(isinstance(item, str) and DIGEST.fullmatch(item) for item in platforms.values())
        or len(set(platforms.values())) != 2
    ):
        fail(f"{profile} platform digests are invalid")
    attestations = assurance["attestationDigests"]
    if (
        not isinstance(attestations, list)
        or len(attestations) < 2
        or len(attestations) != len(set(attestations))
        or not all(isinstance(item, str) and DIGEST.fullmatch(item) for item in attestations)
    ):
        fail(f"{profile} attestation digests are invalid")
    expected_files = {
        "manifest": f"manifest-{profile}.json",
        "signature": f"signature-{profile}.json",
        "sbom": f"sbom-{profile}.cdx.json",
        "installedCollections": f"installed-collections-{profile}.json",
    }
    references = {
        field: validate_file_ref(
            assurance[field],
            expected_name=name,
            payloads=payloads,
            label=f"{profile} assurance {field}",
        )
        for field, name in expected_files.items()
    }
    expected_installed = (
        None
        if profile == "bootstrap"
        else {"name": "lit.supplementary", "version": collection_version}
    )
    if assurance["installedCollection"] != expected_installed:
        fail(f"{profile} installed collection identity is invalid")

    manifest = require_object(json_values[f"manifest-{profile}.json"], f"{profile} manifest")
    if sha256(payloads[f"manifest-{profile}.json"]) != expected_digest:
        fail(f"{profile} raw OCI manifest is not bound to the expected digest")
    descriptors = manifest.get("manifests")
    if not isinstance(descriptors, list):
        fail(f"{profile} manifest descriptors are missing")
    platform_records: dict[str, str] = {}
    attestation_records: set[str] = set()
    for descriptor in descriptors:
        record = require_object(descriptor, f"{profile} manifest descriptor")
        digest = record.get("digest")
        platform = record.get("platform")
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or not isinstance(platform, dict):
            fail(f"{profile} manifest descriptor is invalid")
        operating_system, architecture = platform.get("os"), platform.get("architecture")
        if operating_system == "linux" and architecture in {"amd64", "arm64"}:
            key = f"linux/{architecture}"
            if key in platform_records:
                fail(f"{profile} manifest platform is duplicated")
            platform_records[key] = digest
        elif operating_system == "unknown":
            attestation_records.add(digest)
        else:
            fail(f"{profile} manifest contains an unsupported executable platform")
    if platform_records != platforms or attestation_records != set(attestations):
        fail(f"{profile} manifest does not match its assurance record")

    signatures = json_values[f"signature-{profile}.json"]
    if not isinstance(signatures, list) or not signatures:
        fail(f"{profile} signature evidence is empty")
    for signature in signatures:
        record = require_object(signature, f"{profile} signature record")
        try:
            signed_digest = record["critical"]["image"]["docker-manifest-digest"]
        except (KeyError, TypeError) as exc:
            raise ValueError(f"{profile} signature record is malformed") from exc
        if signed_digest != expected_digest:
            fail(f"{profile} signature is not manifest bound")

    sbom = require_object(json_values[f"sbom-{profile}.cdx.json"], f"{profile} SBOM")
    if (
        sbom.get("bomFormat") != "CycloneDX"
        or not isinstance(sbom.get("specVersion"), str)
        or not isinstance(sbom.get("components"), list)
    ):
        fail(f"{profile} SBOM contract is invalid")
    installed = require_object(
        json_values[f"installed-collections-{profile}.json"],
        f"{profile} installed collections",
    )
    installed_versions: list[Any] = []
    for value in installed.values():
        if isinstance(value, dict) and isinstance(value.get("lit.supplementary"), dict):
            installed_versions.append(value["lit.supplementary"].get("version"))
    if profile == "bootstrap":
        if installed_versions:
            fail("bootstrap unexpectedly contains lit.supplementary")
    elif installed_versions != [collection_version]:
        fail(f"{profile} installed collection set is not exact")

    return {
        "image": expected_image,
        "manifestDigest": expected_digest,
        "platforms": platforms,
        "attestationDigests": attestations,
        **references,
        "installedCollection": expected_installed,
    }


SBOM_REFERENCE_KEYS = {
    "assemblies",
    "bom-ref",
    "dependencies",
    "dependsOn",
    "provides",
    "ref",
    "services",
    "subjects",
    "vulnerabilities",
}
SBOM_UNORDERED_ARRAY_KEYS = {
    "advisories",
    "affects",
    "assemblies",
    "components",
    "compositions",
    "cwes",
    "dependencies",
    "dependsOn",
    "externalReferences",
    "hashes",
    "licenses",
    "properties",
    "provides",
    "ratings",
    "services",
    "subjects",
    "tools",
    "versions",
    "vulnerabilities",
}


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonicalize_sbom_sets(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {
            child_key: canonicalize_sbom_sets(item, child_key)
            for child_key, item in sorted(value.items())
        }
    if isinstance(value, list):
        items = [canonicalize_sbom_sets(item, key) for item in value]
        if key in SBOM_UNORDERED_ARRAY_KEYS:
            return sorted(items, key=canonical_json)
        return items
    return value


def reference_independent_content(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {
            child_key: reference_independent_content(item, child_key)
            for child_key, item in sorted(value.items())
            if child_key != "bom-ref"
        }
    if isinstance(value, list):
        return [reference_independent_content(item, key) for item in value]
    if isinstance(value, str) and key in SBOM_REFERENCE_KEYS:
        return "<cyclonedx-reference>"
    return value


def bounded_factorial(value: int, limit: int, name: str) -> int:
    result = 1
    for factor in range(2, value + 1):
        if result > limit // factor:
            fail(f"{name} exceeds the bounded reference canonicalization work limit")
        result *= factor
    return result


def normalize_sbom(value: Any, name: str) -> dict[str, Any]:
    sbom = require_object(value, name)
    normalized = json.loads(json.dumps(sbom, sort_keys=True, allow_nan=False))
    normalized.pop("serialNumber", None)
    metadata = normalized.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("timestamp", None)

    components = normalized.get("components")
    if not isinstance(components, list):
        fail(f"{name} components are missing")
    referenceable_records: list[tuple[dict[str, Any], str]] = []

    def collect_referenceable_records(item: Any, location: str) -> None:
        if isinstance(item, dict):
            if "bom-ref" in item:
                referenceable_records.append((item, location))
            for child_key, child in sorted(item.items()):
                collect_referenceable_records(child, f"{location}.{child_key}")
        elif isinstance(item, list):
            for index, child in enumerate(item):
                collect_referenceable_records(child, f"{location}[{index}]")

    collect_referenceable_records(normalized, name)

    seen_references: set[str] = set()
    fingerprint_references: dict[str, set[str]] = {}
    for record, location in referenceable_records:
        reference = record.get("bom-ref")
        if not isinstance(reference, str) or not reference:
            fail(f"{location} has an invalid bom-ref")
        if reference in seen_references:
            fail(f"{name} reuses a bom-ref")
        seen_references.add(reference)
        semantic_record = reference_independent_content(record)
        fingerprint = hashlib.sha256(
            canonical_json(canonicalize_sbom_sets(semantic_record)).encode("utf-8")
        ).hexdigest()
        fingerprint_references.setdefault(fingerprint, set()).add(reference)

    def rewrite_references(
        item: Any, references: dict[str, str], key: str | None = None
    ) -> Any:
        if isinstance(item, dict):
            rewritten = {
                child_key: rewrite_references(child, references, child_key)
                for child_key, child in sorted(item.items())
            }
            return rewritten
        if isinstance(item, list):
            rewritten = [rewrite_references(child, references, key) for child in item]
            if key in SBOM_UNORDERED_ARRAY_KEYS:
                return sorted(rewritten, key=canonical_json)
            return rewritten
        if isinstance(item, str) and key in SBOM_REFERENCE_KEYS:
            if item in references:
                return references[item]
            if UUID_REFERENCE.fullmatch(item):
                fail(f"{name} contains an unresolved UUID reference")
        return item

    document_bytes = len(canonical_json(normalized).encode("utf-8"))
    assignment_limit = min(
        MAX_SBOM_CANONICAL_ASSIGNMENTS,
        max(1, MAX_SBOM_CANONICAL_WORK_BYTES // max(1, document_bytes)),
    )
    fixed_references: dict[str, str] = {}
    ambiguous_groups: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
    assignment_count = 1
    for fingerprint, values in sorted(fingerprint_references.items()):
        references = tuple(sorted(values))
        canonical_root = f"urn:mlx90:cyclonedx-object:sha256:{fingerprint}"
        if len(references) == 1:
            fixed_references[references[0]] = canonical_root
            continue
        group_assignments = bounded_factorial(
            len(references), assignment_limit // assignment_count, name
        )
        assignment_count *= group_assignments
        canonical_references = tuple(
            f"{canonical_root}:{index}" for index in range(len(references))
        )
        ambiguous_groups.append((references, canonical_references))

    best_text: str | None = None
    best_value: dict[str, Any] | None = None

    def select_canonical_assignment(
        index: int, references: dict[str, str]
    ) -> None:
        nonlocal best_text, best_value
        if index == len(ambiguous_groups):
            candidate = rewrite_references(normalized, references)
            candidate_text = canonical_json(candidate)
            if best_text is None or candidate_text < best_text:
                best_text = candidate_text
                best_value = candidate
            return
        originals, canonical_values = ambiguous_groups[index]
        for permutation in itertools.permutations(canonical_values):
            for original, canonical_value in zip(originals, permutation):
                references[original] = canonical_value
            select_canonical_assignment(index + 1, references)
            for original in originals:
                del references[original]

    select_canonical_assignment(0, dict(fixed_references))
    if best_value is None:
        fail(f"{name} could not be canonicalized")
    return best_value


def normalize_sbom_inventory(
    value: Any,
    name: str,
    *,
    allow_legacy_vulnerability_enrichment: bool = False,
) -> dict[str, Any]:
    """Canonicalize inventory while isolating legacy, mutable DB findings."""
    sbom = require_object(value, name)
    inventory = json.loads(json.dumps(sbom, sort_keys=True, allow_nan=False))
    has_vulnerability_enrichment = "vulnerabilities" in inventory
    vulnerabilities = inventory.pop("vulnerabilities", None)
    if has_vulnerability_enrichment and not isinstance(vulnerabilities, list):
        fail(f"{name} vulnerabilities are invalid")
    if vulnerabilities and not allow_legacy_vulnerability_enrichment:
        fail(f"{name} unexpectedly contains vulnerability enrichment")
    return normalize_sbom(inventory, name)


def reauthenticate_profile(
    profile: str,
    payloads: dict[str, bytes],
    json_values: dict[str, Any],
    *,
    repository: str,
    release_tag: str,
    source_sha: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
    release_version: str,
    collection_version: str,
    image: str,
    digest: str,
    platform_digests: dict[str, str],
    trivy_image: str,
    producer_tree: dict[str, str] | None,
) -> None:
    reference = f"{image}@{digest}"
    identity = (
        f"https://github.com/{repository}/.github/workflows/"
        f"container-build-publish.yml@refs/tags/{release_tag}"
    )
    verified_signatures = load_json(
        run_checked(
            [
                "cosign",
                "verify",
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--certificate-github-workflow-sha",
                source_sha,
                reference,
            ]
        ),
        f"live {profile} signature evidence",
    )
    if verified_signatures != json_values[f"signature-{profile}.json"]:
        fail(f"{profile} signature capture differs from live registry verification")

    buildkit = load_json(
        run_checked(
            [
                "docker",
                "buildx",
                "imagetools",
                "inspect",
                reference,
                "--format",
                "{{json .Provenance}}",
            ]
        ),
        f"live {profile} BuildKit provenance",
    )
    buildkit = require_exact_object(
        buildkit, {"linux/amd64", "linux/arm64"}, f"live {profile} BuildKit provenance"
    )
    for platform, value in buildkit.items():
        record = require_object(value, f"{profile} {platform} BuildKit provenance")
        try:
            labels = record["SLSA"]["buildDefinition"]["externalParameters"]["request"]["args"]
            builder = record["SLSA"]["runDetails"]["builder"]["id"]
        except (KeyError, TypeError) as exc:
            raise ValueError(f"{profile} {platform} BuildKit provenance is malformed") from exc
        if (
            labels.get("label:org.opencontainers.image.revision") != source_sha
            or labels.get("label:org.opencontainers.image.version") != release_version
            or not isinstance(builder, str)
            or builder
            != (
                f"https://github.com/{repository}/actions/runs/"
                f"{workflow_run_id}/attempts/{workflow_run_attempt}"
            )
        ):
            fail(f"{profile} {platform} BuildKit provenance is not release-run bound")

    for platform in ("linux/amd64", "linux/arm64"):
        platform_reference = f"{image}@{platform_digests[platform]}"
        installed_tree = copy_collection_tree(
            platform_reference,
            platform=platform,
            expect_present=profile != "bootstrap",
        )
        if profile != "bootstrap":
            if installed_tree is None:
                fail(f"{profile} {platform} installed collection tree is missing")
            actual_version = collection_version_from_tar(
                installed_tree, f"live {profile} {platform} installed collection"
            )
            if actual_version != collection_version:
                fail(f"{profile} {platform} installed collection version is invalid")
            if producer_tree is not None and tar_manifest(
                installed_tree, f"live {profile} {platform} installed collection"
            ) != producer_tree:
                fail(
                    f"{profile} {platform} installed collection bytes differ "
                    "from the producer artifact"
                )

        run_checked(
            [
                "docker",
                "run",
                "--rm",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges=true",
                "--pids-limit",
                "256",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=4g",
                trivy_image,
                "image",
                "--cache-dir",
                "/tmp/trivy-cache",
                "--scanners",
                "vuln",
                "--ignore-unfixed",
                "--severity",
                "CRITICAL",
                "--exit-code",
                "1",
                platform_reference,
            ],
            timeout=900,
        )

    live_sbom = load_json(
        run_checked(
            [
                "docker",
                "run",
                "--rm",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges=true",
                "--pids-limit",
                "256",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=4g",
                trivy_image,
                "image",
                "--cache-dir",
                "/tmp/trivy-cache",
                "--scanners",
                "license",
                "--format",
                "cyclonedx",
                reference,
            ],
            timeout=900,
            max_output_bytes=MAX_SBOM_BYTES,
        ),
        f"live {profile} SBOM",
    )
    if normalize_sbom_inventory(
        live_sbom, f"live {profile} SBOM"
    ) != normalize_sbom_inventory(
        json_values[f"sbom-{profile}.cdx.json"],
        f"captured {profile} SBOM",
        allow_legacy_vulnerability_enrichment=True,
    ):
        fail(f"{profile} SBOM capture differs from a live pinned-image scan")


def validate_provenance(
    provenance: Any,
    payloads: dict[str, bytes],
    *,
    repository: str,
    release_tag: str,
    source_sha: str,
    workflow_run_id: int,
    variants: dict[str, tuple[str, str]],
) -> None:
    statement = require_exact_object(
        provenance, {"_type", "subject", "predicateType", "predicate"}, "release provenance"
    )
    if (
        statement["_type"] != "https://in-toto.io/Statement/v1"
        or statement["predicateType"] != "https://slsa.dev/provenance/v1"
    ):
        fail("release provenance envelope is invalid")
    expected_images = {f"{image}@{digest}" for image, digest in variants.values()}
    subjects = statement["subject"]
    if not isinstance(subjects, list) or len(subjects) != len(FILE_PROVENANCE_SUBJECTS) + 3:
        fail("release provenance subject count is invalid")
    seen: set[str] = set()
    for value in subjects:
        item = require_object(value, "release provenance subject")
        name = item.get("name")
        if not isinstance(name, str) or name in seen:
            fail("release provenance subject name is invalid or duplicated")
        seen.add(name)
        if name in FILE_PROVENANCE_SUBJECTS:
            if set(item) != {"name", "digest"}:
                fail(f"release provenance file subject {name} is malformed")
            digest = require_exact_object(item["digest"], {"sha256"}, f"{name} provenance digest")
            if digest["sha256"] != hashlib.sha256(payloads[name]).hexdigest():
                fail(f"release provenance digest mismatch for {name}")
        elif name in expected_images:
            if set(item) != {"name"}:
                fail("release provenance image subject unexpectedly has mutable metadata")
        else:
            fail(f"release provenance has unexpected subject {name}")
    if seen != FILE_PROVENANCE_SUBJECTS | expected_images:
        fail("release provenance subject set is incomplete")

    predicate = require_exact_object(
        statement["predicate"], {"buildDefinition", "runDetails"}, "release provenance predicate"
    )
    build = require_exact_object(
        predicate["buildDefinition"],
        {"buildType", "externalParameters", "internalParameters", "resolvedDependencies"},
        "release provenance build definition",
    )
    expected_parameters = {
        "repository": repository,
        "release": release_tag,
        "commit": source_sha,
    }
    if (
        build["buildType"] != "https://lightning-it.io/provenance/workflow-release"
        or build["externalParameters"] != expected_parameters
        or build["internalParameters"] != {}
        or build["resolvedDependencies"]
        != [
            {
                "uri": f"git+https://github.com/{repository}@{source_sha}",
                "digest": {"gitCommit": source_sha},
            }
        ]
    ):
        fail("release provenance build identity is invalid")
    run = require_exact_object(
        predicate["runDetails"], {"builder", "metadata", "byproducts"}, "provenance run details"
    )
    if run["builder"] != {"id": f"https://github.com/{repository}/actions"}:
        fail("release provenance builder is invalid")
    metadata = require_exact_object(
        run["metadata"], {"invocationId", "startedOn", "finishedOn"}, "provenance metadata"
    )
    if metadata["invocationId"] != str(workflow_run_id):
        fail("release provenance invocation is invalid")
    if parse_rfc3339(metadata["startedOn"], "provenance startedOn") != parse_rfc3339(
        metadata["finishedOn"], "provenance finishedOn"
    ):
        fail("release provenance generation timestamps differ")
    run_url = f"https://github.com/{repository}/actions/runs/{workflow_run_id}"
    if run["byproducts"] != [{"name": "workflow_run", "uri": run_url}]:
        fail("release provenance run byproduct is invalid")


def expanded_profile(
    profile: dict[str, Any], *, release_asset_base: str, provenance_digest: str
) -> dict[str, Any]:
    value = dict(profile)
    for field in ("manifest", "signature", "sbom", "installedCollections"):
        reference = dict(value[field])
        reference["url"] = f"{release_asset_base}/{reference['file']}"
        value[field] = reference
    value["provenance"] = {
        "file": "release-provenance.intoto.jsonl",
        "url": f"{release_asset_base}/release-provenance.intoto.jsonl",
        "digest": provenance_digest,
    }
    return value


def validate_generic(
    generic_value: Any,
    payloads: dict[str, bytes],
    *,
    args: argparse.Namespace,
    receipt: dict[str, Any] | None,
    profiles: dict[str, dict[str, Any]],
    variants: dict[str, tuple[str, str]],
) -> None:
    expected_fields = GENERIC_FIELDS | ({"mlx90"} if args.security else set())
    generic = require_exact_object(generic_value, expected_fields, "generic release evidence")
    release_version = args.release_tag.removeprefix("v")
    run_url = f"https://github.com/{args.repository}/actions/runs/{args.workflow_run_id}"
    release_base = f"https://github.com/{args.repository}/releases/download/{args.release_tag}"
    release_url = f"https://github.com/{args.repository}/releases/tag/{args.release_tag}"
    expected_scalars = {
        "repo": args.repository,
        "repository": args.repository,
        "version": release_version,
        "tag": args.release_tag,
        "sha": args.source_sha,
        "commit_sha": args.source_sha,
        "release_url": release_url,
        "actions_run_url": run_url,
        "workflow_run": run_url,
        "workflow_name": "Container Build & Publish",
        "registry": "quay.io",
        "image_digest": variants["public"][1],
        "security_scan": "trivy-completed",
        "trivy_status": "passed",
        "trivy_gate": "passed-before-quay-publish",
        "trivy_severity": "CRITICAL",
        "trivy_report": f"{release_base}/sbom.cdx.json",
        "sbom": f"{release_base}/sbom.cdx.json",
        "provenance": f"{release_base}/release-provenance.intoto.jsonl",
        "signature": f"{release_base}/SHA256SUMS.sigstore.json",
    }
    for field, expected in expected_scalars.items():
        if generic[field] != expected:
            fail(f"generic release evidence {field} is invalid")
    parse_rfc3339(generic["generated_at"], "generic evidence generated_at")

    profile_order = ("public", "certified", "bootstrap")
    image_refs = [f"{variants[profile][0]}@{variants[profile][1]}" for profile in profile_order]
    if args.security:
        candidate_suffix = (
            f"{args.source_sha}-{args.workflow_run_id}-{args.workflow_run_attempt}"
        )
        published = [
            f"{variants[profile][0]}:mlx90-candidate-{candidate_suffix}"
            for profile in profile_order
        ]
    else:
        published = []
        for profile in profile_order:
            image = variants[profile][0]
            published.extend(
                [
                    f"{image}:{args.release_tag}",
                    f"{image}:{release_version}",
                    f"{image}:sha-{args.source_sha[:12]}",
                    f"{image}:latest",
                ]
            )
    expected_lists = {
        "built_artifacts": image_refs,
        "published_artifacts": published,
        "container_image_tags": published,
        "failed_jobs": [],
        "skipped_jobs": [],
        "skipped_reasons": [],
        "tested_matrix": [
            "ubuntu-latest",
            "docker-buildx",
            "trivy",
            "public-profile",
            "certified-profile",
            "bootstrap-profile",
        ],
    }
    for field, expected in expected_lists.items():
        if generic[field] != expected:
            fail(f"generic release evidence {field} is invalid")
    if generic["quay_image"] != ",".join(image_refs):
        fail("generic release evidence Quay image set is invalid")
    artifacts = require_exact_object(
        generic["artifacts"], {"built", "published", "checksums"}, "generic artifacts"
    )
    if (
        artifacts["built"] != [{"name": item, "sha256": ""} for item in image_refs]
        or artifacts["published"] != published
        or artifacts["checksums"] != []
    ):
        fail("generic release artifact set is invalid")
    publish = require_exact_object(
        generic["publish"],
        {"status", "ansible_galaxy_status", "ansible_galaxy_url", "quay_status", "quay_image", "published_image_url"},
        "generic publish record",
    )
    if publish != {
        "status": "published",
        "ansible_galaxy_status": "",
        "ansible_galaxy_url": "",
        "quay_status": "published",
        "quay_image": ",".join(image_refs),
        "published_image_url": "",
    }:
        fail("generic publish record is invalid")
    security_record = require_exact_object(
        generic["security"],
        {"lint_status", "collection_sanity_status", "security_scan_status", "trivy_status", "trivy_gate", "trivy_severity", "trivy_report"},
        "generic security record",
    )
    if security_record != {
        "lint_status": "",
        "collection_sanity_status": "",
        "security_scan_status": "trivy-completed",
        "trivy_status": "passed",
        "trivy_gate": "passed-before-quay-publish",
        "trivy_severity": "CRITICAL",
        "trivy_report": f"{release_base}/sbom.cdx.json",
    }:
        fail("generic security record is invalid")
    if not isinstance(generic["matrix"], list) or not generic["matrix"]:
        fail("generic release matrix is empty")
    for row in generic["matrix"]:
        item = require_object(row, "generic release matrix row")
        if item.get("status") != "passed" or item.get("evidence") != run_url:
            fail("generic release matrix row is not run bound")
    if generic["tests"].get("failed_jobs") != [] or generic["tests"].get("skipped_jobs") != []:
        fail("generic release tests record contains failed or skipped jobs")

    if not args.security:
        if "mlx90-container-evidence.json" in payloads:
            fail("ordinary release unexpectedly contains MLX-90 container evidence")
        if b"mlx90-immutable-delivery" in payloads["release-evidence.md"]:
            fail("ordinary release unexpectedly contains an MLX-90 Markdown section")
        return
    if receipt is None:
        fail("security release requires an immutable receipt")
    provenance_digest = sha256(payloads["release-provenance.intoto.jsonl"])
    expanded = {
        profile: expanded_profile(
            profiles[profile],
            release_asset_base=release_base,
            provenance_digest=provenance_digest,
        )
        for profile in PROFILES
    }
    expected_mlx90 = {
        "evidenceId": receipt["evidenceId"],
        "securityIdentifiers": receipt["securityIdentifiers"],
        "producer": {
            "repository": receipt["producerRepository"],
            "sourceSha": receipt["producerSourceSha"],
            "workflowRepository": receipt["producerWorkflowRepository"],
            "workflowSha": receipt["producerWorkflowSha"],
            "collection": receipt["collection"],
            "version": receipt["version"],
            "collectionDigest": receipt["collectionDigest"],
            "evidence": {"url": receipt["evidenceUrl"], "digest": receipt["evidenceDigest"]},
            "signature": receipt["signature"],
            "sbom": receipt["sbom"],
            "provenance": receipt["provenance"],
        },
        "consumer": {
            "repository": receipt["consumerRepository"],
            "baseSha": receipt["baseSha"],
            "mergeSha": args.source_sha,
        },
        "containers": expanded,
    }
    if generic["mlx90"] != expected_mlx90:
        fail("generic MLX-90 evidence is not the exact receipt-bound contract")

    container_variants: dict[str, Any] = {}
    for profile in PROFILES:
        record = expanded[profile]
        container_variants[profile] = {
            "image": record["image"],
            "manifestDigest": record["manifestDigest"],
            "platformDigests": record["platforms"],
            "signature": {"url": record["signature"]["url"], "digest": record["signature"]["digest"]},
            "sbom": {"url": record["sbom"]["url"], "digest": record["sbom"]["digest"]},
            "provenance": {"url": record["provenance"]["url"], "digest": record["provenance"]["digest"]},
        }
    expected_container = {
        "apiVersion": "lit.security-release.container/v1",
        "kind": "SecurityReleaseContainerEvidence",
        "securityEvidenceId": receipt["evidenceId"],
        "producer": {
            "repository": receipt["producerRepository"],
            "sourceSha": receipt["producerSourceSha"],
            "collection": receipt["collection"],
            "version": receipt["version"],
            "collectionDigest": receipt["collectionDigest"],
            "evidence": {"url": receipt["evidenceUrl"], "digest": receipt["evidenceDigest"]},
        },
        "consumer": {
            "repository": receipt["consumerRepository"],
            "pullRequest": args.consumer_pull_request,
            "baseSha": receipt["baseSha"],
            "headSha": args.consumer_head_sha,
            "mergeSha": args.source_sha,
        },
        "release": {
            "repository": receipt["consumerRepository"],
            "id": args.release_id,
            "tag": args.release_tag,
            "url": release_url,
            "sourceSha": args.source_sha,
            "workflowRunId": args.workflow_run_id,
            "workflowRunAttempt": args.workflow_run_attempt,
        },
        "variants": container_variants,
        "revocation": {"status": "not_revoked", "checkedAt": args.revocation_checked_at},
    }
    container = load_json(
        payloads["mlx90-container-evidence.json"], "container evidence"
    )
    if container != expected_container:
        fail("container evidence is not the exact receipt/release/run contract")
    parse_rfc3339(args.revocation_checked_at, "revocation checkedAt")
    identifiers = ", ".join(receipt["securityIdentifiers"])
    expected_markdown = (
        "<!-- mlx90-immutable-delivery:start -->\n"
        "## MLX-90 immutable delivery evidence\n\n"
        f"- Evidence ID: `{receipt['evidenceId']}`\n"
        f"- Security identifiers: `{identifiers}`\n"
        f"- Collection: `lit.supplementary {receipt['version']}`\n"
        f"- Collection digest: `{receipt['collectionDigest']}`\n"
        f"- Consumer merge SHA: `{args.source_sha}`\n"
        "- Container variants: `public`, `certified`, `bootstrap`\n"
        "- Required platforms: `linux/amd64`, `linux/arm64`\n"
        "- Signatures, SBOMs, provenance, manifests, platform digests, and installed versions are recorded in `release-evidence.json`.\n"
        "<!-- mlx90-immutable-delivery:end -->\n"
    )
    markdown = payloads["release-evidence.md"].decode("utf-8")
    if markdown.count("<!-- mlx90-immutable-delivery:start -->") != 1 or not markdown.endswith(expected_markdown):
        fail("release evidence Markdown is not the exact terminal MLX-90 record")


def validate_semantics(
    payloads: dict[str, bytes],
    *,
    args: argparse.Namespace,
    receipt_payload: bytes | None,
) -> None:
    json_values: dict[str, Any] = {}
    for name, payload in payloads.items():
        if name.endswith(".json"):
            json_values[name] = load_json(payload, name)
        elif name.endswith(".jsonl"):
            lines = payload.splitlines()
            if len(lines) != 1:
                fail(f"{name} must contain exactly one JSON statement")
            json_values[name] = load_json(lines[0], name)
        else:
            payload.decode("utf-8")
    if payloads["sbom.cdx.json"] != payloads["sbom-public.cdx.json"]:
        fail("canonical SBOM does not equal the public variant SBOM")
    variants = parse_variants(args.variant)
    profiles = {
        profile: validate_profile(
            profile,
            payloads,
            json_values,
            collection_version=args.collection_version,
            expected_image=variants[profile][0],
            expected_digest=variants[profile][1],
        )
        for profile in PROFILES
    }
    receipt = None
    producer_tree = None
    if args.security:
        if receipt_payload is None:
            fail("security release requires an immutable receipt")
        receipt = validate_receipt(
            receipt_payload,
            repository=args.repository,
            collection_version=args.collection_version,
        )
        producer_tree = validate_producer_materials(args, receipt)
    for profile in PROFILES:
        reauthenticate_profile(
            profile,
            payloads,
            json_values,
            repository=args.repository,
            release_tag=args.release_tag,
            source_sha=args.source_sha,
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
            release_version=args.release_tag.removeprefix("v"),
            collection_version=args.collection_version,
            image=variants[profile][0],
            digest=variants[profile][1],
            platform_digests=profiles[profile]["platforms"],
            trivy_image=args.trivy_image,
            producer_tree=producer_tree,
        )
    validate_provenance(
        json_values["release-provenance.intoto.jsonl"],
        payloads,
        repository=args.repository,
        release_tag=args.release_tag,
        source_sha=args.source_sha,
        workflow_run_id=args.workflow_run_id,
        variants=variants,
    )
    validate_generic(
        json_values["release-evidence.json"],
        payloads,
        args=args,
        receipt=receipt,
        profiles=profiles,
        variants=variants,
    )


def load_receipt_input(args: argparse.Namespace) -> bytes | None:
    if not args.security:
        return None
    if (
        (args.receipt is None) == (args.receipt_fd is None)
        or not DIGEST.fullmatch(args.receipt_digest or "")
    ):
        fail("security release receipt input is invalid")
    if args.receipt_fd is not None:
        return read_bounded_fd(
            args.receipt_fd,
            max_bytes=1024 * 1024,
            label="immutable security receipt",
            expected_digest=args.receipt_digest,
        )
    return read_regular_bytes(
        args.receipt,
        max_bytes=1024 * 1024,
        label="immutable security receipt",
        expected_digest=args.receipt_digest,
    )


def sign_assets(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    if not re.fullmatch(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", args.repository):
        fail("repository is invalid")
    if not TAG.fullmatch(args.release_tag) or not SHA.fullmatch(args.source_sha):
        fail("release tag or source SHA is invalid")
    if not VERSION.fullmatch(args.collection_version):
        fail("collection version is invalid")
    if args.trivy_image not in TRIVY_IMAGES:
        fail("Trivy verifier image is not an approved immutable release-gate image")
    for field in ("release_id", "workflow_run_id", "workflow_run_attempt"):
        if type(getattr(args, field)) is not int or getattr(args, field) <= 0:
            fail(f"{field.replace('_', '-')} must be a positive integer")
    parse_variants(args.variant)
    if args.security:
        if (
            not isinstance(args.consumer_head_sha, str)
            or not SHA.fullmatch(args.consumer_head_sha)
            or type(args.consumer_pull_request) is not int
            or args.consumer_pull_request <= 0
            or not isinstance(args.revocation_checked_at, str)
        ):
            fail("security release consumer/run inputs are invalid")
        parse_rfc3339(args.revocation_checked_at, "revocation checkedAt")
    names = list(BASE_ASSETS)
    if args.security:
        names.append("mlx90-container-evidence.json")
    receipt_payload = load_receipt_input(args)

    payloads: dict[str, bytes] = {}
    with secure_directory(args.source, create=False) as source_directory:
        with persistent_snapshot_directory(args.output, create=True) as destination:
            if os.listdir(destination.descriptor):
                fail("signed output directory must start empty")
            for name in names:
                snapshot = snapshot_regular_file(
                    args.source / name,
                    destination,
                    name,
                    max_bytes=release_asset_max_bytes(name),
                    label=f"release asset {name}",
                    capture_bytes=True,
                    source_directory=source_directory,
                )
                if snapshot.payload is None:
                    fail(f"release asset {name} was not captured")
                payloads[name] = snapshot.payload
            validate_semantics(
                payloads,
                args=args,
                receipt_payload=receipt_payload,
            )

            identity = (
                f"https://github.com/{args.repository}/.github/workflows/"
                f"container-build-publish.yml@refs/tags/{args.release_tag}"
            )
            if args.security:
                bundle_name = "mlx90-container-evidence.json.sigstore.json"
                bundle_payload = sign_blob(
                    payloads["mlx90-container-evidence.json"],
                    identity=identity,
                    source_sha=args.source_sha,
                )
                write_exclusive(destination, bundle_name, bundle_payload)
                payloads[bundle_name] = bundle_payload

            manifest_payload = "".join(
                f"{hashlib.sha256(payloads[name]).hexdigest()}  {name}\n"
                for name in sorted(payloads)
            ).encode("utf-8")
            write_exclusive(destination, "SHA256SUMS", manifest_payload)
            bundle_payload = sign_blob(
                manifest_payload,
                identity=identity,
                source_sha=args.source_sha,
            )
            write_exclusive(
                destination, "SHA256SUMS.sigstore.json", bundle_payload
            )
            payloads["SHA256SUMS"] = manifest_payload
            payloads["SHA256SUMS.sigstore.json"] = bundle_payload

    return {
        name: {"digest": sha256(payload), "size": len(payload)}
        for name, payload in sorted(payloads.items())
    }


def validate_checksum_manifest(payloads: dict[str, bytes]) -> None:
    try:
        lines = payloads["SHA256SUMS"].decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise ValueError("release checksum manifest is not UTF-8") from exc
    expected_names = set(payloads) - {"SHA256SUMS", "SHA256SUMS.sigstore.json"}
    if len(lines) != len(expected_names):
        fail("release checksum manifest entry count is invalid")
    actual: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})", line
        )
        if match is None or match.group(2) in actual:
            fail("release checksum manifest contains an invalid or duplicate entry")
        actual[match.group(2)] = match.group(1)
    if set(actual) != expected_names:
        fail("release checksum manifest asset set is not exact")
    for name, digest in actual.items():
        if hashlib.sha256(payloads[name]).hexdigest() != digest:
            fail(f"release checksum mismatch for {name}")


def derive_verify_inputs(args: argparse.Namespace, payloads: dict[str, bytes]) -> dict[str, Any]:
    if not args.security:
        return {}
    container = require_object(
        load_json(payloads["mlx90-container-evidence.json"], "container evidence"),
        "container evidence",
    )
    variants = require_exact_object(
        container.get("variants"), set(PROFILES), "container evidence variants"
    )
    derived_variants: list[str] = []
    for profile in PROFILES:
        record = require_object(variants[profile], f"container {profile} variant")
        image, digest = record.get("image"), record.get("manifestDigest")
        if not isinstance(image, str) or not isinstance(digest, str):
            fail(f"container {profile} variant identity is invalid")
        derived_variants.append(f"{profile}={image}@{digest}")
    if args.variant:
        if parse_variants(args.variant) != parse_variants(derived_variants):
            fail("caller variant set differs from signed container evidence")
    else:
        args.variant = derived_variants
    revocation = require_object(container.get("revocation"), "container revocation")
    checked_at = revocation.get("checkedAt")
    if args.revocation_checked_at is not None and args.revocation_checked_at != checked_at:
        fail("caller revocation timestamp differs from signed container evidence")
    args.revocation_checked_at = checked_at
    signed_attempt = require_object(container.get("release"), "container release").get(
        "workflowRunAttempt"
    )
    if args.max_workflow_run_attempt is not None:
        if (
            type(signed_attempt) is not int
            or signed_attempt <= 0
            or type(args.max_workflow_run_attempt) is not int
            or args.max_workflow_run_attempt <= 0
            or signed_attempt > args.max_workflow_run_attempt
        ):
            fail("signed workflow attempt exceeds the authorized publish attempt")
        args.workflow_run_attempt = signed_attempt
    return container


def run_acceptance_script(
    args: argparse.Namespace,
    payloads: dict[str, bytes],
    container: dict[str, Any],
) -> None:
    if (
        args.acceptance_script_fd is None
        or not DIGEST.fullmatch(args.acceptance_script_digest or "")
    ):
        fail("exact acceptance script input is invalid")
    script_payload = read_bounded_fd(
        args.acceptance_script_fd,
        max_bytes=1024 * 1024,
        label="live immutable acceptance policy",
        expected_digest=args.acceptance_script_digest,
    )
    sources = {
        "script": script_payload,
        "signature": payloads["signature-public.json"],
        "sbom": payloads["sbom-public.cdx.json"],
        "provenance": payloads["release-provenance.intoto.jsonl"],
    }
    files: dict[str, int] = {}
    try:
        for name, payload in sources.items():
            files[name] = sealed_payload_fd(payload, f"acceptance-{name}")
        descriptors = tuple(files.values())
        public = container["variants"]["public"]
        environment = os.environ.copy()
        environment.update(
            {
                "IMAGE_REF": f"{public['image']}@{public['manifestDigest']}",
                "EXPECTED_COLLECTION": "lit.supplementary",
                "EXPECTED_VERSION": args.collection_version,
                "COSIGN_IDENTITY_REGEXP": "^"
                + re.escape(
                    f"https://github.com/{args.repository}/.github/workflows/"
                    f"container-build-publish.yml@refs/tags/{args.release_tag}"
                )
                + "$",
                "COSIGN_ISSUER": "https://token.actions.githubusercontent.com",
                "COSIGN_WORKFLOW_SHA": args.source_sha,
                "SIGNATURE_RECEIPT": f"/dev/fd/{files['signature']}",
                "SBOM_FILE": f"/dev/fd/{files['sbom']}",
                "PROVENANCE_FILE": f"/dev/fd/{files['provenance']}",
                "RELEASE_ASSET_DIRECTORY": os.fspath(args.output),
                "EXPECTED_REPOSITORY": args.repository,
                "EXPECTED_RELEASE_TAG": args.release_tag,
                "EXPECTED_SOURCE_SHA": args.source_sha,
            }
        )
        completed = subprocess.run(
            ["bash", f"/dev/fd/{files['script']}"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=900,
            pass_fds=descriptors,
            env=environment,
        )
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            fail(f"immutable container acceptance failed: {detail or 'no diagnostic'}")
        if b"MLX-90 immutable acceptance passed" not in completed.stdout:
            fail("immutable container acceptance returned no success record")
    finally:
        for descriptor in files.values():
            os.close(descriptor)


def verify_signed_assets(args: argparse.Namespace) -> dict[str, Any]:
    if (
        not re.fullmatch(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", args.repository)
        or not TAG.fullmatch(args.release_tag)
        or not SHA.fullmatch(args.source_sha)
        or not VERSION.fullmatch(args.collection_version)
        or args.trivy_image not in TRIVY_IMAGES
    ):
        fail("signed release verification identity is invalid")
    for field in ("release_id", "workflow_run_id", "workflow_run_attempt"):
        if type(getattr(args, field)) is not int or getattr(args, field) <= 0:
            fail(f"{field.replace('_', '-')} must be a positive integer")
    if args.security and (
        not isinstance(args.consumer_head_sha, str)
        or not SHA.fullmatch(args.consumer_head_sha)
        or type(args.consumer_pull_request) is not int
        or args.consumer_pull_request <= 0
    ):
        fail("security release consumer identity is invalid")
    names = [*BASE_ASSETS, "SHA256SUMS", "SHA256SUMS.sigstore.json"]
    if args.security:
        names.extend(
            [
                "mlx90-container-evidence.json",
                "mlx90-container-evidence.json.sigstore.json",
            ]
        )
    receipt_payload = load_receipt_input(args)
    payloads: dict[str, bytes] = {}
    with secure_directory(args.source, create=False) as source_directory:
        with persistent_snapshot_directory(args.output, create=True) as destination:
            if os.listdir(destination.descriptor):
                fail("verified output directory must start empty")
            for name in names:
                snapshot = snapshot_regular_file(
                    args.source / name,
                    destination,
                    name,
                    max_bytes=release_asset_max_bytes(name),
                    label=f"signed release asset {name}",
                    capture_bytes=True,
                    source_directory=source_directory,
                )
                if snapshot.payload is None:
                    fail(f"signed release asset {name} was not captured")
                payloads[name] = snapshot.payload

            identity = (
                f"https://github.com/{args.repository}/.github/workflows/"
                f"container-build-publish.yml@refs/tags/{args.release_tag}"
            )
            verify_blob(
                payloads["SHA256SUMS"],
                payloads["SHA256SUMS.sigstore.json"],
                identity=identity,
                source_sha=args.source_sha,
            )
            validate_checksum_manifest(payloads)
            if args.security:
                verify_blob(
                    payloads["mlx90-container-evidence.json"],
                    payloads["mlx90-container-evidence.json.sigstore.json"],
                    identity=identity,
                    source_sha=args.source_sha,
                )
            container = derive_verify_inputs(args, payloads)
            validate_semantics(payloads, args=args, receipt_payload=receipt_payload)
            if args.acceptance_script_fd is not None:
                if not args.security:
                    fail("ordinary release cannot run MLX-90 immutable acceptance")
                run_acceptance_script(args, payloads, container)

    assets = {
        name: {"digest": sha256(payload), "size": len(payload)}
        for name, payload in sorted(payloads.items())
    }
    claims: dict[str, Any] = {}
    if args.security:
        public = container["variants"]["public"]
        claims = {
            "evidenceId": container["securityEvidenceId"],
            "producerEvidenceDigest": container["producer"]["evidence"]["digest"],
            "producerEvidenceUrl": container["producer"]["evidence"]["url"],
            "producerSourceSha": container["producer"]["sourceSha"],
            "producerVersion": container["producer"]["version"],
            "publicImageRef": f"{public['image']}@{public['manifestDigest']}",
            "releaseRunAttempt": container["release"]["workflowRunAttempt"],
            "releaseRunId": container["release"]["workflowRunId"],
            "revocationCheckedAt": container["revocation"]["checkedAt"],
        }
    return {"assets": assets, "claims": claims}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--collection-version", required=True)
    parser.add_argument("--release-id", type=int, required=True)
    parser.add_argument("--workflow-run-id", type=int, required=True)
    parser.add_argument("--workflow-run-attempt", type=int, required=True)
    parser.add_argument("--max-workflow-run-attempt", type=int)
    parser.add_argument("--variant", action="append", default=[])
    parser.add_argument("--trivy-image", required=True)
    parser.add_argument("--security", action="store_true")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--receipt-fd", type=int)
    parser.add_argument("--receipt-digest")
    parser.add_argument("--consumer-head-sha")
    parser.add_argument("--consumer-pull-request", type=int)
    parser.add_argument("--revocation-checked-at")
    parser.add_argument("--producer-artifact", type=Path)
    parser.add_argument("--producer-artifact-digest")
    parser.add_argument("--producer-signature", type=Path)
    parser.add_argument("--producer-sbom", type=Path)
    parser.add_argument("--producer-provenance", type=Path)
    parser.add_argument("--verify-signed", action="store_true")
    parser.add_argument("--acceptance-script-fd", type=int)
    parser.add_argument("--acceptance-script-digest")
    args = parser.parse_args()
    try:
        result = verify_signed_assets(args) if args.verify_signed else sign_assets(args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"MLX-90 release signing rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
