#!/usr/bin/env python3
"""Fail-closed MLX-90 collection update and receipt validation.

The workflow-dispatch payload is intentionally limited to an evidence URL and
its SHA-256. Trust in the evidence bytes comes from the producer-signed release
checksum manifest; version and collection digest are derived only after that
cryptographic binding has been verified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from mlx90_secure_files import (
    FileSnapshot,
    HeldDirectory,
    held_directory,
    open_exclusive_regular,
    private_snapshot_directory,
    read_regular_bytes,
    replace_regular_from_snapshot,
    secure_directory,
    snapshot_regular_file,
    unlink_relative,
    write_exclusive_regular,
)

CONSUMER = "lightning-it/container-ee-wunder-ansible-ubi9"
PRODUCER = "lightning-it/ansible-collection-supplementary"
WORKFLOW_REPOSITORY = PRODUCER
PRODUCER_WORKFLOW = ".github/workflows/collection-ci.yml"
PRODUCER_IDENTITY = (
    f"https://github.com/{PRODUCER}/{PRODUCER_WORKFLOW}@refs/heads/main"
)
PRODUCER_PUBLISH_WORKFLOW = ".github/workflows/collection-publish.yml"
PRODUCER_PUBLISH_IDENTITY = (
    f"https://github.com/{PRODUCER}/{PRODUCER_PUBLISH_WORKFLOW}@refs/heads/main"
)
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
COLLECTION = "lit.supplementary"
EVIDENCE_ASSET = "security-release-evidence.json"
CHECKSUMS_ASSET = "SHA256SUMS"
CHECKSUMS_BUNDLE_ASSET = "SHA256SUMS.sigstore.json"
# Production profiles are allowlisted by exact identifier and exact release
# tuple. Prefixes, patterns, fixture identifiers, and reuse for another release
# are deliberately not accepted.
APPROVED_ACCEPTANCE_RELEASES: dict[
    str, tuple[str, str, frozenset[str]]
] = {
    "lit.supplementary/forgejo-manifest-secret-permissions-v1": (
        "3.1.0",
        "3.2.2",
        frozenset({"GHSA-vjjf-wc74-gp86"}),
    )
}
APPROVED_ACCEPTANCE_PROFILES: frozenset[str] = frozenset(
    APPROVED_ACCEPTANCE_RELEASES
)
NON_RELEASEABLE_FIXTURE_PROFILES = frozenset({"lit.supplementary/mlx90-fixture"})
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
SECURITY_ID = re.compile(
    r"^(?:CVE-[0-9]{4}-[0-9]{4,}|"
    r"GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}|"
    r"LIT-SEC-[A-Z0-9._-]+)$"
)
EVIDENCE_ID = re.compile(r"\A[A-Z0-9][A-Z0-9._-]{2,127}\Z")
RFC3339_TIMESTAMP = re.compile(
    r"\A(?P<date_time>[0-9]{4}-(?:0[1-9]|1[0-2])-"
    r"(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):"
    r"[0-5][0-9]:[0-5][0-9])(?:\.(?P<fraction>[0-9]{1,6}))?"
    r"(?P<offset>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z"
)
ASSET_URL = re.compile(
    r"^https://github\.com/lightning-it/ansible-collection-supplementary/"
    r"releases/download/[^/?#]+/[^/?#]+$"
)
CHECKSUM_LINE = re.compile(
    r"^([0-9a-f]{64}) ([ *])([A-Za-z0-9][A-Za-z0-9._-]{0,127})$"
)
RELEASE_URL = re.compile(
    r"^https://github\.com/lightning-it/ansible-collection-supplementary/"
    r"releases/tag/[^/?#]+$"
)
RECEIPT_KEYS = {
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
EVIDENCE_MAX_BYTES = 4 * 1024 * 1024
CHECKSUMS_MAX_BYTES = 64 * 1024
BUNDLE_MAX_BYTES = 4 * 1024 * 1024
COLLECTION_MAX_BYTES = 256 * 1024 * 1024
ASSURANCE_MAX_BYTES = 16 * 1024 * 1024
INSTALLED_EXPORT_MAX_BYTES = 512 * 1024 * 1024
RECEIPT_MAX_BYTES = 1024 * 1024
REQUIREMENTS_MAX_BYTES = 1024 * 1024


def fail(message: str) -> None:
    raise ValueError(message)


def require_dict(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{name} must be an object")
    return value


def require_exact(mapping: dict[str, Any], keys: set[str], name: str) -> None:
    missing = keys - mapping.keys()
    unknown = mapping.keys() - keys
    if missing:
        fail(f"{name} missing fields: {', '.join(sorted(missing))}")
    if unknown:
        fail(f"{name} has unknown fields: {', '.join(sorted(unknown))}")


def load_strict_json(payload: bytes, name: str) -> object:
    """Parse one UTF-8 JSON document without ambiguous object or number values."""

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{name} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> None:
        fail(f"{name} contains invalid JSON constant {value}")

    def parse_finite_float(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            fail(f"{name} contains a non-finite JSON number")
        return result

    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"{name} must be UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
            parse_float=parse_finite_float,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} is not valid JSON") from exc
    except RecursionError as exc:
        raise ValueError(f"{name} exceeds the JSON nesting limit") from exc


def parse_time(value: object, name: str) -> datetime:
    match = RFC3339_TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        fail(f"{name} must be an RFC3339 timestamp")
    try:
        fraction = match.group("fraction")
        offset = match.group("offset")
        normalized = match.group("date_time")
        if fraction is not None:
            normalized += f".{fraction.ljust(6, '0')}"
        normalized += "+00:00" if offset == "Z" else offset
        result = datetime.fromisoformat(normalized)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{name} must be an RFC3339 timestamp") from exc
    return result.astimezone(timezone.utc)


def validate_ref(value: object, name: str) -> dict[str, str]:
    ref = require_dict(value, name)
    require_exact(ref, {"url", "digest"}, name)
    if not isinstance(ref["url"], str) or not ASSET_URL.fullmatch(ref["url"]):
        fail(f"{name}.url must be an immutable producer release asset URL")
    if not isinstance(ref["digest"], str) or not DIGEST.fullmatch(ref["digest"]):
        fail(f"{name}.digest must be sha256")
    return {"url": ref["url"], "digest": ref["digest"]}


def validate_versioned_asset_url(value: str, version: str, name: str) -> None:
    prefix = f"https://github.com/{PRODUCER}/releases/download/v{version}/"
    if not value.startswith(prefix):
        fail(f"{name} must belong to producer release v{version}")


def load_evidence_bytes(payload: bytes, now: datetime | None = None) -> dict[str, Any]:
    data = load_strict_json(payload, "evidence")
    evidence = require_dict(data, "evidence")
    require_exact(
        evidence,
        {
            "apiVersion",
            "kind",
            "metadata",
            "security",
            "producer",
            "artifact",
            "consumers",
            "acceptance",
            "validity",
            "status",
        },
        "evidence",
    )
    if evidence["apiVersion"] != "lit.security-release/v1":
        fail("unsupported evidence apiVersion")
    if evidence["kind"] != "SecurityReleaseEvidence":
        fail("unsupported evidence kind")
    if evidence["status"] != "approved":
        fail("consumer updates require approved evidence")

    metadata = require_dict(evidence["metadata"], "metadata")
    security = require_dict(evidence["security"], "security")
    producer = require_dict(evidence["producer"], "producer")
    artifact = require_dict(evidence["artifact"], "artifact")
    acceptance = require_dict(evidence["acceptance"], "acceptance")
    validity = require_dict(evidence["validity"], "validity")
    require_exact(metadata, {"id", "createdAt"}, "metadata")
    require_exact(
        security,
        {"identifiers", "affectedVersion", "fixedVersion"},
        "security",
    )
    require_exact(
        producer,
        {"repository", "sourceSha", "workflowRepository", "workflowRef"},
        "producer",
    )
    require_exact(
        artifact,
        {
            "collection",
            "version",
            "digest",
            "releaseUrl",
            "signature",
            "sbom",
            "provenance",
        },
        "artifact",
    )
    require_exact(
        acceptance,
        {"profile", "expectedCollection", "expectedVersion"},
        "acceptance",
    )
    require_exact(validity, {"notBefore", "expiresAt", "revoked"}, "validity")

    if not isinstance(metadata["id"], str) or not EVIDENCE_ID.fullmatch(metadata["id"]):
        fail("metadata.id is invalid")
    created_at = parse_time(metadata["createdAt"], "metadata.createdAt")
    identifiers = security["identifiers"]
    if (
        not isinstance(identifiers, list)
        or not identifiers
        or len(identifiers) != len(set(identifiers))
        or not all(
            isinstance(item, str) and SECURITY_ID.fullmatch(item)
            for item in identifiers
        )
    ):
        fail("security.identifiers are invalid or duplicated")
    if producer["repository"] != PRODUCER:
        fail("unexpected producer repository")
    if producer["workflowRepository"] != WORKFLOW_REPOSITORY:
        fail("unexpected producer workflow repository")
    if not isinstance(producer["sourceSha"], str) or not SHA.fullmatch(
        producer["sourceSha"]
    ):
        fail("producer.sourceSha must be a full SHA")
    if not isinstance(producer["workflowRef"], str) or not SHA.fullmatch(
        producer["workflowRef"]
    ):
        fail("producer.workflowRef must be a full SHA")
    if producer["workflowRef"] != producer["sourceSha"]:
        fail("producer.workflowRef must match producer.sourceSha")
    if artifact["collection"] != COLLECTION:
        fail("unexpected collection")
    if not isinstance(artifact["version"], str) or not VERSION.fullmatch(
        artifact["version"]
    ):
        fail("artifact.version is invalid")
    if security["fixedVersion"] != artifact["version"]:
        fail("security.fixedVersion does not match artifact.version")
    if not isinstance(security["affectedVersion"], str) or not VERSION.fullmatch(
        security["affectedVersion"]
    ):
        fail("security.affectedVersion must be an exact version")
    if security["affectedVersion"] == security["fixedVersion"]:
        fail("security fixedVersion must differ from affectedVersion")
    if not isinstance(artifact["digest"], str) or not DIGEST.fullmatch(
        artifact["digest"]
    ):
        fail("artifact.digest must be sha256")
    if not isinstance(artifact["releaseUrl"], str) or not RELEASE_URL.fullmatch(
        artifact["releaseUrl"]
    ):
        fail("artifact.releaseUrl must be the producer release page")
    expected_release_url = (
        f"https://github.com/{PRODUCER}/releases/tag/v{artifact['version']}"
    )
    if artifact["releaseUrl"] != expected_release_url:
        fail("artifact.releaseUrl does not match artifact.version")
    for field in ("signature", "sbom", "provenance"):
        ref = validate_ref(artifact[field], f"artifact.{field}")
        validate_versioned_asset_url(
            ref["url"], artifact["version"], f"artifact.{field}.url"
        )
    if evidence["consumers"] != [CONSUMER]:
        fail("consumer allowlist must contain exactly this repository")
    if acceptance["expectedCollection"] != COLLECTION:
        fail("acceptance.expectedCollection does not match")
    if acceptance["expectedVersion"] != artifact["version"]:
        fail("acceptance.expectedVersion does not match")
    profile = acceptance["profile"]
    if not isinstance(profile, str):
        fail("acceptance.profile must be a string")
    if profile in NON_RELEASEABLE_FIXTURE_PROFILES:
        fail("acceptance.profile is a non-releaseable fixture")
    if profile not in APPROVED_ACCEPTANCE_PROFILES:
        fail("acceptance.profile has no release-eligible approval")
    approved_release = APPROVED_ACCEPTANCE_RELEASES.get(profile)
    if approved_release is None:
        fail("acceptance.profile has no release-tuple approval")
    approved_affected, approved_fixed, approved_identifiers = approved_release
    if (
        security["affectedVersion"] != approved_affected
        or security["fixedVersion"] != approved_fixed
        or frozenset(identifiers) != approved_identifiers
    ):
        fail("acceptance.profile is not approved for this security release")
    if validity["revoked"] is not False:
        fail("evidence is revoked")
    not_before = parse_time(validity["notBefore"], "validity.notBefore")
    expires_at = parse_time(validity["expiresAt"], "validity.expiresAt")
    if created_at < not_before or created_at >= expires_at:
        fail("metadata.createdAt is outside the evidence validity window")
    checked_at = now or datetime.now(timezone.utc)
    if expires_at <= not_before or checked_at < not_before or checked_at >= expires_at:
        fail("evidence is outside its validity window")
    return evidence


def load_evidence(path: Path, now: datetime | None = None) -> dict[str, Any]:
    payload = read_regular_bytes(
        path,
        max_bytes=EVIDENCE_MAX_BYTES,
        label="producer evidence",
    )
    return load_evidence_bytes(payload, now=now)


def file_digest(path: Path) -> str:
    payload = read_regular_bytes(
        path,
        max_bytes=EVIDENCE_MAX_BYTES,
        label="digest input",
    )
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def verify_evidence_signature(
    evidence_path: Path,
    checksums_path: Path,
    checksums_bundle_path: Path,
    producer_workflow_sha: str,
) -> tuple[str, bytes]:
    """Authenticate exact evidence bytes before parsing their policy fields."""

    if evidence_path.name != EVIDENCE_ASSET:
        fail(f"evidence path must name {EVIDENCE_ASSET}")
    if checksums_path.name != CHECKSUMS_ASSET:
        fail(f"cryptographic verification requires {CHECKSUMS_ASSET}")
    if checksums_bundle_path.name != CHECKSUMS_BUNDLE_ASSET:
        fail(f"cryptographic verification requires {CHECKSUMS_BUNDLE_ASSET}")
    if not isinstance(producer_workflow_sha, str) or not SHA.fullmatch(
        producer_workflow_sha
    ):
        fail("producer publish workflow SHA is invalid")
    with private_snapshot_directory("mlx90-producer-signature-") as snapshot_root:
        evidence_snapshot = snapshot_regular_file(
            evidence_path,
            snapshot_root,
            EVIDENCE_ASSET,
            max_bytes=EVIDENCE_MAX_BYTES,
            label="producer evidence",
            capture_bytes=True,
        )
        checksums_snapshot = snapshot_regular_file(
            checksums_path,
            snapshot_root,
            CHECKSUMS_ASSET,
            max_bytes=CHECKSUMS_MAX_BYTES,
            label="producer checksum manifest",
            capture_bytes=True,
        )
        bundle_snapshot = snapshot_regular_file(
            checksums_bundle_path,
            snapshot_root,
            CHECKSUMS_BUNDLE_ASSET,
            max_bytes=BUNDLE_MAX_BYTES,
            label="producer checksum Sigstore bundle",
        )
        try:
            completed = subprocess.run(
                [
                    "cosign",
                    "verify-blob",
                    "--bundle",
                    str(bundle_snapshot.path),
                    "--certificate-oidc-issuer",
                    OIDC_ISSUER,
                    "--certificate-identity",
                    PRODUCER_PUBLISH_IDENTITY,
                    "--certificate-github-workflow-sha",
                    producer_workflow_sha,
                    str(checksums_snapshot.path),
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError(
                "cannot execute producer evidence signature verification"
            ) from exc
        assert evidence_snapshot.payload is not None
        assert checksums_snapshot.payload is not None
        evidence_bytes = evidence_snapshot.payload
        checksums_bytes = checksums_snapshot.payload
    if completed.returncode != 0:
        fail("producer evidence signature verification failed")

    try:
        lines = checksums_bytes.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise ValueError("signed producer checksum manifest must be UTF-8") from exc
    entries: dict[str, str] = {}
    for line in lines:
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            fail("signed producer checksum manifest has a malformed entry")
        checksum, _, filename = match.groups()
        if filename in entries:
            fail("signed producer checksum manifest has a duplicate asset")
        entries[filename] = checksum
    authenticated_digest = f"sha256:{hashlib.sha256(evidence_bytes).hexdigest()}"
    if entries.get(EVIDENCE_ASSET) != authenticated_digest.removeprefix("sha256:"):
        fail("signed producer checksum manifest does not bind evidence")
    return authenticated_digest, evidence_bytes


def load_authenticated_evidence(
    evidence_path: Path,
    evidence_url: str,
    checksums_path: Path,
    checksums_bundle_path: Path,
    producer_workflow_sha: str,
    now: datetime | None = None,
) -> tuple[dict[str, Any], str]:
    if not ASSET_URL.fullmatch(evidence_url) or not evidence_url.endswith(
        f"/{EVIDENCE_ASSET}"
    ):
        fail("evidence URL must be the producer Security release asset")
    authenticated_digest, evidence_bytes = verify_evidence_signature(
        evidence_path,
        checksums_path,
        checksums_bundle_path,
        producer_workflow_sha,
    )
    evidence = load_evidence_bytes(evidence_bytes, now=now)
    if evidence["producer"]["workflowRef"] != producer_workflow_sha:
        fail("signed evidence producer SHA does not match publish workflow SHA")
    validate_versioned_asset_url(
        evidence_url, evidence["artifact"]["version"], "evidence URL"
    )
    return evidence, authenticated_digest


def _parse_requirement_text(text: str) -> tuple[list[str], int, str]:
    """Parse the canonical collection requirements subset without YAML ambiguity."""

    if not isinstance(text, str) or not text or "\x00" in text or "\r" in text:
        fail("collection requirements are empty or not canonical UTF-8 text")
    lines = text.splitlines(keepends=True)
    rendered = [line.removesuffix("\n") for line in lines]
    if len(rendered) < 4 or rendered[0] != "---" or rendered[1] != "collections:":
        fail("collection requirements must use the canonical block schema")

    name_pattern = re.compile(
        r"^  - name: ([a-z0-9_]+(?:\.[a-z0-9_]+)+)$"
    )
    version_pattern = re.compile(r'^    version: "([^"]+)"$')
    names: set[str] = set()
    target_index = -1
    target_version = ""
    cursor = 2
    while cursor < len(rendered):
        line = rendered[cursor]
        if not line or re.fullmatch(r"\s*#.*", line):
            cursor += 1
            continue
        name_match = name_pattern.fullmatch(line)
        if name_match is None:
            fail("collection requirements contain a non-canonical entry")
        name = name_match.group(1)
        if name in names:
            fail(f"collection requirements duplicate {name}")
        names.add(name)
        cursor += 1
        while cursor < len(rendered) and (
            not rendered[cursor]
            or re.fullmatch(r"\s*#.*", rendered[cursor]) is not None
        ):
            cursor += 1
        if cursor >= len(rendered):
            fail(f"collection requirements entry {name} has no version")
        version_match = version_pattern.fullmatch(rendered[cursor])
        if version_match is None or not VERSION.fullmatch(version_match.group(1)):
            fail(f"collection requirements entry {name} has an invalid version")
        if name == COLLECTION:
            target_index = cursor
            target_version = version_match.group(1)
        cursor += 1

    if target_index < 0:
        fail("requirements do not contain lit.supplementary")
    return lines, target_index, target_version


def requirement_version_text(text: str) -> str:
    return _parse_requirement_text(text)[2]


def render_requirement_update(payload: bytes, version: str) -> bytes:
    if not isinstance(payload, bytes) or not payload:
        fail("collection requirements payload is empty or invalid")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        fail("target collection version is invalid")
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("collection requirements must be UTF-8") from exc
    lines, row, _ = _parse_requirement_text(text)
    newline = "\n" if lines[row].endswith("\n") else ""
    lines[row] = f'    version: "{version}"{newline}'
    rendered = "".join(lines).encode("utf-8")
    if requirement_version_text(rendered.decode("utf-8")) != version:
        fail("rendered collection requirements do not bind the target version")
    return rendered


def requirement_version(path: Path) -> str:
    payload = read_regular_bytes(
        path,
        max_bytes=REQUIREMENTS_MAX_BYTES,
        label="collection requirements",
    )
    try:
        return requirement_version_text(payload.decode("utf-8"))
    except UnicodeError as exc:
        raise ValueError("collection requirements must be UTF-8") from exc


def receipt_for(
    evidence: dict[str, Any], evidence_url: str, evidence_digest: str, base_sha: str
) -> dict[str, Any]:
    producer, artifact = evidence["producer"], evidence["artifact"]
    return {
        "schemaVersion": 1,
        "evidenceId": evidence["metadata"]["id"],
        "evidenceUrl": evidence_url,
        "evidenceDigest": evidence_digest,
        "securityIdentifiers": evidence["security"]["identifiers"],
        "producerRepository": producer["repository"],
        "producerSourceSha": producer["sourceSha"],
        "producerWorkflowRepository": producer["workflowRepository"],
        "producerWorkflowSha": producer["workflowRef"],
        "collection": artifact["collection"],
        "version": artifact["version"],
        "collectionDigest": artifact["digest"],
        "signature": artifact["signature"],
        "sbom": artifact["sbom"],
        "provenance": artifact["provenance"],
        "consumerRepository": CONSUMER,
        "baseSha": base_sha,
    }


def prepare_security_update(
    evidence_path: Path,
    evidence_url: str,
    evidence_digest: str,
    checksums_path: Path,
    checksums_bundle_path: Path,
    producer_workflow_sha: str,
    base_sha: str,
    requirements_path: Path,
    requirements_digest: str,
    receipt_path: Path,
) -> dict[str, Any]:
    """Render one digest-bound update through held directory descriptors."""

    if not isinstance(evidence_digest, str) or not DIGEST.fullmatch(evidence_digest):
        fail("dispatch evidence digest must be sha256")
    if not isinstance(base_sha, str) or not SHA.fullmatch(base_sha):
        fail("base SHA must be a full SHA")
    if not isinstance(requirements_digest, str) or not DIGEST.fullmatch(
        requirements_digest
    ):
        fail("base requirements digest must be sha256")
    if not isinstance(requirements_path, Path) or not isinstance(receipt_path, Path):
        fail("requirements and receipt must be filesystem paths")
    if requirements_path.name in {"", ".", ".."} or receipt_path.name in {
        "",
        ".",
        "..",
    }:
        fail("requirements or receipt path is unsafe")

    with (
        held_directory(requirements_path.parent) as requirements_directory,
        held_directory(receipt_path.parent) as receipt_directory,
        private_snapshot_directory("mlx90-prepare-input-") as snapshot_root,
    ):
        requirements_snapshot = snapshot_regular_file(
            requirements_path,
            snapshot_root,
            "base-requirements.yml",
            max_bytes=REQUIREMENTS_MAX_BYTES,
            label="exact-base collection requirements",
            expected_digest=requirements_digest,
            capture_bytes=True,
            source_directory=requirements_directory,
        )
        assert requirements_snapshot.payload is not None
        try:
            current_version = requirement_version_text(
                requirements_snapshot.payload.decode("utf-8")
            )
        except UnicodeError as exc:
            raise ValueError("collection requirements must be UTF-8") from exc
        evidence, authenticated_digest = load_authenticated_evidence(
            evidence_path,
            evidence_url,
            checksums_path,
            checksums_bundle_path,
            producer_workflow_sha,
        )
        if authenticated_digest != evidence_digest:
            fail("signed evidence does not match dispatch digest")
        if current_version != evidence["security"]["affectedVersion"]:
            fail("main requirements version does not match affectedVersion")
        rendered_requirements = render_requirement_update(
            requirements_snapshot.payload,
            evidence["artifact"]["version"],
        )
        receipt = receipt_for(evidence, evidence_url, evidence_digest, base_sha)
        receipt_payload = (
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

        write_exclusive_regular(
            receipt_directory,
            receipt_path.name,
            receipt_payload,
            mode=0o644,
            label="security release receipt",
        )
        try:
            replace_regular_from_snapshot(
                requirements_directory,
                requirements_path.name,
                rendered_requirements,
                requirements_snapshot,
                label="collection requirements",
            )
        except Exception:
            unlink_relative(receipt_directory, receipt_path.name)
            raise
    return receipt


def validate_receipt(
    receipt_path: Path,
    evidence_path: Path,
    requirements_path: Path,
    base_sha: str,
    evidence_url: str,
    checksums_path: Path,
    checksums_bundle_path: Path,
    producer_workflow_sha: str,
    *,
    receipt_digest: str,
    requirements_digest: str,
    base_requirements_path: Path,
    base_requirements_digest: str,
) -> dict[str, Any]:
    if not SHA.fullmatch(base_sha):
        fail("base SHA must be a full SHA")
    with private_snapshot_directory("mlx90-receipt-inputs-") as snapshot_root:
        receipt_snapshot = snapshot_regular_file(
            receipt_path,
            snapshot_root,
            "security-release-receipt.json",
            max_bytes=RECEIPT_MAX_BYTES,
            label="security release receipt",
            expected_digest=receipt_digest,
            capture_bytes=True,
        )
        requirements_snapshot = snapshot_regular_file(
            requirements_path,
            snapshot_root,
            "requirements.yml",
            max_bytes=REQUIREMENTS_MAX_BYTES,
            label="current collection requirements",
            expected_digest=requirements_digest,
            capture_bytes=True,
        )
        base_requirements_snapshot = snapshot_regular_file(
            base_requirements_path,
            snapshot_root,
            "base-requirements.yml",
            max_bytes=REQUIREMENTS_MAX_BYTES,
            label="base collection requirements",
            expected_digest=base_requirements_digest,
            capture_bytes=True,
        )
        assert receipt_snapshot.payload is not None
        assert requirements_snapshot.payload is not None
        assert base_requirements_snapshot.payload is not None
        try:
            receipt = require_dict(
                load_strict_json(receipt_snapshot.payload, "receipt"), "receipt"
            )
            current_version = requirement_version_text(
                requirements_snapshot.payload.decode("utf-8")
            )
            base_version = requirement_version_text(
                base_requirements_snapshot.payload.decode("utf-8")
            )
        except UnicodeError as exc:
            raise ValueError(f"receipt validation input is not UTF-8: {exc}") from exc
    require_exact(receipt, RECEIPT_KEYS, "receipt")
    if type(receipt["schemaVersion"]) is not int or receipt["schemaVersion"] != 1:
        fail("unsupported receipt schemaVersion")
    if not isinstance(receipt["evidenceDigest"], str) or not DIGEST.fullmatch(
        receipt["evidenceDigest"]
    ):
        fail("receipt evidence digest is invalid")
    evidence, authenticated_digest = load_authenticated_evidence(
        evidence_path,
        evidence_url,
        checksums_path,
        checksums_bundle_path,
        producer_workflow_sha,
    )
    if authenticated_digest != receipt["evidenceDigest"]:
        fail("evidence file does not match receipt digest")
    if receipt["evidenceUrl"] != evidence_url:
        fail("receipt evidence URL does not match dispatch")
    validate_versioned_asset_url(
        receipt["evidenceUrl"], evidence["artifact"]["version"], "receipt evidence URL"
    )
    expected = receipt_for(
        evidence, receipt["evidenceUrl"], receipt["evidenceDigest"], base_sha
    )
    if receipt != expected:
        fail("receipt does not exactly match evidence and base SHA")
    if current_version != evidence["artifact"]["version"]:
        fail("requirements version does not match evidence")
    if base_version != evidence["security"]["affectedVersion"]:
        fail("base requirements version does not match affectedVersion")
    return evidence


def download_checked(
    url: str,
    expected_digest: str,
    destination: Path,
    *,
    held_directory: HeldDirectory | None = None,
    max_bytes: int = COLLECTION_MAX_BYTES,
) -> None:
    if not ASSET_URL.fullmatch(url):
        fail("refusing non-producer release asset URL")
    if not isinstance(expected_digest, str) or not DIGEST.fullmatch(expected_digest):
        fail("release asset expected digest is invalid")
    if type(max_bytes) is not int or max_bytes <= 0 or max_bytes > COLLECTION_MAX_BYTES:
        fail("release asset verification limit is invalid")
    if held_directory is None:
        with secure_directory(destination.parent, create=True) as directory:
            download_checked(
                url,
                expected_digest,
                destination,
                held_directory=directory,
                max_bytes=max_bytes,
            )
        return
    if destination.parent != held_directory.path:
        fail("release asset destination does not match its held directory")
    digest = hashlib.sha256()
    total = 0
    request = urllib.request.Request(
        url, headers={"User-Agent": "mlx90-evidence-verifier"}
    )
    descriptor: int | None = None
    created = False
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            descriptor = open_exclusive_regular(
                held_directory,
                destination.name,
            )
            created = True
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                for chunk in iter(lambda: response.read(1024 * 1024), b""):
                    total += len(chunk)
                    if total > max_bytes:
                        fail(f"release asset exceeds the {max_bytes}-byte limit")
                    digest.update(chunk)
                    handle.write(chunk)
                if total <= 0:
                    fail("release asset is empty")
                actual = f"sha256:{digest.hexdigest()}"
                if actual != expected_digest:
                    fail(
                        "release asset digest mismatch: "
                        f"expected {expected_digest}, got {actual}"
                    )
                handle.flush()
                os.fsync(handle.fileno())
                os.fchmod(handle.fileno(), 0o400)
                metadata = os.fstat(handle.fileno())
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o400
                    or metadata.st_size != total
                ):
                    fail("release asset output is unsafe after download")
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if created:
            unlink_relative(held_directory, destination.name)
        raise


def _verify_collection_snapshot_signature(
    artifact: FileSnapshot,
    bundle: FileSnapshot,
    producer_workflow_sha: str,
) -> None:
    if not isinstance(producer_workflow_sha, str) or not SHA.fullmatch(
        producer_workflow_sha
    ):
        fail("producer workflow SHA for signature verification is invalid")
    command = [
        "cosign",
        "verify-blob",
        "--bundle",
        str(bundle.path),
        "--certificate-oidc-issuer",
        OIDC_ISSUER,
        "--certificate-identity",
        PRODUCER_IDENTITY,
        "--certificate-github-workflow-sha",
        producer_workflow_sha,
        str(artifact.path),
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("cannot execute producer signature verification") from exc
    if completed.returncode != 0:
        fail("producer collection signature verification failed")


def verify_collection_signature(
    artifact: Path,
    bundle: Path,
    producer_workflow_sha: str,
    *,
    artifact_digest: str,
    bundle_digest: str,
) -> None:
    """Verify private, digest-bound snapshots rather than mutable input paths."""

    with private_snapshot_directory("mlx90-collection-signature-") as snapshot_root:
        artifact_snapshot = snapshot_regular_file(
            artifact,
            snapshot_root,
            "collection.tar.gz",
            max_bytes=COLLECTION_MAX_BYTES,
            label="producer collection artifact",
            expected_digest=artifact_digest,
        )
        bundle_snapshot = snapshot_regular_file(
            bundle,
            snapshot_root,
            "collection.sigstore.json",
            max_bytes=BUNDLE_MAX_BYTES,
            label="producer collection Sigstore bundle",
            expected_digest=bundle_digest,
        )
        _verify_collection_snapshot_signature(
            artifact_snapshot,
            bundle_snapshot,
            producer_workflow_sha,
        )


def _validate_assurance_documents(
    evidence: dict[str, Any],
    sbom: object,
    provenance: object,
) -> None:
    artifact = evidence["artifact"]
    version = artifact["version"]
    sbom = require_dict(sbom, "sbom")
    component = require_dict(
        require_dict(sbom.get("metadata"), "sbom.metadata").get("component"),
        "sbom.metadata.component",
    )
    expected_hash = artifact["digest"].removeprefix("sha256:")
    if sbom.get("bomFormat") != "CycloneDX":
        fail("producer SBOM must be CycloneDX")
    if component.get("version") != version:
        fail("producer SBOM version does not match evidence")
    if component.get("purl") != f"pkg:ansible/lit/supplementary@{version}":
        fail("producer SBOM purl does not match evidence")
    hashes = component.get("hashes")
    if (
        not isinstance(hashes, list)
        or {"alg": "SHA-256", "content": expected_hash} not in hashes
    ):
        fail("producer SBOM does not bind the collection digest")
    properties = component.get("properties")
    if not isinstance(properties, list):
        fail("producer SBOM component properties are missing")
    expected_properties = {
        ("lit:candidate:filename", f"lit-supplementary-{version}.tar.gz"),
        ("lit:candidate:commit", evidence["producer"]["sourceSha"]),
    }
    actual_properties = {
        (entry.get("name"), entry.get("value"))
        for entry in properties
        if isinstance(entry, dict)
    }
    if not expected_properties <= actual_properties:
        fail("producer SBOM does not bind filename and source SHA")
    provenance = require_dict(provenance, "provenance")
    expected_provenance = {
        "schema_version": 1,
        "repository": PRODUCER,
        "candidate": f"lit-supplementary-{version}.tar.gz",
        "candidate_sha256": expected_hash,
        "commit_sha": evidence["producer"]["sourceSha"],
        "ref": "refs/heads/main",
        "source_ref": "refs/heads/main",
        "workflow": "Collection CI",
        "workflow_event_sha": evidence["producer"]["sourceSha"],
    }
    for name, expected in expected_provenance.items():
        if provenance.get(name) != expected:
            fail(f"producer provenance field {name} does not match evidence")


def verify_assets(evidence: dict[str, Any], output: Path) -> dict[str, str]:
    artifact = evidence["artifact"]
    version = artifact["version"]
    authenticated_evidence_id = evidence["metadata"]["id"]
    collection_url = (
        f"https://github.com/{PRODUCER}/releases/download/v{version}/"
        f"lit-supplementary-{version}.tar.gz"
    )
    created_outputs: list[str] = []
    with secure_directory(output, create=True) as output_directory:
        try:
            download_checked(
                collection_url,
                artifact["digest"],
                output / "collection.tar.gz",
                held_directory=output_directory,
                max_bytes=COLLECTION_MAX_BYTES,
            )
            created_outputs.append("collection.tar.gz")
            for field in ("signature", "sbom", "provenance"):
                ref = artifact[field]
                download_checked(
                    ref["url"],
                    ref["digest"],
                    output / field,
                    held_directory=output_directory,
                    max_bytes=(
                        BUNDLE_MAX_BYTES
                        if field == "signature"
                        else ASSURANCE_MAX_BYTES
                    ),
                )
                created_outputs.append(field)
            with private_snapshot_directory("mlx90-producer-assets-") as snapshot_root:
                collection_snapshot = snapshot_regular_file(
                    output / "collection.tar.gz",
                    snapshot_root,
                    "collection.tar.gz",
                    max_bytes=COLLECTION_MAX_BYTES,
                    label="producer collection artifact",
                    expected_digest=artifact["digest"],
                    source_directory=output_directory,
                )
                signature_snapshot = snapshot_regular_file(
                    output / "signature",
                    snapshot_root,
                    "collection.sigstore.json",
                    max_bytes=BUNDLE_MAX_BYTES,
                    label="producer collection Sigstore bundle",
                    expected_digest=artifact["signature"]["digest"],
                    source_directory=output_directory,
                )
                sbom_snapshot = snapshot_regular_file(
                    output / "sbom",
                    snapshot_root,
                    "sbom.cdx.json",
                    max_bytes=ASSURANCE_MAX_BYTES,
                    label="producer SBOM",
                    expected_digest=artifact["sbom"]["digest"],
                    capture_bytes=True,
                    source_directory=output_directory,
                )
                provenance_snapshot = snapshot_regular_file(
                    output / "provenance",
                    snapshot_root,
                    "provenance.json",
                    max_bytes=ASSURANCE_MAX_BYTES,
                    label="producer provenance",
                    expected_digest=artifact["provenance"]["digest"],
                    capture_bytes=True,
                    source_directory=output_directory,
                )
                _verify_collection_snapshot_signature(
                    collection_snapshot,
                    signature_snapshot,
                    evidence["producer"]["workflowRef"],
                )
                assert sbom_snapshot.payload is not None
                assert provenance_snapshot.payload is not None
                sbom = load_strict_json(sbom_snapshot.payload, "producer SBOM")
                provenance = load_strict_json(
                    provenance_snapshot.payload, "producer provenance"
                )
                _validate_assurance_documents(evidence, sbom, provenance)
                result = {
                    "collectionDigest": collection_snapshot.digest,
                    "evidenceId": authenticated_evidence_id,
                    "version": version,
                }
        except Exception:
            for name in reversed(created_outputs):
                unlink_relative(output_directory, name)
            raise
    return result


def tar_file_manifest(path: Path, name: str) -> dict[str, str]:
    result: dict[str, str] = {}
    total_size = 0
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            candidate = PurePosixPath(member.name)
            parts = tuple(part for part in candidate.parts if part not in {"", "."})
            if candidate.is_absolute() or not parts or ".." in parts:
                fail(f"{name} contains an unsafe path")
            normalized = PurePosixPath(*parts).as_posix()
            if member.isdir():
                continue
            if not member.isfile():
                fail(f"{name} contains unsupported non-regular entry {normalized}")
            if normalized in result:
                fail(f"{name} contains duplicate path {normalized}")
            total_size += member.size
            if len(result) >= 100_000 or total_size > 512 * 1024 * 1024:
                fail(f"{name} exceeds the verification size limit")
            handle = archive.extractfile(member)
            if handle is None:
                fail(f"{name} cannot read {normalized}")
            file_hash = hashlib.sha256()
            with handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    file_hash.update(chunk)
            result[normalized] = file_hash.hexdigest()
    if not result:
        fail(f"{name} contains no regular files")
    return result


def verify_installed_tree(
    artifact: Path,
    installed: Path,
    artifact_digest: str,
) -> None:
    with private_snapshot_directory("mlx90-installed-tree-") as snapshot_root:
        artifact_snapshot = snapshot_regular_file(
            artifact,
            snapshot_root,
            "producer-collection.tar.gz",
            max_bytes=COLLECTION_MAX_BYTES,
            label="producer collection artifact",
            expected_digest=artifact_digest,
        )
        installed_snapshot = snapshot_regular_file(
            installed,
            snapshot_root,
            "installed-collection.tar.gz",
            max_bytes=INSTALLED_EXPORT_MAX_BYTES,
            label="installed collection export",
        )
        expected = tar_file_manifest(
            artifact_snapshot.path, "producer collection artifact"
        )
        actual = tar_file_manifest(
            installed_snapshot.path, "installed collection export"
        )
    missing = sorted(expected.keys() - actual.keys())
    unexpected = sorted(actual.keys() - expected.keys())
    changed = sorted(
        path
        for path in expected.keys() & actual.keys()
        if expected[path] != actual[path]
    )
    if missing:
        fail(f"installed collection is missing producer file {missing[0]}")
    if unexpected:
        fail(f"installed collection contains unexpected file {unexpected[0]}")
    if changed:
        fail(f"installed collection file differs from producer artifact: {changed[0]}")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--evidence", type=Path, required=True)
    prepare.add_argument("--evidence-url", required=True)
    prepare.add_argument("--evidence-digest", required=True)
    prepare.add_argument("--checksums", type=Path, required=True)
    prepare.add_argument("--checksums-bundle", type=Path, required=True)
    prepare.add_argument("--producer-workflow-sha", required=True)
    prepare.add_argument("--base-sha", required=True)
    prepare.add_argument("--requirements", type=Path, required=True)
    prepare.add_argument("--requirements-digest", required=True)
    prepare.add_argument("--receipt", type=Path, required=True)
    validate = subparsers.add_parser("validate-receipt")
    validate.add_argument("--evidence", type=Path, required=True)
    validate.add_argument("--evidence-url", required=True)
    validate.add_argument("--checksums", type=Path, required=True)
    validate.add_argument("--checksums-bundle", type=Path, required=True)
    validate.add_argument("--producer-workflow-sha", required=True)
    validate.add_argument("--base-sha", required=True)
    validate.add_argument("--requirements", type=Path, required=True)
    validate.add_argument("--requirements-digest", required=True)
    validate.add_argument("--base-requirements", type=Path, required=True)
    validate.add_argument("--base-requirements-digest", required=True)
    validate.add_argument("--receipt", type=Path, required=True)
    validate.add_argument("--receipt-digest", required=True)
    assets = subparsers.add_parser("verify-assets")
    assets.add_argument("--evidence", type=Path, required=True)
    assets.add_argument("--evidence-url", required=True)
    assets.add_argument("--checksums", type=Path, required=True)
    assets.add_argument("--checksums-bundle", type=Path, required=True)
    assets.add_argument("--producer-workflow-sha", required=True)
    assets.add_argument("--output", type=Path, required=True)
    version = subparsers.add_parser("requirement-version")
    version.add_argument("--requirements", type=Path, required=True)
    installed = subparsers.add_parser("verify-installed-tree")
    installed.add_argument("--artifact", type=Path, required=True)
    installed.add_argument("--artifact-digest", required=True)
    installed.add_argument("--installed", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare_security_update(
                args.evidence,
                args.evidence_url,
                args.evidence_digest,
                args.checksums,
                args.checksums_bundle,
                args.producer_workflow_sha,
                args.base_sha,
                args.requirements,
                args.requirements_digest,
                args.receipt,
            )
        elif args.command == "validate-receipt":
            validate_receipt(
                args.receipt,
                args.evidence,
                args.requirements,
                args.base_sha,
                args.evidence_url,
                args.checksums,
                args.checksums_bundle,
                args.producer_workflow_sha,
                receipt_digest=args.receipt_digest,
                requirements_digest=args.requirements_digest,
                base_requirements_path=args.base_requirements,
                base_requirements_digest=args.base_requirements_digest,
            )
        elif args.command == "verify-assets":
            evidence, _ = load_authenticated_evidence(
                args.evidence,
                args.evidence_url,
                args.checksums,
                args.checksums_bundle,
                args.producer_workflow_sha,
            )
            print(
                json.dumps(
                    verify_assets(evidence, args.output),
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
            return 0
        elif args.command == "requirement-version":
            print(requirement_version(args.requirements))
            return 0
        else:
            verify_installed_tree(
                args.artifact,
                args.installed,
                args.artifact_digest,
            )
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        tarfile.TarError,
        urllib.error.URLError,
    ) as exc:
        print(f"security release rejected: {exc}", file=sys.stderr)
        return 1
    print(f"security release {args.command} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
