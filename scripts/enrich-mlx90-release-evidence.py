#!/usr/bin/env python3
"""Bind container release evidence to the MLX-90 producer receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from mlx90_secure_files import read_regular_bytes

CONSUMER = "lightning-it/container-ee-wunder-ansible-ubi9"
PRODUCER = "lightning-it/ansible-collection-supplementary"
COLLECTION = "lit.supplementary"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)
SEMVER_TAG = re.compile(
    r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)
EVIDENCE_ID = re.compile(r"\A[A-Z0-9][A-Z0-9._-]{2,127}\Z")
RFC3339_TIMESTAMP = re.compile(
    r"\A(?P<date_time>[0-9]{4}-(?:0[1-9]|1[0-2])-"
    r"(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):"
    r"[0-5][0-9]:[0-5][0-9])(?:\.(?P<fraction>[0-9]{1,6}))?"
    r"(?P<offset>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z"
)
SECURITY_ID = re.compile(
    r"^(?:CVE-[0-9]{4}-[0-9]{4,}|"
    r"GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}|"
    r"LIT-SEC-[A-Z0-9._-]+)$"
)
PROFILES = ("public", "certified", "bootstrap")
ASSURANCE_MAX_BYTES = 16 * 1024 * 1024
SBOM_MAX_BYTES = 64 * 1024 * 1024
SIGNATURE_MAX_BYTES = 4 * 1024 * 1024
PROVENANCE_MAX_BYTES = 16 * 1024 * 1024
CANONICAL_IMAGES = {
    "public": "quay.io/lightning-it/ee-wunder-ansible-ubi9",
    "certified": "quay.io/lightning-it/ee-wunder-ansible-ubi9-certified",
    "bootstrap": "quay.io/lightning-it/ee-wunder-ansible-ubi9-bootstrap",
}
MACOS_SYSTEM_ALIASES = {
    Path("/tmp"): Path("/private/tmp"),
    Path("/var"): Path("/private/var"),
}
MARKDOWN_START = "<!-- mlx90-immutable-delivery:start -->"
MARKDOWN_END = "<!-- mlx90-immutable-delivery:end -->"
MARKDOWN_HEADING = "## MLX-90 immutable delivery evidence"
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
RECEIPT_MAX_BYTES = 1024 * 1024


def fail(message: str) -> None:
    raise ValueError(message)


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


def parse_time(value: object, field: str) -> datetime:
    match = RFC3339_TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        fail(f"{field} must be an RFC3339 timestamp")
    try:
        fraction = match.group("fraction")
        offset = match.group("offset")
        normalized = match.group("date_time")
        if fraction is not None:
            normalized += f".{fraction.ljust(6, '0')}"
        normalized += "+00:00" if offset == "Z" else offset
        return datetime.fromisoformat(normalized)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{field} must be an RFC3339 timestamp") from exc


def load(path: Path, *, max_bytes: int, name: str) -> dict[str, Any]:
    payload = read_regular_bytes(path, max_bytes=max_bytes, label=name)
    data = load_strict_json(payload, name)
    if not isinstance(data, dict):
        fail(f"{path} must contain an object")
    return data


def validate_producer_asset_ref(
    value: object, version: str, field: str, expected_asset: str
) -> dict[str, str]:
    if not isinstance(value, dict):
        fail(f"receipt {field} must be an object")
    missing = {"url", "digest"} - value.keys()
    unknown = value.keys() - {"url", "digest"}
    if missing or unknown:
        fail(f"receipt {field} fields are not exact")
    url, expected_digest = value["url"], value["digest"]
    expected_url = (
        f"https://github.com/{PRODUCER}/releases/download/"
        f"v{version}/{expected_asset}"
    )
    if not isinstance(url, str) or url != expected_url:
        fail(f"receipt {field} URL is not the trusted producer release asset")
    if not isinstance(expected_digest, str) or not DIGEST.fullmatch(expected_digest):
        fail(f"receipt {field} digest is invalid")
    return {"url": url, "digest": expected_digest}


def validate_producer_receipt(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("receipt must be an object")
    if set(value) != RECEIPT_FIELDS:
        fail("receipt fields are not exact")
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
        fail("unsupported receipt version")
    evidence_id = value["evidenceId"]
    if not isinstance(evidence_id, str) or not EVIDENCE_ID.fullmatch(evidence_id):
        fail("receipt evidence ID is invalid")
    identifiers = value["securityIdentifiers"]
    if (
        not isinstance(identifiers, list)
        or not identifiers
        or not all(
            isinstance(identifier, str) and SECURITY_ID.fullmatch(identifier)
            for identifier in identifiers
        )
        or len(identifiers) != len(set(identifiers))
    ):
        fail("receipt security identifiers are invalid or duplicated")
    if value["consumerRepository"] != CONSUMER:
        fail("receipt consumer does not match")
    if value["producerRepository"] != PRODUCER:
        fail("receipt producer does not match")
    if value["producerWorkflowRepository"] != PRODUCER:
        fail("receipt producer workflow repository does not match")
    if value["collection"] != COLLECTION:
        fail("receipt collection does not match")
    version = value["version"]
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        fail("receipt collection version is invalid")
    for field in ("collectionDigest", "evidenceDigest"):
        field_value = value[field]
        if not isinstance(field_value, str) or not DIGEST.fullmatch(field_value):
            fail(f"receipt {field} is invalid")
    for field in ("producerSourceSha", "producerWorkflowSha", "baseSha"):
        field_value = value[field]
        if not isinstance(field_value, str) or not SHA.fullmatch(field_value):
            fail(f"receipt {field} is invalid")
    if value["producerWorkflowSha"] != value["producerSourceSha"]:
        fail("receipt producer workflow SHA must match source SHA")
    validate_producer_asset_ref(
        {"url": value["evidenceUrl"], "digest": value["evidenceDigest"]},
        version,
        "evidence",
        "security-release-evidence.json",
    )
    expected_assets = {
        "signature": f"lit-supplementary-{version}.tar.gz.sigstore.json",
        "sbom": "sbom.cdx.json",
        "provenance": "provenance.json",
    }
    for field, expected_asset in expected_assets.items():
        validate_producer_asset_ref(value[field], version, field, expected_asset)
    return value


def digest(path: Path, *, max_bytes: int, label: str) -> str:
    payload = read_regular_bytes(path, max_bytes=max_bytes, label=label)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def checked_file_ref(
    dist: Path,
    value: object,
    release_asset_base: str,
    *,
    max_bytes: int,
    label: str,
) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"file", "digest"}:
        fail("assurance file reference is malformed")
    name, expected = value["file"], value["digest"]
    if not isinstance(name, str) or Path(name).name != name:
        fail("assurance filename is unsafe")
    if not isinstance(expected, str) or not DIGEST.fullmatch(expected):
        fail("assurance file digest is malformed")
    path = dist / name
    if digest(path, max_bytes=max_bytes, label=label) != expected:
        fail(f"assurance digest mismatch for {name}")
    return {"file": name, "url": f"{release_asset_base}/{name}", "digest": expected}


def validate_assurance(
    profile: str,
    assurance: object,
    dist: Path,
    release_asset_base: str,
    expected_version: str,
) -> dict[str, Any]:
    required = {
        "image",
        "manifestDigest",
        "platforms",
        "attestationDigests",
        "manifest",
        "signature",
        "sbom",
        "installedCollections",
        "installedCollection",
    }
    if not isinstance(assurance, dict) or set(assurance) != required:
        fail(f"{profile} assurance fields are not exact")
    manifest_digest = assurance["manifestDigest"]
    if not isinstance(manifest_digest, str) or not DIGEST.fullmatch(manifest_digest):
        fail(f"{profile} manifest digest is invalid")
    platforms = assurance["platforms"]
    if not isinstance(platforms, dict) or set(platforms) != {
        "linux/amd64",
        "linux/arm64",
    }:
        fail(f"{profile} must contain exactly amd64 and arm64")
    if not all(
        isinstance(value, str) and DIGEST.fullmatch(value)
        for value in platforms.values()
    ):
        fail(f"{profile} platform digest is invalid")
    if len(set(platforms.values())) != 2:
        fail(f"{profile} platform digests must be distinct")
    attestations = assurance["attestationDigests"]
    if (
        not isinstance(attestations, list)
        or len(attestations) < 2
        or not all(
            isinstance(value, str) and DIGEST.fullmatch(value) for value in attestations
        )
        or len(attestations) != len(set(attestations))
    ):
        fail(f"{profile} BuildKit SBOM/provenance attestations are incomplete")
    installed = assurance["installedCollection"]
    if profile == "bootstrap":
        if installed is not None:
            fail("bootstrap must not contain lit.supplementary")
    elif installed != {"name": "lit.supplementary", "version": expected_version}:
        fail(f"{profile} installed collection version does not match producer evidence")
    image = assurance["image"]
    if not isinstance(image, str) or image != CANONICAL_IMAGES.get(profile):
        fail(f"{profile} image is not the canonical container repository")
    return {
        "image": image,
        "manifestDigest": manifest_digest,
        "platforms": platforms,
        "attestationDigests": attestations,
        "manifest": checked_file_ref(
            dist,
            assurance["manifest"],
            release_asset_base,
            max_bytes=ASSURANCE_MAX_BYTES,
            label=f"{profile} manifest assurance asset",
        ),
        "signature": checked_file_ref(
            dist,
            assurance["signature"],
            release_asset_base,
            max_bytes=SIGNATURE_MAX_BYTES,
            label=f"{profile} signature assurance asset",
        ),
        "sbom": checked_file_ref(
            dist,
            assurance["sbom"],
            release_asset_base,
            max_bytes=SBOM_MAX_BYTES,
            label=f"{profile} SBOM assurance asset",
        ),
        "installedCollections": checked_file_ref(
            dist,
            assurance["installedCollections"],
            release_asset_base,
            max_bytes=ASSURANCE_MAX_BYTES,
            label=f"{profile} installed-collections assurance asset",
        ),
        "installedCollection": installed,
    }


def immutable_ref(value: dict[str, Any]) -> dict[str, str]:
    return {"url": value["url"], "digest": value["digest"]}


def validate_release_context(
    evidence: dict[str, Any], consumer_merge_sha: str, release_asset_base: str
) -> str:
    if evidence.get("commit_sha") != consumer_merge_sha:
        fail("generic release evidence is not bound to consumer merge SHA")
    release_tag = evidence.get("tag")
    if not isinstance(release_tag, str) or not SEMVER_TAG.fullmatch(release_tag):
        fail("generic release evidence tag is invalid")
    expected_base = (
        f"https://github.com/{CONSUMER}/releases/download/{release_tag}"
    )
    if release_asset_base != expected_base:
        fail("release asset base does not match generic release evidence tag")
    expected_references = {
        "sbom": f"{expected_base}/sbom.cdx.json",
        "trivy_report": f"{expected_base}/sbom.cdx.json",
        "provenance": f"{expected_base}/release-provenance.intoto.jsonl",
        "signature": f"{expected_base}/SHA256SUMS.sigstore.json",
    }
    for field, expected in expected_references.items():
        if evidence.get(field) != expected:
            fail(f"generic release evidence {field} is not an immutable release asset")
    return release_tag


def render_markdown(
    current: str, receipt: dict[str, Any], consumer_merge_sha: str
) -> str:
    if current.count(MARKDOWN_START) != current.count(MARKDOWN_END):
        fail("existing MLX-90 Markdown transaction markers are incomplete")
    if current.count(MARKDOWN_START) > 1:
        fail("existing MLX-90 Markdown section is duplicated")
    if MARKDOWN_HEADING in current and MARKDOWN_START not in current:
        fail("existing MLX-90 Markdown section has no transaction markers")
    if MARKDOWN_START in current:
        start = current.index(MARKDOWN_START)
        end = current.index(MARKDOWN_END, start) + len(MARKDOWN_END)
        if current[end:].strip():
            fail("existing MLX-90 Markdown section is not terminal")
        current = current[:start].rstrip()
    identifiers = ", ".join(receipt["securityIdentifiers"])
    section = (
        f"{MARKDOWN_START}\n"
        f"{MARKDOWN_HEADING}\n\n"
        f"- Evidence ID: `{receipt['evidenceId']}`\n"
        f"- Security identifiers: `{identifiers}`\n"
        f"- Collection: `lit.supplementary {receipt['version']}`\n"
        f"- Collection digest: `{receipt['collectionDigest']}`\n"
        f"- Consumer merge SHA: `{consumer_merge_sha}`\n"
        "- Container variants: `public`, `certified`, `bootstrap`\n"
        "- Required platforms: `linux/amd64`, `linux/arm64`\n"
        "- Signatures, SBOMs, provenance, manifests, platform digests, and installed versions are recorded in `release-evidence.json`.\n"
        f"{MARKDOWN_END}\n"
    )
    prefix = current.rstrip()
    return f"{prefix}\n\n{section}" if prefix else section


def validate_completed_outputs(
    evidence: dict[str, Any],
    container_evidence: dict[str, Any],
    receipt: dict[str, Any],
    release_tag: str,
    release_asset_base: str,
) -> None:
    mlx90 = evidence.get("mlx90")
    if not isinstance(mlx90, dict) or set(mlx90) != {
        "evidenceId",
        "securityIdentifiers",
        "producer",
        "consumer",
        "containers",
    }:
        fail("completed generic evidence has an invalid MLX-90 section")
    if (
        mlx90["evidenceId"] != receipt["evidenceId"]
        or mlx90["securityIdentifiers"] != receipt["securityIdentifiers"]
        or set(mlx90["containers"]) != set(PROFILES)
    ):
        fail("completed generic evidence is not bound to the producer receipt")
    if set(container_evidence) != {
        "apiVersion",
        "kind",
        "securityEvidenceId",
        "producer",
        "consumer",
        "release",
        "variants",
        "revocation",
    }:
        fail("completed container evidence fields are not exact")
    evidence_id = container_evidence["securityEvidenceId"]
    if (
        not isinstance(evidence_id, str)
        or not EVIDENCE_ID.fullmatch(evidence_id)
        or evidence_id != receipt["evidenceId"]
    ):
        fail("completed container evidence ID is invalid")
    if (
        container_evidence["apiVersion"] != "lit.security-release.container/v1"
        or container_evidence["kind"] != "SecurityReleaseContainerEvidence"
        or container_evidence["release"].get("tag") != release_tag
        or set(container_evidence["variants"]) != set(PROFILES)
    ):
        fail("completed container evidence contract is invalid")
    for profile, record in container_evidence["variants"].items():
        if not isinstance(record, dict) or set(record) != {
            "image",
            "manifestDigest",
            "platformDigests",
            "signature",
            "sbom",
            "provenance",
        }:
            fail(f"completed {profile} container evidence fields are not exact")
        if set(record["platformDigests"]) != {"linux/amd64", "linux/arm64"}:
            fail(f"completed {profile} platform evidence is incomplete")
        for field in ("signature", "sbom", "provenance"):
            reference = record[field]
            if (
                not isinstance(reference, dict)
                or set(reference) != {"url", "digest"}
                or not isinstance(reference["url"], str)
                or not reference["url"].startswith(f"{release_asset_base}/")
                or not isinstance(reference["digest"], str)
                or not DIGEST.fullmatch(reference["digest"])
            ):
                fail(f"completed {profile} {field} evidence is invalid")
    try:
        json.dumps(evidence, sort_keys=True, allow_nan=False)
        json.dumps(container_evidence, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("completed MLX-90 evidence is not canonical JSON") from exc


def has_symlink_component(path: Path) -> bool:
    absolute = path if path.is_absolute() else Path.cwd() / path
    if ".." in absolute.parts:
        return True
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if not current.is_symlink():
            continue
        # macOS exposes these exact root-level aliases as stable system paths.
        # No nested or user-controlled symlink is accepted.
        expected = (
            MACOS_SYSTEM_ALIASES.get(current) if sys.platform == "darwin" else None
        )
        if expected is None:
            return True
        try:
            if current.resolve(strict=True) != expected or not expected.is_dir():
                return True
        except OSError:
            return True
    return False


def _stage_bytes(target: Path, value: bytes, mode: int) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)
        raise
    return temporary_path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_outputs(outputs: dict[Path, bytes]) -> None:
    if not outputs:
        fail("atomic evidence update has no outputs")
    originals: dict[Path, bytes | None] = {}
    modes: dict[Path, int] = {}
    for target in outputs:
        if not target.parent.is_dir() or has_symlink_component(target.parent):
            fail(f"evidence output parent is unsafe: {target.parent}")
        if target.is_symlink() or (target.exists() and not target.is_file()):
            fail(f"evidence output target is unsafe: {target}")
        originals[target] = target.read_bytes() if target.exists() else None
        modes[target] = target.stat().st_mode & 0o777 if target.exists() else 0o644

    staged: dict[Path, Path] = {}
    committed: list[Path] = []
    directories = sorted({target.parent for target in outputs}, key=str)
    try:
        for target, value in outputs.items():
            staged[target] = _stage_bytes(target, value, modes[target])
        for target in outputs:
            os.replace(staged[target], target)
            committed.append(target)
        for directory in directories:
            _fsync_directory(directory)
    except OSError as exc:
        rollback_error: OSError | None = None
        for target in reversed(committed):
            try:
                original = originals[target]
                if original is None:
                    target.unlink(missing_ok=True)
                else:
                    rollback = _stage_bytes(target, original, modes[target])
                    try:
                        os.replace(rollback, target)
                    finally:
                        rollback.unlink(missing_ok=True)
            except OSError as rollback_exc:
                rollback_error = rollback_error or rollback_exc
        for directory in directories:
            try:
                _fsync_directory(directory)
            except OSError as rollback_exc:
                rollback_error = rollback_error or rollback_exc
        if rollback_error is not None:
            raise ValueError(
                "atomic evidence update failed and rollback was incomplete"
            ) from rollback_error
        raise ValueError("atomic evidence update failed; original files restored") from exc
    finally:
        for temporary_path in staged.values():
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument(
        "--receipt", type=Path, default=Path(".lit/security-release-receipt.json")
    )
    parser.add_argument("--require-receipt", action="store_true")
    parser.add_argument("--consumer-merge-sha", required=True)
    parser.add_argument("--consumer-head-sha")
    parser.add_argument("--consumer-pull-request", type=int)
    parser.add_argument("--release-id", type=int)
    parser.add_argument("--release-run-id", type=int)
    parser.add_argument("--release-run-attempt", type=int)
    parser.add_argument("--revocation-checked-at")
    parser.add_argument("--release-asset-base", required=True)
    args = parser.parse_args()
    try:
        if not args.receipt.is_file() and not args.require_receipt:
            print("No MLX-90 receipt; generic release evidence remains unchanged.")
            return 0
        if not args.receipt.is_file():
            fail("required MLX-90 receipt is missing")
        if not SHA.fullmatch(args.consumer_merge_sha):
            fail("consumer merge SHA must be a full SHA")
        if args.consumer_head_sha is None:
            fail("missing --consumer-head-sha for MLX-90 receipt enrichment")
        if not SHA.fullmatch(args.consumer_head_sha):
            fail("consumer head SHA must be a full SHA")
        for name in (
            "consumer_pull_request",
            "release_id",
            "release_run_id",
            "release_run_attempt",
        ):
            value = getattr(args, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                fail(f"{name.replace('_', '-')} must be a positive integer")
        parse_time(args.revocation_checked_at, "revocation-checked-at")
        receipt = validate_producer_receipt(
            load(args.receipt, max_bytes=RECEIPT_MAX_BYTES, name="producer receipt")
        )

        evidence_path = args.dist / "release-evidence.json"
        markdown_path = args.dist / "release-evidence.md"
        provenance_path = args.dist / "release-provenance.intoto.jsonl"
        container_evidence_path = args.dist / "mlx90-container-evidence.json"
        evidence = load(
            evidence_path,
            max_bytes=ASSURANCE_MAX_BYTES,
            name="generic release evidence",
        )
        release_tag = validate_release_context(
            evidence, args.consumer_merge_sha, args.release_asset_base
        )
        markdown_current = markdown_path.read_text(encoding="utf-8")
        provenance_ref = {
            "file": provenance_path.name,
            "url": f"{args.release_asset_base}/{provenance_path.name}",
            "digest": digest(
                provenance_path,
                max_bytes=PROVENANCE_MAX_BYTES,
                label="release provenance",
            ),
        }
        containers: dict[str, Any] = {}
        for profile in PROFILES:
            assurance = load(
                args.dist / f"assurance-{profile}.json",
                max_bytes=ASSURANCE_MAX_BYTES,
                name=f"{profile} assurance",
            )
            record = validate_assurance(
                profile,
                assurance,
                args.dist,
                args.release_asset_base,
                receipt["version"],
            )
            record["provenance"] = provenance_ref
            containers[profile] = record
        public_image = containers["public"]["image"]
        if containers["certified"]["image"] != f"{public_image}-certified":
            fail("certified image must be the public image with -certified suffix")
        if containers["bootstrap"]["image"] != f"{public_image}-bootstrap":
            fail("bootstrap image must be the public image with -bootstrap suffix")

        evidence["mlx90"] = {
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
                "evidence": {
                    "url": receipt["evidenceUrl"],
                    "digest": receipt["evidenceDigest"],
                },
                "signature": receipt["signature"],
                "sbom": receipt["sbom"],
                "provenance": receipt["provenance"],
            },
            "consumer": {
                "repository": receipt["consumerRepository"],
                "baseSha": receipt["baseSha"],
                "mergeSha": args.consumer_merge_sha,
            },
            "containers": containers,
        }

        interoperability_variants: dict[str, Any] = {}
        for profile, record in containers.items():
            interoperability_variants[profile] = {
                "image": record["image"],
                "manifestDigest": record["manifestDigest"],
                "platformDigests": record["platforms"],
                "signature": immutable_ref(record["signature"]),
                "sbom": immutable_ref(record["sbom"]),
                "provenance": immutable_ref(record["provenance"]),
            }
        container_evidence = {
            "apiVersion": "lit.security-release.container/v1",
            "kind": "SecurityReleaseContainerEvidence",
            "securityEvidenceId": receipt["evidenceId"],
            "producer": {
                "repository": receipt["producerRepository"],
                "sourceSha": receipt["producerSourceSha"],
                "collection": receipt["collection"],
                "version": receipt["version"],
                "collectionDigest": receipt["collectionDigest"],
                "evidence": {
                    "url": receipt["evidenceUrl"],
                    "digest": receipt["evidenceDigest"],
                },
            },
            "consumer": {
                "repository": receipt["consumerRepository"],
                "pullRequest": args.consumer_pull_request,
                "baseSha": receipt["baseSha"],
                "headSha": args.consumer_head_sha,
                "mergeSha": args.consumer_merge_sha,
            },
            "release": {
                "repository": receipt["consumerRepository"],
                "id": args.release_id,
                "tag": release_tag,
                "url": (
                    "https://github.com/lightning-it/container-ee-wunder-ansible-ubi9/"
                    f"releases/tag/{release_tag}"
                ),
                "sourceSha": args.consumer_merge_sha,
                "workflowRunId": args.release_run_id,
                "workflowRunAttempt": args.release_run_attempt,
            },
            "variants": interoperability_variants,
            "revocation": {
                "status": "not_revoked",
                "checkedAt": args.revocation_checked_at,
            },
        }
        validate_completed_outputs(
            evidence,
            container_evidence,
            receipt,
            release_tag,
            args.release_asset_base,
        )
        markdown = render_markdown(
            markdown_current, receipt, args.consumer_merge_sha
        )
        outputs = {
            evidence_path: (
                json.dumps(
                    evidence, indent=2, sort_keys=True, allow_nan=False
                )
                + "\n"
            ).encode("utf-8"),
            markdown_path: markdown.encode("utf-8"),
            container_evidence_path: (
                json.dumps(
                    container_evidence, indent=2, sort_keys=True, allow_nan=False
                )
                + "\n"
            ).encode("utf-8"),
        }
        atomic_write_outputs(outputs)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"MLX-90 release evidence rejected: {exc}", file=sys.stderr)
        return 1
    print("MLX-90 release evidence enriched and validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
