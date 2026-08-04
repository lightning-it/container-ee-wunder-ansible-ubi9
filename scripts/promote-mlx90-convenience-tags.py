#!/usr/bin/env python3
"""Validate signed MLX-90 final acceptance before mutable tag promotion."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from mlx90_secure_files import private_snapshot_directory, snapshot_regular_file

CONSUMER = "lightning-it/container-ee-wunder-ansible-ubi9"
PRODUCER = "lightning-it/ansible-collection-supplementary"
FINALIZER = "lightning-it/modulix-validation"
FINALIZER_WORKFLOW = ".github/workflows/mlx90-final-acceptance.yml"
FINALIZER_IDENTITY = (
    f"https://github.com/{FINALIZER}/{FINALIZER_WORKFLOW}@refs/heads/main"
)
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
ACCEPTANCE_ASSET = "mlx90-final-acceptance.json"
CHECKSUMS_ASSET = "SHA256SUMS"
CHECKSUMS_BUNDLE_ASSET = "SHA256SUMS.sigstore.json"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
CHECKSUM_LINE = re.compile(
    r"^([0-9a-f]{64}) ([ *])([A-Za-z0-9][A-Za-z0-9._-]{0,127})$"
)
SEMVER_TAG = re.compile(
    r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)
VERSION = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)
EVIDENCE_ID = re.compile(r"\A[A-Z0-9][A-Z0-9._-]{2,127}\Z")
RFC3339_TIMESTAMP = re.compile(
    r"\A(?P<date_time>[0-9]{4}-(?:0[1-9]|1[0-2])-"
    r"(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):"
    r"[0-5][0-9]:[0-5][0-9])(?:\.(?P<fraction>[0-9]{1,6}))?"
    r"(?P<offset>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z"
)
VARIANTS = ("public", "certified", "bootstrap")
REQUIRED_CHECKS = {
    "producerEvidence",
    "producerSignature",
    "consumerIdentity",
    "containerRelease",
    "manifestDigests",
    "platformDigests",
    "pulledByDigest",
    "collectionVersion",
    "bootstrapCollectionAbsent",
    "securityAcceptance",
    "signature",
    "sbom",
    "provenance",
    "buildkitAttestations",
    "notRevoked",
}
ACCEPTANCE_MAX_BYTES = 4 * 1024 * 1024
CHECKSUMS_MAX_BYTES = 64 * 1024
BUNDLE_MAX_BYTES = 4 * 1024 * 1024


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


def require_dict(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{name} must be an object")
    return value


def require_exact(value: dict[str, Any], keys: set[str], name: str) -> None:
    missing = keys - value.keys()
    unknown = value.keys() - keys
    if missing:
        fail(f"{name} missing fields: {', '.join(sorted(missing))}")
    if unknown:
        fail(f"{name} has unknown fields: {', '.join(sorted(unknown))}")


def validate_release_asset_ref(
    value: object,
    *,
    release_tag: str,
    field: str,
    expected_asset: str,
) -> dict[str, str]:
    reference = require_dict(value, field)
    require_exact(reference, {"url", "digest"}, field)
    url, expected_digest = reference["url"], reference["digest"]
    expected_url = (
        f"https://github.com/{CONSUMER}/releases/download/"
        f"{release_tag}/{expected_asset}"
    )
    if not isinstance(url, str) or url != expected_url:
        fail(f"{field}.url must name immutable release asset {expected_asset}")
    if not isinstance(expected_digest, str) or not DIGEST.fullmatch(expected_digest):
        fail(f"{field}.digest must be sha256")
    return {"url": url, "digest": expected_digest}


def verify_final_acceptance_signature(
    path: Path,
    *,
    checksums_path: Path | None,
    checksums_bundle_path: Path | None,
    expected_digest: str,
    finalizer_sha: str,
) -> bytes:
    if not isinstance(path, Path) or path.name != ACCEPTANCE_ASSET:
        fail(f"acceptance path must name {ACCEPTANCE_ASSET}")
    if not isinstance(checksums_path, Path) or checksums_path.name != CHECKSUMS_ASSET:
        fail(f"cryptographic verification requires {CHECKSUMS_ASSET}")
    if (
        not isinstance(checksums_bundle_path, Path)
        or checksums_bundle_path.name != CHECKSUMS_BUNDLE_ASSET
    ):
        fail(f"cryptographic verification requires {CHECKSUMS_BUNDLE_ASSET}")
    if not isinstance(expected_digest, str) or not DIGEST.fullmatch(expected_digest):
        fail("expected acceptance digest is invalid")
    if not isinstance(finalizer_sha, str) or not SHA.fullmatch(finalizer_sha):
        fail("finalizer SHA is invalid")
    with private_snapshot_directory(
        "mlx90-final-acceptance-signature-"
    ) as snapshot_root:
        acceptance_snapshot = snapshot_regular_file(
            path,
            snapshot_root,
            ACCEPTANCE_ASSET,
            max_bytes=ACCEPTANCE_MAX_BYTES,
            label="final acceptance immutable dispatch",
            expected_digest=expected_digest,
            capture_bytes=True,
        )
        checksums_snapshot = snapshot_regular_file(
            checksums_path,
            snapshot_root,
            CHECKSUMS_ASSET,
            max_bytes=CHECKSUMS_MAX_BYTES,
            label="final-acceptance checksum manifest",
            capture_bytes=True,
        )
        bundle_snapshot = snapshot_regular_file(
            checksums_bundle_path,
            snapshot_root,
            CHECKSUMS_BUNDLE_ASSET,
            max_bytes=BUNDLE_MAX_BYTES,
            label="final-acceptance Sigstore bundle",
            capture_bytes=True,
        )
        assert acceptance_snapshot.payload is not None
        assert checksums_snapshot.payload is not None
        assert bundle_snapshot.payload is not None
        checksum_bytes = checksums_snapshot.payload
        try:
            lines = checksum_bytes.decode("utf-8").splitlines()
        except UnicodeError as exc:
            raise ValueError("signed checksum manifest must be UTF-8") from exc
        entries: dict[str, str] = {}
        for line in lines:
            match = CHECKSUM_LINE.fullmatch(line)
            if match is None:
                fail("signed checksum manifest has a malformed entry")
            checksum, _, filename = match.groups()
            if filename in entries:
                fail("signed checksum manifest has a duplicate asset")
            entries[filename] = checksum
        expected_hex = expected_digest.removeprefix("sha256:")
        if entries.get(ACCEPTANCE_ASSET) != expected_hex:
            fail("signed checksum manifest does not bind final acceptance")
        held_descriptors: list[int] = []

        def hold_anonymous(payload: bytes, name: str) -> int:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(
                name,
                flags,
                0o600,
                dir_fd=snapshot_root.descriptor,
            )
            try:
                os.unlink(name, dir_fd=snapshot_root.descriptor)
                offset = 0
                while offset < len(payload):
                    written = os.write(descriptor, payload[offset:])
                    if written <= 0:
                        raise OSError("short write to held verification input")
                    offset += written
                os.fchmod(descriptor, 0o400)
                os.lseek(descriptor, 0, os.SEEK_SET)
            except BaseException:
                os.close(descriptor)
                raise
            held_descriptors.append(descriptor)
            return descriptor

        try:
            checksums_descriptor = hold_anonymous(
                checksum_bytes,
                "cosign-checksums",
            )
            bundle_descriptor = hold_anonymous(
                bundle_snapshot.payload,
                "cosign-bundle",
            )
            try:
                completed = subprocess.run(
                    [
                        "cosign",
                        "verify-blob",
                        "--bundle",
                        f"/dev/fd/{bundle_descriptor}",
                        "--certificate-identity",
                        FINALIZER_IDENTITY,
                        "--certificate-oidc-issuer",
                        OIDC_ISSUER,
                        "--certificate-github-workflow-sha",
                        finalizer_sha,
                        f"/dev/fd/{checksums_descriptor}",
                    ],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    pass_fds=(bundle_descriptor, checksums_descriptor),
                    timeout=60,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise ValueError(
                    "cannot execute final-acceptance signature verification"
                ) from exc
        finally:
            for descriptor in held_descriptors:
                os.close(descriptor)
        if completed.returncode != 0:
            fail("final-acceptance signature verification failed")
        return acceptance_snapshot.payload


def validate_timestamp(value: object, field: str) -> None:
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
        datetime.fromisoformat(normalized)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{field} must be an RFC3339 timestamp") from exc


def validate(
    path: Path,
    *,
    receipt_bundle_path: Path,
    checksums_path: Path | None = None,
    checksums_bundle_path: Path | None = None,
    expected_digest: str,
    consumer_merge_sha: str,
    container_release_tag: str,
    finalizer_sha: str,
    quay_namespace: str,
) -> dict[str, Any]:
    if not isinstance(path, Path):
        fail("acceptance path must be a filesystem path")
    if not isinstance(expected_digest, str) or not DIGEST.fullmatch(expected_digest):
        fail("expected acceptance digest is invalid")
    if (
        not isinstance(consumer_merge_sha, str)
        or not SHA.fullmatch(consumer_merge_sha)
        or not isinstance(finalizer_sha, str)
        or not SHA.fullmatch(finalizer_sha)
    ):
        fail("consumer or finalizer SHA is invalid")
    if not isinstance(container_release_tag, str) or not SEMVER_TAG.fullmatch(
        container_release_tag
    ):
        fail("container release tag is invalid")
    if not isinstance(quay_namespace, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9._-]{1,127}", quay_namespace
    ):
        fail("Quay namespace is invalid")
    acceptance_bytes = verify_final_acceptance_signature(
        path,
        checksums_path=checksums_path,
        checksums_bundle_path=checksums_bundle_path,
        expected_digest=expected_digest,
        finalizer_sha=finalizer_sha,
    )
    acceptance = require_dict(
        load_strict_json(acceptance_bytes, "final acceptance"), "acceptance"
    )
    require_exact(
        acceptance,
        {
            "apiVersion",
            "kind",
            "status",
            "securityEvidenceId",
            "producer",
            "consumer",
            "container",
            "acceptance",
            "receiptBundle",
            "checks",
            "finalizer",
        },
        "acceptance",
    )
    if (
        acceptance["apiVersion"] != "lit.security-release.acceptance/v1"
        or acceptance["kind"] != "SecurityReleaseAcceptance"
        or acceptance["status"] != "delivered"
    ):
        fail("only delivered MLX-90 final acceptance may promote tags")

    receipt_bundle = require_dict(acceptance["receiptBundle"], "receiptBundle")
    require_exact(receipt_bundle, {"assetName", "digest", "size"}, "receiptBundle")
    try:
        receipt_bytes = receipt_bundle_path.read_bytes()
    except OSError as exc:
        raise ValueError("cannot read verification receipt bundle") from exc
    if (
        not receipt_bytes
        or len(receipt_bytes) > 64 * 1024 * 1024
        or receipt_bundle["assetName"] != "mlx90-verification-receipts.json"
        or receipt_bundle["digest"]
        != "sha256:" + hashlib.sha256(receipt_bytes).hexdigest()
        or type(receipt_bundle["size"]) is not int
        or receipt_bundle["size"] != len(receipt_bytes)
    ):
        fail("verification receipt bundle does not match final acceptance")
    evidence_id = acceptance["securityEvidenceId"]
    if not isinstance(evidence_id, str) or not EVIDENCE_ID.fullmatch(evidence_id):
        fail("evidence ID is invalid")

    producer = require_dict(acceptance["producer"], "producer")
    require_exact(
        producer,
        {
            "repository",
            "sourceSha",
            "collection",
            "version",
            "collectionDigest",
            "releaseUrl",
            "evidence",
        },
        "producer",
    )
    producer_evidence = require_dict(producer["evidence"], "producer evidence")
    require_exact(producer_evidence, {"url", "digest"}, "producer evidence")
    if (
        producer["repository"] != PRODUCER
        or producer["collection"] != "lit.supplementary"
        or not isinstance(producer["sourceSha"], str)
        or not SHA.fullmatch(producer["sourceSha"])
        or not isinstance(producer["version"], str)
        or not VERSION.fullmatch(producer["version"])
        or not isinstance(producer["collectionDigest"], str)
        or not DIGEST.fullmatch(producer["collectionDigest"])
        or producer["releaseUrl"]
        != f"https://github.com/{PRODUCER}/releases/tag/v{producer['version']}"
        or producer_evidence["url"]
        != (
            f"https://github.com/{PRODUCER}/releases/download/"
            f"v{producer['version']}/security-release-evidence.json"
        )
        or not isinstance(producer_evidence["digest"], str)
        or not DIGEST.fullmatch(producer_evidence["digest"])
    ):
        fail("producer evidence identity is invalid")

    consumer = require_dict(acceptance["consumer"], "consumer")
    require_exact(
        consumer,
        {"repository", "pullRequest", "baseSha", "headSha", "mergeSha"},
        "consumer",
    )
    if consumer["repository"] != CONSUMER or consumer["mergeSha"] != consumer_merge_sha:
        fail("consumer identity does not match the immutable callback")
    if not all(
        isinstance(consumer[name], str) and SHA.fullmatch(consumer[name])
        for name in ("baseSha", "headSha", "mergeSha")
    ):
        fail("consumer SHAs are invalid")
    if type(consumer["pullRequest"]) is not int or consumer["pullRequest"] <= 0:
        fail("consumer pull request is invalid")

    profile = require_dict(acceptance["acceptance"], "acceptance profile")
    require_exact(
        profile,
        {"profile", "expectedCollection", "expectedVersion", "acceptedAt"},
        "acceptance profile",
    )
    if (
        not isinstance(profile["profile"], str)
        or not re.fullmatch(
            r"[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]+", profile["profile"]
        )
        or profile["profile"] == "lit.supplementary/mlx90-fixture"
        or profile["expectedCollection"] != producer["collection"]
        or profile["expectedVersion"] != producer["version"]
    ):
        fail("fixture or invalid acceptance profile cannot promote tags")
    validate_timestamp(profile["acceptedAt"], "acceptance profile.acceptedAt")

    checks = require_dict(acceptance["checks"], "checks")
    require_exact(checks, REQUIRED_CHECKS, "checks")
    if not all(value is True for value in checks.values()):
        fail("all final acceptance checks must be true")

    finalizer = require_dict(acceptance["finalizer"], "finalizer")
    require_exact(
        finalizer,
        {"repository", "workflow", "workflowSha", "runId", "runAttempt", "runUrl"},
        "finalizer",
    )
    if (
        finalizer["repository"] != FINALIZER
        or finalizer["workflow"] != FINALIZER_WORKFLOW
        or finalizer["workflowSha"] != finalizer_sha
    ):
        fail("finalizer identity does not match the signed release tag")
    if type(finalizer["runId"]) is not int or finalizer["runId"] <= 0:
        fail("finalizer run ID is invalid")
    if type(finalizer["runAttempt"]) is not int or finalizer["runAttempt"] <= 0:
        fail("finalizer run attempt is invalid")
    if finalizer["runUrl"] != (
        f"https://github.com/{FINALIZER}/actions/runs/{finalizer['runId']}"
    ):
        fail("finalizer run URL is invalid")

    container = require_dict(acceptance["container"], "container")
    require_exact(
        container,
        {
            "repository",
            "releaseId",
            "releaseTag",
            "releaseUrl",
            "sourceSha",
            "evidence",
            "variants",
        },
        "container",
    )
    if (
        container["repository"] != CONSUMER
        or container["sourceSha"] != consumer_merge_sha
        or container["releaseTag"] != container_release_tag
        or container["releaseUrl"]
        != f"https://github.com/{CONSUMER}/releases/tag/{container_release_tag}"
    ):
        fail("container release does not match the immutable callback")
    if type(container["releaseId"]) is not int or container["releaseId"] <= 0:
        fail("container release ID is invalid")
    validate_release_asset_ref(
        container["evidence"],
        release_tag=container_release_tag,
        field="container evidence",
        expected_asset="mlx90-container-evidence.json",
    )

    repo = CONSUMER.split("/", 1)[1]
    base_image = f"quay.io/{quay_namespace}/{repo.removeprefix('container-')}"
    expected_images = {
        "public": base_image,
        "certified": f"{base_image}-certified",
        "bootstrap": f"{base_image}-bootstrap",
    }
    variants = require_dict(container["variants"], "container variants")
    require_exact(variants, set(VARIANTS), "container variants")
    result: dict[str, dict[str, str]] = {}
    for name in VARIANTS:
        variant = require_dict(variants[name], f"container variants.{name}")
        require_exact(
            variant,
            {
                "image",
                "manifestDigest",
                "platformDigests",
                "signature",
                "sbom",
                "provenance",
                "pulledImage",
                "collectionPresent",
                "installedCollectionVersion",
                "profileExecuted",
            },
            f"container variants.{name}",
        )
        image, digest = variant["image"], variant["manifestDigest"]
        if (
            image != expected_images[name]
            or not isinstance(digest, str)
            or not DIGEST.fullmatch(digest)
        ):
            fail(f"container variants.{name} image or digest is invalid")
        if variant["pulledImage"] != f"{image}@{digest}":
            fail(f"container variants.{name} was not accepted by immutable digest")
        platforms = require_dict(
            variant["platformDigests"], f"container variants.{name}.platformDigests"
        )
        require_exact(
            platforms,
            {"linux/amd64", "linux/arm64"},
            f"container variants.{name}.platformDigests",
        )
        if not all(
            isinstance(value, str) and DIGEST.fullmatch(value)
            for value in platforms.values()
        ):
            fail(f"container variants.{name} platform digest is invalid")
        expected_assets = {
            "signature": f"signature-{name}.json",
            "sbom": f"sbom-{name}.cdx.json",
            "provenance": "release-provenance.intoto.jsonl",
        }
        for reference, expected_asset in expected_assets.items():
            validate_release_asset_ref(
                variant[reference],
                release_tag=container_release_tag,
                field=f"container variants.{name}.{reference}",
                expected_asset=expected_asset,
            )
        if name == "bootstrap":
            if (
                variant["collectionPresent"] is not False
                or variant["installedCollectionVersion"] is not None
                or variant["profileExecuted"] is not False
            ):
                fail("bootstrap acceptance state is invalid")
        elif (
            variant["collectionPresent"] is not True
            or variant["installedCollectionVersion"] != producer["version"]
            or variant["profileExecuted"] is not True
        ):
            fail(f"container variants.{name} acceptance state is invalid")
        result[name] = {"image": image, "digest": digest}
    if len({value["digest"] for value in result.values()}) != len(VARIANTS):
        fail("container variant manifest digests must be distinct")
    return {
        "evidenceId": evidence_id,
        "producerEvidenceUrl": producer_evidence["url"],
        "producerEvidenceDigest": producer_evidence["digest"],
        "producerSourceSha": producer["sourceSha"],
        "producerVersion": producer["version"],
        "consumerBaseSha": consumer["baseSha"],
        "consumerHeadSha": consumer["headSha"],
        "consumerMergeSha": consumer["mergeSha"],
        "consumerPullRequest": consumer["pullRequest"],
        "containerReleaseId": container["releaseId"],
        "containerReleaseTag": container["releaseTag"],
        "finalAcceptanceVerified": True,
        "finalizerRunAttempt": finalizer["runAttempt"],
        "finalizerRunId": finalizer["runId"],
        "finalizerRunUrl": finalizer["runUrl"],
        "finalizerSha": finalizer_sha,
        "variants": result,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--acceptance", type=Path, required=True)
    parser.add_argument("--receipt-bundle", type=Path, required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    parser.add_argument("--checksums-bundle", type=Path, required=True)
    parser.add_argument("--acceptance-digest", required=True)
    parser.add_argument("--consumer-merge-sha", required=True)
    parser.add_argument("--container-release-tag", required=True)
    parser.add_argument("--finalizer-sha", required=True)
    parser.add_argument("--quay-namespace", required=True)
    args = parser.parse_args()
    try:
        result = validate(
            args.acceptance,
            receipt_bundle_path=args.receipt_bundle,
            checksums_path=args.checksums,
            checksums_bundle_path=args.checksums_bundle,
            expected_digest=args.acceptance_digest,
            consumer_merge_sha=args.consumer_merge_sha,
            container_release_tag=args.container_release_tag,
            finalizer_sha=args.finalizer_sha,
            quay_namespace=args.quay_namespace,
        )
    except (OSError, ValueError) as exc:
        print(f"convenience tag promotion rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
