#!/usr/bin/env python3
"""Authenticate exact MLX-90 guard inputs and emit a bounded claim set."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterator


SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
EVIDENCE_ID = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,127}$")
VERSION = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)
CHECKSUM_LINE = re.compile(
    r"^([0-9a-f]{64}) ([ *])([A-Za-z0-9][A-Za-z0-9._-]{0,127})$"
)
PRODUCER = "lightning-it/ansible-collection-supplementary"
CONSUMER = "lightning-it/container-ee-wunder-ansible-ubi9"
FINALIZER = "lightning-it/modulix-validation"
FINALIZER_WORKFLOW = ".github/workflows/mlx90-final-acceptance.yml"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
PRODUCER_PUBLISH_IDENTITY = (
    f"https://github.com/{PRODUCER}/.github/workflows/"
    "collection-publish.yml@refs/heads/main"
)
FINALIZER_IDENTITY = (
    f"https://github.com/{FINALIZER}/{FINALIZER_WORKFLOW}@refs/heads/main"
)
PRODUCER_ACCEPTANCE_FILES = {
    "security-release-evidence.json": 16 * 1024 * 1024,
    "SHA256SUMS": 1024 * 1024,
    "SHA256SUMS.sigstore.json": 16 * 1024 * 1024,
}
FINAL_ACCEPTANCE_FILES = {
    "SHA256SUMS": 1024 * 1024,
    "SHA256SUMS.sigstore.json": 16 * 1024 * 1024,
    "mlx90-final-acceptance.json": 16 * 1024 * 1024,
    "mlx90-verification-receipts.json": 64 * 1024 * 1024,
    "mlx90-verification-report.json": 16 * 1024 * 1024,
    "security-release-delivered.json": 16 * 1024 * 1024,
}
SIGNED_ACCEPTANCE_ASSETS = {
    "mlx90-final-acceptance.json",
    "mlx90-verification-receipts.json",
    "mlx90-verification-report.json",
    "security-release-delivered.json",
}


def fail(message: str) -> None:
    raise ValueError(message)


def _duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def strict_json(payload: bytes, label: str) -> Any:
    if not payload:
        fail(f"{label} is empty")
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_duplicate_object,
            parse_constant=lambda value: fail(
                f"{label} contains non-finite number {value}"
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def require_exact(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        fail(f"{label} does not have the exact required fields")


def _hash(name: str) -> Any:
    if name not in {"sha1", "sha256"}:
        fail("unsupported Git object format")
    try:
        return hashlib.new(name, usedforsecurity=False)
    except TypeError:  # pragma: no cover - compatibility for older Python builds
        return hashlib.new(name)


def read_git_blob(
    descriptor: int,
    *,
    object_format: str,
    expected_oid: str,
    max_bytes: int,
    label: str,
) -> bytes:
    expected_length = {"sha1": 40, "sha256": 64}.get(object_format)
    if (
        type(descriptor) is not int
        or descriptor < 3
        or expected_length is None
        or len(expected_oid) != expected_length
        or any(character not in "0123456789abcdef" for character in expected_oid)
        or type(max_bytes) is not int
        or max_bytes <= 0
    ):
        fail(f"{label} Git blob binding is invalid")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            fail(f"{label} exceeds its Git blob size limit")
    payload = b"".join(chunks)
    if not payload:
        fail(f"{label} Git blob is empty")
    digest = _hash(object_format)
    digest.update(f"blob {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    if not __import__("hmac").compare_digest(digest.hexdigest(), expected_oid):
        fail(f"{label} bytes do not match Git object ID {expected_oid}")
    return payload


def read_regular_fd(descriptor: int, *, max_bytes: int, label: str) -> bytes:
    if type(descriptor) is not int or descriptor < 3:
        fail(f"{label} descriptor is invalid")
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        fail(f"{label} descriptor is not a regular file")
    if before.st_size <= 0 or before.st_size > max_bytes:
        fail(f"{label} is empty or exceeds its size limit")
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        if not chunk:
            fail(f"{label} ended before its declared size")
        chunks.append(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after:
        fail(f"{label} changed while its exact bytes were captured")
    return b"".join(chunks)


@contextlib.contextmanager
def sealed_file(payload: bytes, label: str) -> Iterator[int]:
    if not payload:
        fail(f"{label} cannot be held as an empty file")
    memfd_create = getattr(os, "memfd_create", None)
    if memfd_create is None:
        fail("sealed anonymous files are unavailable")
    descriptor = memfd_create(
        f"mlx90-{label}",
        getattr(os, "MFD_CLOEXEC", 0x0001) | getattr(os, "MFD_ALLOW_SEALING", 0x0002),
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write to sealed verification input")
            offset += written
        os.fchmod(descriptor, 0o400)
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        yield descriptor
    finally:
        os.close(descriptor)


def verify_cosign(
    checksums: bytes,
    bundle: bytes,
    *,
    identity: str,
    workflow_sha: str,
) -> None:
    if not SHA.fullmatch(workflow_sha):
        fail("signature workflow SHA is invalid")
    with sealed_file(checksums, "checksums") as checksums_fd, sealed_file(
        bundle, "bundle"
    ) as bundle_fd:
        try:
            completed = subprocess.run(
                [
                    "cosign",
                    "verify-blob",
                    "--bundle",
                    f"/proc/self/fd/{bundle_fd}",
                    "--certificate-identity",
                    identity,
                    "--certificate-oidc-issuer",
                    OIDC_ISSUER,
                    "--certificate-github-workflow-sha",
                    workflow_sha,
                    f"/proc/self/fd/{checksums_fd}",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                pass_fds=(bundle_fd, checksums_fd),
                timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError("cannot execute exact-byte Sigstore verification") from exc
    if completed.returncode != 0:
        fail("exact-byte Sigstore verification failed")


def checksum_entries(payload: bytes, *, exact_names: set[str] | None) -> dict[str, str]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise ValueError("checksum manifest must be UTF-8") from exc
    result: dict[str, str] = {}
    for line in lines:
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            fail("checksum manifest has a non-canonical entry")
        digest, _, name = match.groups()
        if name in result:
            fail("checksum manifest has a duplicate asset")
        result[name] = digest
    if exact_names is not None and set(result) != exact_names:
        fail("checksum manifest does not have the exact required asset set")
    return result


def requirement_version(payload: bytes, label: str) -> str:
    consumer = sys.modules.get("security_release_consumer")
    if consumer is None:
        fail("commit-bound producer validator is not loaded")
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"{label} is not UTF-8") from exc
    version = consumer.requirement_version_text(text)
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        fail(f"{label} parser returned an invalid lit.supplementary version")
    return version


def authenticate_producer(
    *,
    receipt_bytes: bytes,
    requirements_bytes: bytes,
    base_requirements_bytes: bytes,
    evidence_bytes: bytes,
    checksums_bytes: bytes,
    bundle_bytes: bytes,
    evidence_url: str,
    producer_sha: str,
    base_sha: str,
    cosign_verifier: Callable[..., None] = verify_cosign,
) -> tuple[dict[str, Any], dict[str, Any]]:
    consumer = sys.modules.get("security_release_consumer")
    if consumer is None:
        fail("commit-bound producer validator is not loaded")
    if not SHA.fullmatch(producer_sha) or not SHA.fullmatch(base_sha):
        fail("producer or base SHA is invalid")
    entries = checksum_entries(checksums_bytes, exact_names=None)
    evidence_digest = f"sha256:{hashlib.sha256(evidence_bytes).hexdigest()}"
    if entries.get("security-release-evidence.json") != evidence_digest[7:]:
        fail("signed producer checksum manifest does not bind evidence bytes")
    cosign_verifier(
        checksums_bytes,
        bundle_bytes,
        identity=PRODUCER_PUBLISH_IDENTITY,
        workflow_sha=producer_sha,
    )
    strict_evidence = require_object(
        strict_json(evidence_bytes, "producer evidence"), "producer evidence"
    )
    evidence = consumer.load_evidence_bytes(evidence_bytes)
    if evidence != strict_evidence:
        fail("producer evidence parsing is not canonical")
    if evidence["producer"]["workflowRef"] != producer_sha:
        fail("producer evidence does not bind the release workflow SHA")
    consumer.validate_versioned_asset_url(
        evidence_url, evidence["artifact"]["version"], "evidence URL"
    )
    if evidence_url != (
        f"https://github.com/{PRODUCER}/releases/download/"
        f"v{evidence['artifact']['version']}/security-release-evidence.json"
    ):
        fail("producer evidence URL is not exact")
    receipt = require_object(strict_json(receipt_bytes, "receipt"), "receipt")
    consumer.require_exact(receipt, consumer.RECEIPT_KEYS, "receipt")
    expected_receipt = consumer.receipt_for(
        evidence, evidence_url, evidence_digest, base_sha
    )
    if receipt != expected_receipt:
        fail("receipt does not exactly match authenticated producer evidence")
    if requirement_version(requirements_bytes, "requirements") != evidence["artifact"][
        "version"
    ]:
        fail("requirements version does not match producer evidence")
    if requirement_version(
        base_requirements_bytes, "base requirements"
    ) != evidence["security"]["affectedVersion"]:
        fail("base requirements version does not match affectedVersion")
    return evidence, receipt


def validate_update(
    *,
    receipt_bytes: bytes,
    requirements_bytes: bytes,
    base_requirements_bytes: bytes,
    evidence_bytes: bytes,
    checksums_bytes: bytes,
    bundle_bytes: bytes,
    evidence_url: str,
    producer_sha: str,
    base_sha: str,
) -> dict[str, Any]:
    consumer = sys.modules.get("security_release_consumer")
    evidence, _ = authenticate_producer(
        receipt_bytes=receipt_bytes,
        requirements_bytes=requirements_bytes,
        base_requirements_bytes=base_requirements_bytes,
        evidence_bytes=evidence_bytes,
        checksums_bytes=checksums_bytes,
        bundle_bytes=bundle_bytes,
        evidence_url=evidence_url,
        producer_sha=producer_sha,
        base_sha=base_sha,
    )
    assert consumer is not None
    with tempfile.TemporaryDirectory(prefix="mlx90-guard-assets-") as temporary:
        output = Path(temporary) / "assets"
        result = consumer.verify_assets(evidence, output)
        strict_json((output / "sbom").read_bytes(), "producer SBOM")
        strict_json((output / "provenance").read_bytes(), "producer provenance")
    if set(result) != {"collectionDigest", "evidenceId", "version"}:
        fail("producer asset verifier returned an unexpected claim set")
    if (
        result["collectionDigest"] != evidence["artifact"]["digest"]
        or result["evidenceId"] != evidence["metadata"]["id"]
        or result["version"] != evidence["artifact"]["version"]
    ):
        fail("producer asset verifier claims differ from authenticated evidence")
    return {
        "collectionDigest": result["collectionDigest"],
        "evidenceId": result["evidenceId"],
        "version": result["version"],
    }


_ConcretePath = type(Path())


class HeldBytesPath(_ConcretePath):  # type: ignore[misc, valid-type]
    """Path-compatible immutable byte view for an already authenticated input."""

    _held_payload: bytes

    def __new__(cls, name: str, payload: bytes) -> "HeldBytesPath":
        instance = super().__new__(cls, name)
        instance._held_payload = payload
        return instance

    def __init__(self, _name: str, _payload: bytes) -> None:
        # pathlib's concrete class would otherwise interpret payload as a
        # second path component after __new__ stored the held bytes.  Python
        # 3.14 moved concrete-path initialization out of __new__, while older
        # supported versions still inherit object.__init__ here.
        if _ConcretePath.__init__ is not object.__init__:
            super().__init__(_name)

    def read_bytes(self) -> bytes:
        return self._held_payload


def validate_cleanup(
    *,
    receipt_bytes: bytes,
    requirements_bytes: bytes,
    base_requirements_bytes: bytes,
    producer_files: dict[str, bytes],
    acceptance_files: dict[str, bytes],
    evidence_url: str,
    producer_sha: str,
    receipt_base_sha: str,
    acceptance_digest: str,
    finalizer_sha: str,
    quay_namespace: str,
) -> dict[str, Any]:
    evidence, receipt = authenticate_producer(
        receipt_bytes=receipt_bytes,
        requirements_bytes=requirements_bytes,
        base_requirements_bytes=base_requirements_bytes,
        evidence_bytes=producer_files["security-release-evidence.json"],
        checksums_bytes=producer_files["SHA256SUMS"],
        bundle_bytes=producer_files["SHA256SUMS.sigstore.json"],
        evidence_url=evidence_url,
        producer_sha=producer_sha,
        base_sha=receipt_base_sha,
    )
    entries = checksum_entries(
        acceptance_files["SHA256SUMS"], exact_names=SIGNED_ACCEPTANCE_ASSETS
    )
    for name in SIGNED_ACCEPTANCE_ASSETS:
        actual = hashlib.sha256(acceptance_files[name]).hexdigest()
        if entries[name] != actual:
            fail(f"signed final-acceptance checksum differs for {name}")
    if not DIGEST.fullmatch(acceptance_digest) or (
        "sha256:" + entries["mlx90-final-acceptance.json"] != acceptance_digest
    ):
        fail("final acceptance digest does not match its signed manifest")
    verify_cosign(
        acceptance_files["SHA256SUMS"],
        acceptance_files["SHA256SUMS.sigstore.json"],
        identity=FINALIZER_IDENTITY,
        workflow_sha=finalizer_sha,
    )
    acceptance = require_object(
        strict_json(
            acceptance_files["mlx90-final-acceptance.json"], "final acceptance"
        ),
        "final acceptance",
    )
    receipt_bundle = require_object(
        strict_json(
            acceptance_files["mlx90-verification-receipts.json"],
            "verification receipt bundle",
        ),
        "verification receipt bundle",
    )
    require_object(
        strict_json(
            acceptance_files["mlx90-verification-report.json"],
            "verification report",
        ),
        "verification report",
    )
    delivered = require_object(
        strict_json(
            acceptance_files["security-release-delivered.json"],
            "delivered producer evidence",
        ),
        "delivered producer evidence",
    )
    try:
        consumer_merge_sha = acceptance["consumer"]["mergeSha"]
        container_release_tag = acceptance["container"]["releaseTag"]
    except (KeyError, TypeError) as exc:
        raise ValueError("final acceptance identity is malformed") from exc
    promotion = sys.modules.get("mlx90_promotion_validator")
    if promotion is None:
        fail("commit-bound final-acceptance validator is not loaded")
    original_verify = promotion.verify_final_acceptance_signature

    def already_verified(*_args: Any, **_kwargs: Any) -> bytes:
        return acceptance_files["mlx90-final-acceptance.json"]

    promotion.verify_final_acceptance_signature = already_verified
    try:
        claims = promotion.validate(
            HeldBytesPath(
                "mlx90-final-acceptance.json",
                acceptance_files["mlx90-final-acceptance.json"],
            ),
            receipt_bundle_path=HeldBytesPath(
                "mlx90-verification-receipts.json",
                acceptance_files["mlx90-verification-receipts.json"],
            ),
            checksums_path=HeldBytesPath(
                "SHA256SUMS", acceptance_files["SHA256SUMS"]
            ),
            checksums_bundle_path=HeldBytesPath(
                "SHA256SUMS.sigstore.json",
                acceptance_files["SHA256SUMS.sigstore.json"],
            ),
            expected_digest=acceptance_digest,
            consumer_merge_sha=consumer_merge_sha,
            container_release_tag=container_release_tag,
            finalizer_sha=finalizer_sha,
            quay_namespace=quay_namespace,
        )
    finally:
        promotion.verify_final_acceptance_signature = original_verify
    if claims["evidenceId"] != evidence["metadata"]["id"]:
        fail("final acceptance evidence ID differs from producer evidence")
    if (
        claims["producerEvidenceUrl"] != evidence_url
        or claims["producerEvidenceDigest"] != receipt["evidenceDigest"]
        or claims["producerSourceSha"] != evidence["producer"]["sourceSha"]
        or claims["producerVersion"] != evidence["artifact"]["version"]
        or claims["consumerBaseSha"] != receipt_base_sha
    ):
        fail("final acceptance producer or consumer claims differ from the receipt")
    expected_producer = {
        "repository": PRODUCER,
        "sourceSha": evidence["producer"]["sourceSha"],
        "collection": evidence["artifact"]["collection"],
        "version": evidence["artifact"]["version"],
        "collectionDigest": evidence["artifact"]["digest"],
        "releaseUrl": evidence["artifact"]["releaseUrl"],
        "evidence": {"url": evidence_url, "digest": receipt["evidenceDigest"]},
    }
    if acceptance.get("producer") != expected_producer:
        fail("final acceptance producer object is not exact")
    delivery = require_object(delivered.get("delivery"), "delivery")
    require_exact(
        delivery,
        {
            "consumerRepository",
            "consumerHeadSha",
            "consumerMergeSha",
            "container",
            "acceptedAt",
            "acceptanceRunUrl",
        },
        "delivery",
    )
    delivered_core = dict(delivered)
    delivered_core.pop("status", None)
    delivered_core.pop("delivery", None)
    if delivered_core != evidence or delivered.get("status") != "delivered":
        fail("delivered producer evidence does not exactly extend signed evidence")
    if (
        delivery["consumerRepository"] != CONSUMER
        or delivery["consumerHeadSha"] != claims["consumerHeadSha"]
        or delivery["consumerMergeSha"] != claims["consumerMergeSha"]
        or delivery["acceptanceRunUrl"] != claims["finalizerRunUrl"]
        or delivery["acceptedAt"] != acceptance["acceptance"]["acceptedAt"]
    ):
        fail("delivered producer evidence has inconsistent final claims")
    delivery_container = require_object(delivery["container"], "delivery.container")
    require_exact(
        delivery_container,
        {"tag", "manifestDigest", "imageDigests", "signature", "sbom", "provenance"},
        "delivery.container",
    )
    public = acceptance["container"]["variants"]["public"]
    if (
        delivery_container["tag"] != claims["containerReleaseTag"]
        or delivery_container["manifestDigest"] != public["manifestDigest"]
        or delivery_container["signature"] != public["signature"]
        or delivery_container["sbom"] != public["sbom"]
        or delivery_container["provenance"] != public["provenance"]
    ):
        fail("delivered container claims differ from final acceptance")
    expected_image_digests = sorted(
        {
            digest
            for variant in acceptance["container"]["variants"].values()
            for digest in (
                variant["manifestDigest"],
                *variant["platformDigests"].values(),
            )
        }
    )
    if delivery_container["imageDigests"] != expected_image_digests:
        fail("delivered container digest set is not exact")
    return {
        "acceptanceDigest": acceptance_digest,
        "consumerHeadSha": claims["consumerHeadSha"],
        "consumerMergeSha": claims["consumerMergeSha"],
        "consumerPullRequest": claims["consumerPullRequest"],
        "containerReleaseId": claims["containerReleaseId"],
        "containerReleaseTag": claims["containerReleaseTag"],
        "evidenceId": claims["evidenceId"],
        "finalizerRunAttempt": claims["finalizerRunAttempt"],
        "finalizerRunId": claims["finalizerRunId"],
        "finalizerRunUrl": claims["finalizerRunUrl"],
        "finalizerSha": claims["finalizerSha"],
        "producerVersion": claims["producerVersion"],
        "receiptDigest": f"sha256:{hashlib.sha256(receipt_bytes).hexdigest()}",
    }


def add_git_blob(parser: argparse.ArgumentParser, name: str) -> None:
    parser.add_argument(f"--{name}-oid", required=True)
    parser.add_argument(f"--{name}-fd", type=int, required=True)


def add_producer_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--object-format", choices=("sha1", "sha256"), required=True)
    add_git_blob(parser, "receipt")
    add_git_blob(parser, "requirements")
    add_git_blob(parser, "base-requirements")
    parser.add_argument("--evidence-fd", type=int, required=True)
    parser.add_argument("--checksums-fd", type=int, required=True)
    parser.add_argument("--checksums-bundle-fd", type=int, required=True)
    parser.add_argument("--evidence-url", required=True)
    parser.add_argument("--producer-sha", required=True)


def git_input(args: argparse.Namespace, name: str, limit: int) -> bytes:
    return read_git_blob(
        getattr(args, name.replace("-", "_") + "_fd"),
        object_format=args.object_format,
        expected_oid=getattr(args, name.replace("-", "_") + "_oid"),
        max_bytes=limit,
        label=name,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    update = commands.add_parser("update")
    add_producer_inputs(update)
    update.add_argument("--base-sha", required=True)
    cleanup = commands.add_parser("cleanup")
    add_producer_inputs(cleanup)
    cleanup.add_argument("--receipt-base-sha", required=True)
    cleanup.add_argument("--acceptance-digest", required=True)
    cleanup.add_argument("--finalizer-sha", required=True)
    cleanup.add_argument("--quay-namespace", required=True)
    for name in FINAL_ACCEPTANCE_FILES:
        cleanup.add_argument(f"--{name.removesuffix('.json').replace('.', '-')}-fd", type=int, required=True)
    args = parser.parse_args()
    try:
        receipt_bytes = git_input(args, "receipt", 16 * 1024 * 1024)
        requirements_bytes = git_input(args, "requirements", 16 * 1024 * 1024)
        base_requirements_bytes = git_input(
            args, "base-requirements", 16 * 1024 * 1024
        )
        producer_files = {
            "security-release-evidence.json": read_regular_fd(
                args.evidence_fd,
                max_bytes=PRODUCER_ACCEPTANCE_FILES["security-release-evidence.json"],
                label="producer evidence",
            ),
            "SHA256SUMS": read_regular_fd(
                args.checksums_fd,
                max_bytes=PRODUCER_ACCEPTANCE_FILES["SHA256SUMS"],
                label="producer checksums",
            ),
            "SHA256SUMS.sigstore.json": read_regular_fd(
                args.checksums_bundle_fd,
                max_bytes=PRODUCER_ACCEPTANCE_FILES["SHA256SUMS.sigstore.json"],
                label="producer checksum bundle",
            ),
        }
        if args.command == "update":
            result = validate_update(
                receipt_bytes=receipt_bytes,
                requirements_bytes=requirements_bytes,
                base_requirements_bytes=base_requirements_bytes,
                evidence_bytes=producer_files["security-release-evidence.json"],
                checksums_bytes=producer_files["SHA256SUMS"],
                bundle_bytes=producer_files["SHA256SUMS.sigstore.json"],
                evidence_url=args.evidence_url,
                producer_sha=args.producer_sha,
                base_sha=args.base_sha,
            )
        else:
            acceptance_files = {
                name: read_regular_fd(
                    getattr(
                        args,
                        name.removesuffix(".json").replace(".", "_").replace("-", "_")
                        + "_fd",
                    ),
                    max_bytes=limit,
                    label=f"final acceptance {name}",
                )
                for name, limit in FINAL_ACCEPTANCE_FILES.items()
            }
            result = validate_cleanup(
                receipt_bytes=receipt_bytes,
                requirements_bytes=requirements_bytes,
                base_requirements_bytes=base_requirements_bytes,
                producer_files=producer_files,
                acceptance_files=acceptance_files,
                evidence_url=args.evidence_url,
                producer_sha=args.producer_sha,
                receipt_base_sha=args.receipt_base_sha,
                acceptance_digest=args.acceptance_digest,
                finalizer_sha=args.finalizer_sha,
                quay_namespace=args.quay_namespace,
            )
        result.update(
            {
                "baseRequirementsBlob": args.base_requirements_oid,
                "receiptBlob": args.receipt_oid,
                "requirementsBlob": args.requirements_oid,
            }
        )
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"MLX-90 guard verification rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
