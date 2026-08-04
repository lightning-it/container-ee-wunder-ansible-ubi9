#!/usr/bin/env python3
"""Descriptor-based, bounded snapshots for MLX-90 verification inputs."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, NamedTuple


READ_CHUNK_SIZE = 1024 * 1024
MAX_CAPTURE_SIZE = 16 * 1024 * 1024
MACOS_SYSTEM_ALIASES = {
    Path("/tmp"): Path("/private/tmp"),
    Path("/var"): Path("/private/var"),
}


class FileSnapshot(NamedTuple):
    path: Path
    digest: str
    size: int
    payload: bytes | None
    source_identity: tuple[int, int, int, int, int, int]


class HeldDirectory:
    """A directory held open for race-resistant relative access."""

    def __init__(self, path: Path, descriptor: int) -> None:
        self.path = path
        self.descriptor = descriptor


class PrivateSnapshotDirectory(HeldDirectory):
    """An owner-only snapshot directory with tracked cleanup leaves."""

    def __init__(self, path: Path, descriptor: int) -> None:
        super().__init__(path, descriptor)
        self.snapshots: set[str] = set()


def _fail(message: str, error: OSError | None = None) -> None:
    if error is None:
        raise ValueError(message)
    raise ValueError(message) from error


def _require_posix_primitives() -> None:
    missing = [
        name
        for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
        if not isinstance(getattr(os, name, None), int)
        or getattr(os, name) == 0
    ]
    supports_dir_fd = getattr(os, "supports_dir_fd", set())
    if (
        os.open not in supports_dir_fd
        or os.unlink not in supports_dir_fd
        or os.mkdir not in supports_dir_fd
        or os.rename not in supports_dir_fd
    ):
        missing.append("dir_fd open/unlink/mkdir/rename")
    if missing:
        _fail(
            "secure descriptor snapshots are unavailable: " + ", ".join(missing)
        )


def _open_flags(base: int, *, nonblocking: bool = False) -> int:
    _require_posix_primitives()
    flags = base | os.O_CLOEXEC | os.O_NOFOLLOW
    if nonblocking:
        flags |= os.O_NONBLOCK
    return flags


def _close(descriptor: int | None) -> None:
    if descriptor is not None:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _open_descriptor(
    path: str | Path,
    flags: int,
    mode: int = 0o777,
    *,
    dir_fd: int | None = None,
) -> int:
    if dir_fd is None:
        return os.open(path, flags, mode)
    return os.open(path, flags, mode, dir_fd=dir_fd)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short write while creating private snapshot")
        offset += written


def _validate_directory_descriptor(
    descriptor: int,
    *,
    label: str,
    exact_mode: int | None = None,
) -> None:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        _fail(f"{label} is not a directory")
    if exact_mode is not None and stat.S_IMODE(metadata.st_mode) != exact_mode:
        _fail(f"{label} must have mode {exact_mode:04o}")


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _normalize_macos_system_alias(path: Path) -> Path:
    """Map only Apple's fixed root aliases without resolving user components."""

    if sys.platform != "darwin" or not path.is_absolute():
        return path
    parts = path.parts
    if len(parts) < 2:
        return path
    alias = Path(path.anchor) / parts[1]
    expected = MACOS_SYSTEM_ALIASES.get(alias)
    if expected is None:
        return path
    try:
        if (
            not alias.is_symlink()
            or alias.resolve(strict=True) != expected
            or not expected.is_dir()
        ):
            _fail("macOS system alias is unsafe")
    except OSError as exc:
        _fail("macOS system alias is unsafe", exc)
    return expected.joinpath(*parts[2:])


def _open_directory_chain(path: Path, *, label: str) -> int:
    """Open a directory without following a symlink in any path component."""

    parts = path.parts
    if ".." in parts:
        _fail(f"{label} path is unsafe")
    flags = _open_flags(os.O_RDONLY) | os.O_DIRECTORY
    descriptor: int | None = None
    try:
        if path.is_absolute():
            descriptor = _open_descriptor(path.anchor, flags)
            components = parts[1:]
        else:
            descriptor = _open_descriptor(".", flags)
            components = parts
        _validate_directory_descriptor(descriptor, label=label)
        for component in components:
            next_descriptor = _open_descriptor(
                component,
                flags,
                dir_fd=descriptor,
            )
            try:
                _validate_directory_descriptor(next_descriptor, label=label)
            except Exception:
                _close(next_descriptor)
                raise
            _close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        _close(descriptor)
        raise


@contextmanager
def held_directory(path: Path) -> Iterator[HeldDirectory]:
    """Hold one existing non-symlink directory for relative operations."""

    _require_posix_primitives()
    if not isinstance(path, Path):
        _fail("held directory path is invalid")
    descriptor: int | None = None
    try:
        descriptor = _open_directory_chain(
            _normalize_macos_system_alias(path),
            label="held directory",
        )
    except ValueError:
        _close(descriptor)
        raise
    except OSError as exc:
        _close(descriptor)
        _fail("cannot open held directory", exc)
    directory = HeldDirectory(path, descriptor)
    try:
        yield directory
    finally:
        _close(directory.descriptor)


@contextmanager
def secure_directory(path: Path, *, create: bool) -> Iterator[HeldDirectory]:
    """Hold an exact 0700 directory open and operate on leaves via dir_fd."""

    _require_posix_primitives()
    if not isinstance(path, Path) or path.name in {"", ".", ".."}:
        _fail("secure output directory path is invalid")
    parent_descriptor: int | None = None
    descriptor: int | None = None
    normalized_path = _normalize_macos_system_alias(path)
    try:
        parent_descriptor = _open_directory_chain(
            normalized_path.parent,
            label="secure output parent",
        )
        if create:
            try:
                os.mkdir(normalized_path.name, 0o700, dir_fd=parent_descriptor)
            except FileExistsError:
                pass
        descriptor = _open_descriptor(
            normalized_path.name,
            _open_flags(os.O_RDONLY) | os.O_DIRECTORY,
            dir_fd=parent_descriptor,
        )
        _validate_directory_descriptor(
            descriptor,
            label="secure output directory",
            exact_mode=0o700,
        )
    except ValueError:
        _close(descriptor)
        _close(parent_descriptor)
        raise
    except OSError as exc:
        _close(descriptor)
        _close(parent_descriptor)
        _fail("cannot open secure output directory", exc)
    _close(parent_descriptor)
    directory = HeldDirectory(path, descriptor)
    try:
        yield directory
    finally:
        _close(directory.descriptor)


def open_exclusive_regular(directory: HeldDirectory, name: str) -> int:
    """Create a 0600 regular leaf exclusively relative to a held directory."""

    if not isinstance(directory, HeldDirectory):
        _fail("exclusive output directory is invalid")
    if Path(name).name != name or name in {"", ".", ".."}:
        _fail("exclusive output name is unsafe")
    descriptor: int | None = None
    created = False
    validated = False
    try:
        descriptor = _open_descriptor(
            name,
            _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            0o600,
            dir_fd=directory.descriptor,
        )
        created = True
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            _fail("exclusive output leaf is unsafe")
        validated = True
        return descriptor
    except FileExistsError as exc:
        raise ValueError("exclusive output leaf already exists") from exc
    except ValueError:
        raise
    except OSError as exc:
        _fail("cannot create exclusive output leaf", exc)
    finally:
        if created and not validated:
            # Ownership of a valid descriptor transfers to the caller only on return.
            # During exception unwinding, close and remove the exact created leaf.
            _close(descriptor)
            try:
                os.unlink(name, dir_fd=directory.descriptor)
            except OSError:
                pass


def unlink_relative(directory: HeldDirectory, name: str) -> None:
    """Remove one exact leaf relative to a held directory descriptor."""

    if not isinstance(directory, HeldDirectory):
        _fail("output cleanup directory is invalid")
    if Path(name).name != name or name in {"", ".", ".."}:
        _fail("output cleanup name is unsafe")
    try:
        os.unlink(name, dir_fd=directory.descriptor)
    except FileNotFoundError:
        pass
    except OSError as exc:
        _fail(f"cannot remove partial output {name}", exc)


def write_exclusive_regular(
    directory: HeldDirectory,
    name: str,
    payload: bytes,
    *,
    mode: int,
    label: str,
) -> str:
    """Publish exact bytes once without following or replacing a leaf."""

    if not isinstance(directory, HeldDirectory):
        _fail(f"{label} output directory is invalid")
    if Path(name).name != name or name in {"", ".", ".."}:
        _fail(f"{label} output name is unsafe")
    if not isinstance(payload, bytes) or not payload:
        _fail(f"{label} output payload is empty or invalid")
    if type(mode) is not int or mode not in {0o600, 0o640, 0o644}:
        _fail(f"{label} output mode is invalid")
    descriptor: int | None = None
    created = False
    succeeded = False
    try:
        descriptor = open_exclusive_regular(directory, name)
        created = True
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_size != len(payload)
        ):
            _fail(f"{label} exclusive output is unsafe")
        os.fsync(directory.descriptor)
        succeeded = True
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"
    except ValueError:
        raise
    except OSError as exc:
        _fail(f"cannot write {label} exclusive output", exc)
    finally:
        _close(descriptor)
        if created and not succeeded:
            try:
                os.unlink(name, dir_fd=directory.descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                pass


def replace_regular_from_snapshot(
    directory: HeldDirectory,
    name: str,
    payload: bytes,
    source_snapshot: FileSnapshot,
    *,
    label: str,
) -> str:
    """Atomically replace the unchanged source entry with exact rendered bytes."""

    if not isinstance(directory, HeldDirectory):
        _fail(f"{label} output directory is invalid")
    if Path(name).name != name or name in {"", ".", ".."}:
        _fail(f"{label} output name is unsafe")
    if not isinstance(payload, bytes) or not payload:
        _fail(f"{label} output payload is empty or invalid")
    if not isinstance(source_snapshot, FileSnapshot):
        _fail(f"{label} source snapshot is invalid")
    source_mode = stat.S_IMODE(source_snapshot.source_identity[2])
    if (
        not source_mode & stat.S_IRUSR
        or source_mode & 0o133
        or source_mode not in {0o400, 0o440, 0o444, 0o600, 0o640, 0o644}
    ):
        _fail(f"{label} source mode is unsafe")

    temporary_name = f".mlx90-update-{secrets.token_hex(16)}"
    temporary_descriptor: int | None = None
    current_descriptor: int | None = None
    final_descriptor: int | None = None
    temporary_created = False
    renamed = False
    try:
        temporary_descriptor = open_exclusive_regular(
            directory,
            temporary_name,
        )
        temporary_created = True
        _write_all(temporary_descriptor, payload)
        os.fsync(temporary_descriptor)
        os.fchmod(temporary_descriptor, source_mode)
        os.fsync(temporary_descriptor)
        temporary_metadata = os.fstat(temporary_descriptor)
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or stat.S_IMODE(temporary_metadata.st_mode) != source_mode
            or temporary_metadata.st_size != len(payload)
        ):
            _fail(f"{label} rendered output is unsafe")

        current_descriptor = _open_descriptor(
            name,
            _open_flags(os.O_RDONLY, nonblocking=True),
            dir_fd=directory.descriptor,
        )
        current_metadata = os.fstat(current_descriptor)
        if not stat.S_ISREG(current_metadata.st_mode):
            _fail(f"{label} source entry is no longer a regular file")
        if _identity(current_metadata) != source_snapshot.source_identity:
            _fail(f"{label} source entry changed after its authenticated snapshot")
        _close(current_descriptor)
        current_descriptor = None

        os.rename(
            temporary_name,
            name,
            src_dir_fd=directory.descriptor,
            dst_dir_fd=directory.descriptor,
        )
        renamed = True
        os.fsync(directory.descriptor)
        final_descriptor = _open_descriptor(
            name,
            _open_flags(os.O_RDONLY, nonblocking=True),
            dir_fd=directory.descriptor,
        )
        final_metadata = os.fstat(final_descriptor)
        if (
            not stat.S_ISREG(final_metadata.st_mode)
            or (final_metadata.st_dev, final_metadata.st_ino)
            != (temporary_metadata.st_dev, temporary_metadata.st_ino)
            or stat.S_IMODE(final_metadata.st_mode) != source_mode
            or final_metadata.st_size != len(payload)
        ):
            _fail(f"{label} atomic replacement is unsafe")
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"
    except ValueError:
        raise
    except OSError as exc:
        _fail(f"cannot replace {label}", exc)
    finally:
        _close(final_descriptor)
        _close(current_descriptor)
        _close(temporary_descriptor)
        if temporary_created and not renamed:
            try:
                os.unlink(temporary_name, dir_fd=directory.descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                pass


@contextmanager
def private_snapshot_directory(prefix: str) -> Iterator[PrivateSnapshotDirectory]:
    """Yield a private directory and remove it on every exit path."""

    _require_posix_primitives()
    manager = tempfile.TemporaryDirectory(prefix=prefix)
    root = Path(manager.name)
    descriptor: int | None = None
    try:
        os.chmod(root, 0o700)
        descriptor = _open_directory_chain(
            _normalize_macos_system_alias(root),
            label="private snapshot directory",
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            _fail("private snapshot directory is not an owner-only directory")
    except OSError as exc:
        _close(descriptor)
        manager.cleanup()
        _fail("cannot create private snapshot directory", exc)
    except ValueError:
        _close(descriptor)
        manager.cleanup()
        raise
    directory = PrivateSnapshotDirectory(root, descriptor)
    try:
        yield directory
    finally:
        for name in tuple(directory.snapshots):
            try:
                os.unlink(name, dir_fd=directory.descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        _close(directory.descriptor)
        manager.cleanup()


@contextmanager
def persistent_snapshot_directory(
    path: Path, *, create: bool
) -> Iterator[PrivateSnapshotDirectory]:
    """Hold a private snapshot directory without deleting successful leaves."""

    with secure_directory(path, create=create) as held:
        descriptor: int | None = None
        directory: PrivateSnapshotDirectory | None = None
        try:
            descriptor = os.dup(held.descriptor)
            directory = PrivateSnapshotDirectory(path, descriptor)
            descriptor = None
            yield directory
        finally:
            _close(descriptor)
            if directory is not None:
                _close(directory.descriptor)


def snapshot_regular_file(
    source: Path,
    directory: PrivateSnapshotDirectory,
    name: str,
    *,
    max_bytes: int,
    label: str,
    expected_digest: str | None = None,
    capture_bytes: bool = False,
    source_directory: HeldDirectory | None = None,
) -> FileSnapshot:
    """Stream one immutable view of a regular file into an exclusive snapshot."""

    if not isinstance(source, Path):
        _fail(f"{label} must be a filesystem path")
    if Path(name).name != name or name in {"", ".", ".."}:
        _fail(f"{label} snapshot name is unsafe")
    if type(max_bytes) is not int or max_bytes <= 0:
        _fail(f"{label} snapshot limit is invalid")
    if capture_bytes and max_bytes > MAX_CAPTURE_SIZE:
        _fail(f"{label} capture limit exceeds {MAX_CAPTURE_SIZE} bytes")
    if expected_digest is not None and (
        len(expected_digest) != 71
        or not expected_digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in expected_digest[7:])
    ):
        _fail(f"{label} expected digest is invalid")

    if not isinstance(directory, PrivateSnapshotDirectory):
        _fail(f"{label} snapshot directory is invalid")
    destination = directory.path / name
    source_parent_descriptor: int | None = None
    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    destination_created = False
    succeeded = False
    try:
        if source_directory is None:
            source_parent_descriptor = _open_directory_chain(
                _normalize_macos_system_alias(source.parent),
                label=f"{label} parent",
            )
        else:
            if (
                not isinstance(source_directory, HeldDirectory)
                or source.parent != source_directory.path
            ):
                _fail(f"{label} held source directory does not match its path")
            source_parent_descriptor = os.dup(source_directory.descriptor)
        parent_metadata = os.fstat(source_parent_descriptor)
        if not stat.S_ISDIR(parent_metadata.st_mode):
            _fail(f"{label} parent is not a directory")
        source_descriptor = _open_descriptor(
            source.name,
            _open_flags(os.O_RDONLY, nonblocking=True),
            dir_fd=source_parent_descriptor,
        )
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail(f"{label} is not a regular file")
        if before.st_size <= 0:
            _fail(f"{label} is empty")
        if before.st_size > max_bytes:
            _fail(f"{label} exceeds the {max_bytes}-byte verification limit")

        destination_descriptor = _open_descriptor(
            name,
            _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            0o600,
            dir_fd=directory.descriptor,
        )
        destination_created = True
        digest = hashlib.sha256()
        captured = bytearray() if capture_bytes else None
        total = 0
        while True:
            chunk = os.read(source_descriptor, READ_CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                _fail(f"{label} exceeds the {max_bytes}-byte verification limit")
            digest.update(chunk)
            if captured is not None:
                captured.extend(chunk)
            _write_all(destination_descriptor, chunk)

        after = os.fstat(source_descriptor)
        identity_before = _identity(before)
        identity_after = _identity(after)
        if identity_before != identity_after or total != before.st_size:
            _fail(f"{label} changed while it was being snapshotted")
        actual_digest = f"sha256:{digest.hexdigest()}"
        if expected_digest is not None and actual_digest != expected_digest:
            _fail(
                f"{label} digest mismatch: expected {expected_digest}, got {actual_digest}"
            )

        os.fsync(destination_descriptor)
        os.fchmod(destination_descriptor, 0o400)
        destination_metadata = os.fstat(destination_descriptor)
        if (
            not stat.S_ISREG(destination_metadata.st_mode)
            or stat.S_IMODE(destination_metadata.st_mode) != 0o400
            or destination_metadata.st_size != total
        ):
            _fail(f"{label} private snapshot is unsafe")
        _close(destination_descriptor)
        destination_descriptor = None
        _close(source_descriptor)
        source_descriptor = None
        _close(source_parent_descriptor)
        source_parent_descriptor = None
        directory.snapshots.add(name)
        succeeded = True
        return FileSnapshot(
            destination,
            actual_digest,
            total,
            bytes(captured) if captured is not None else None,
            identity_before,
        )
    except ValueError:
        raise
    except OSError as exc:
        _fail(f"cannot snapshot {label}", exc)
    finally:
        _close(destination_descriptor)
        _close(source_descriptor)
        _close(source_parent_descriptor)
        if destination_created and not succeeded:
            try:
                os.unlink(name, dir_fd=directory.descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                pass


def read_regular_bytes(
    source: Path,
    *,
    max_bytes: int,
    label: str,
    expected_digest: str | None = None,
) -> bytes:
    """Read bounded regular-file bytes through the same snapshot primitive."""

    with private_snapshot_directory("mlx90-read-snapshot-") as directory:
        snapshot = snapshot_regular_file(
            source,
            directory,
            "payload",
            max_bytes=max_bytes,
            label=label,
            expected_digest=expected_digest,
            capture_bytes=True,
        )
        assert snapshot.payload is not None
        return snapshot.payload


def capture_regular_file(
    source: Path,
    *,
    max_bytes: int,
    label: str,
) -> dict[str, str | int]:
    """Return one bounded regular-file snapshot as transport-safe JSON fields."""

    payload = read_regular_bytes(
        source,
        max_bytes=max_bytes,
        label=label,
    )
    return {
        "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        "payloadBase64": base64.b64encode(payload).decode("ascii"),
        "size": len(payload),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--source", type=Path, required=True)
    capture.add_argument("--max-bytes", type=int, required=True)
    capture.add_argument("--label", required=True)
    args = parser.parse_args()
    try:
        if args.command == "capture":
            print(
                json.dumps(
                    capture_regular_file(
                        args.source,
                        max_bytes=args.max_bytes,
                        label=args.label,
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
            return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
