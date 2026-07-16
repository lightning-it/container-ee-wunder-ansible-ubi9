#!/usr/bin/env python3
"""Run ansible-galaxy with a UBI 9 TLS compatibility guard.

Current UBI 9 OpenSSL packages expose CPython issue 151504: loading even a
valid DER certificate through SSLContext.load_verify_locations(cadata=...)
raises ASN1_R_NOT_ENOUGH_DATA. Ansible's URL helper uses that path while
augmenting the system trust store.

Using the distribution's PEM bundle as an explicit CA file avoids the broken
DER path while preserving normal certificate and hostname verification. Remove
this guard after the corrected CPython packages reach UBI 9.
"""

from __future__ import annotations

import os
import re
import ssl
import sys
from collections.abc import Sequence

from ansible.module_utils import urls


_original_make_context = urls.make_context


def _make_context(
    cafile: str | None = None,
    cadata: bytearray | None = None,
    capath: str | None = None,
    ciphers: Sequence[str] | None = None,
    validate_certs: bool = True,
    client_cert: str | None = None,
    client_key: str | None = None,
) -> ssl.SSLContext:
    """Prefer the verified system PEM bundle when no custom trust is supplied."""

    if validate_certs and not cafile and not cadata and not capath:
        candidates = (
            ssl.get_default_verify_paths().cafile,
            "/etc/pki/tls/certs/ca-bundle.crt",
        )
        cafile = next(
            (path for path in candidates if path and os.path.isfile(path)),
            None,
        )

    return _original_make_context(
        cafile=cafile,
        cadata=cadata,
        capath=capath,
        ciphers=ciphers,
        validate_certs=validate_certs,
        client_cert=client_cert,
        client_key=client_key,
    )


urls.make_context = _make_context

from ansible.cli.galaxy import main  # noqa: E402


if __name__ == "__main__":
    sys.argv[0] = re.sub(r"(-script\.pyw|\.exe)?$", "", sys.argv[0])
    sys.exit(main())
