"""Checks passifs. Importer ce paquet enregistre les checks."""

from sonde.checks.passive import (  # noqa: F401
    bimi,
    cert,
    cookies,
    dkim,
    dmarc,
    dnssec,
    extras,
    headers,
    https,
    leaks,
    mixed_content,
    mta_sts,
    mx,
    security_txt,
    spf,
    tls_rpt,
    tls_versions,
)
