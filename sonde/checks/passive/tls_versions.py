"""Versions TLS acceptées par le serveur (1.0 / 1.1 / 1.2 / 1.3)."""

from __future__ import annotations

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.finding import Finding
from sonde.core.target import Target
from sonde.core.tls import probe
from sonde.i18n import N_, _

REF = [
    "https://www.rfc-editor.org/rfc/rfc8996",
    "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-tls",
]
FIX = "# Nginx\nssl_protocols TLSv1.2 TLSv1.3;\n\n# Apache\nSSLProtocol -all +TLSv1.2 +TLSv1.3"


class TlsVersionsCheck(BaseCheck):
    id = "web.tls_versions"
    name = N_("TLS versions")
    category = "web"
    order = 3

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        report = await probe(ctx, target)
        v = report.versions
        if all(r is None for r in v.values()):
            raise RuntimeError(_("no TLS version could be tested from this machine"))

        accepted = [name for name, ok in v.items() if ok]
        untestable = [name for name, ok in v.items() if ok is None]
        status = {True: _("accepted"), False: _("refused"), None: _("not testable")}
        evidence = "\n".join(f"{name}: {status[ok]}" for name, ok in v.items())
        if report.handshake and report.handshake.protocol:
            evidence += "\n" + _("Negotiated by default: {protocol}",
                                 protocol=report.handshake.protocol)  # fmt: skip
            if report.handshake.cipher:
                evidence += f" ({report.handshake.cipher})"

        old = [n for n in ("TLS 1.0", "TLS 1.1") if v.get(n)]
        modern = [n for n in ("TLS 1.2", "TLS 1.3") if v.get(n)]
        findings: list[Finding] = []

        if not modern and old:
            findings.append(
                self.finding(
                    "crit",
                    _("Only obsolete TLS versions are accepted"),
                    _(
                        "The server accepts neither TLS 1.2 nor TLS 1.3. Recent browsers refuse "
                        "the connection, and old versions have known weaknesses."
                    ),
                    fix=FIX,
                    evidence=evidence,
                    references=REF,
                )
            )
        elif old:
            findings.append(
                self.finding(
                    "warn",
                    _("Obsolete versions accepted: {versions}", versions=", ".join(old)),
                    _(
                        "TLS 1.0 and 1.1 have been deprecated since 2021 (RFC 8996): they rely "
                        "on weakened algorithms. Leaving them enabled lets an attacker force a "
                        "downgraded connection."
                    ),
                    fix=FIX,
                    evidence=evidence,
                    references=REF,
                )
            )
        elif not v.get("TLS 1.3") and v.get("TLS 1.2"):
            findings.append(
                self.finding(
                    "info",
                    _("TLS 1.3 not offered"),
                    _(
                        "Only TLS 1.2 is accepted. That is safe, but TLS 1.3 is faster and "
                        "removes fragile options."
                    ),
                    fix=FIX,
                    evidence=evidence,
                    references=REF,
                )
            )
        elif modern:
            findings.append(
                self.finding(
                    "ok",
                    _("TLS versions: {versions}", versions=", ".join(accepted)),
                    _("Only modern TLS versions are accepted."),
                    evidence=evidence,
                    references=REF,
                )
            )
        else:
            findings.append(
                self.finding(
                    "info",
                    _("TLS versions not determined"),
                    _("No version could be confirmed from this machine."),
                    evidence=evidence,
                    references=REF,
                )
            )

        if untestable and findings[0].severity != "info":
            findings.append(
                self.finding(
                    "info",
                    _("Not testable locally: {versions}", versions=", ".join(untestable)),
                    _("This machine's TLS library cannot test these versions."),
                    evidence=evidence,
                    references=REF,
                )
            )
        return findings


register(TlsVersionsCheck())
