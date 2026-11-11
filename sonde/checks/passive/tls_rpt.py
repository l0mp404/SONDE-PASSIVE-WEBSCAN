"""TLS-RPT : rapports d'échec de chiffrement des emails."""

from __future__ import annotations

import re

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.dns import txt_records
from sonde.core.finding import Finding
from sonde.core.target import Target
from sonde.i18n import N_, _

REF = ["https://www.rfc-editor.org/rfc/rfc8460"]
_RE = re.compile(r"^v\s*=\s*TLSRPTv1\s*(;|$)", re.IGNORECASE)
_RUA_RE = re.compile(r"rua\s*=\s*((?:mailto:|https:)\S+)", re.IGNORECASE)


class TlsRptCheck(BaseCheck):
    id = "email.tls_rpt"
    name = N_("TLS-RPT")
    category = "email"
    order = 60

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        d = target.domain
        recs = [r for r in await txt_records(ctx, f"_smtp._tls.{d}") if _RE.match(r.strip())]
        if not recs:
            return [
                self.finding(
                    "info",
                    _("TLS-RPT not configured"),
                    _(
                        "TLS-RPT sends daily reports when a sender fails to encrypt an email to "
                        "you. Useful to roll out MTA-STS safely."
                    ),
                    fix=f'_smtp._tls.{d}. IN TXT "v=TLSRPTv1; rua=mailto:tls-rpt@{d}"',
                    references=REF,
                )
            ]
        rec = recs[0]
        if len(recs) > 1 or not _RUA_RE.search(rec):
            why = _("several records") if len(recs) > 1 else _("“rua” address missing or invalid")
            return [
                self.finding(
                    "warn",
                    _("TLS-RPT: invalid record"),
                    _("The TLS-RPT record is unusable ({reason}).", reason=why),
                    fix=f'_smtp._tls.{d}. IN TXT "v=TLSRPTv1; rua=mailto:tls-rpt@{d}"',
                    evidence="\n".join(recs),
                    references=REF,
                )
            ]
        return [
            self.finding(
                "ok",
                _("TLS-RPT configured"),
                _("You receive reports about encryption failures of incoming email."),
                evidence=rec,
                references=REF,
            )
        ]


register(TlsRptCheck())
