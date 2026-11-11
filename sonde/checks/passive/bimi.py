"""BIMI : logo de marque affiché dans les clients mail (optionnel)."""

from __future__ import annotations

import re

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.dns import txt_records
from sonde.core.finding import Finding
from sonde.core.target import Target
from sonde.i18n import N_, _

REF = [
    "https://bimigroup.org/",
    "https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/",
]
_RE = re.compile(r"^v\s*=\s*BIMI1\s*(;|$)", re.IGNORECASE)


class BimiCheck(BaseCheck):
    id = "email.bimi"
    name = N_("BIMI")
    category = "email"
    order = 70

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        d = target.domain
        recs = [r for r in await txt_records(ctx, f"default._bimi.{d}") if _RE.match(r.strip())]
        if not recs:
            return [
                self.finding(
                    "info",
                    _("BIMI not configured"),
                    _(
                        "BIMI shows your brand logo in the inbox of compatible recipients. "
                        "Purely optional: it requires a strict DMARC (quarantine/reject) and, "
                        "for Gmail/Apple, a mark certificate."
                    ),
                    references=REF,
                )
            ]
        rec = recs[0]
        tags = {}
        for part in rec.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        logo = tags.get("l", "")
        if not logo.lower().startswith("https://"):
            return [
                self.finding(
                    "warn",
                    _("BIMI: logo (l=) missing or not HTTPS"),
                    _("The BIMI record must point to an SVG logo served over HTTPS."),
                    fix=f'default._bimi.{d}. IN TXT "v=BIMI1; l=https://{d}/logo.svg;"',
                    evidence=rec,
                    references=REF,
                )
            ]
        return [
            self.finding(
                "ok",
                _("BIMI configured"),
                _("A brand logo is declared for display in mail clients.")
                + (
                    ""
                    if tags.get("a")
                    else " " + _("Without a certificate (a=), some clients will not show it.")
                ),
                evidence=rec,
                references=REF,
            )
        ]


register(BimiCheck())
