"""DNSSEC : le domaine publie-t-il un enregistrement DS chez son parent ?"""

from __future__ import annotations

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.dns import resolve
from sonde.core.finding import Finding
from sonde.core.target import Target
from sonde.i18n import N_, _

REF = ["https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"]


class DnssecCheck(BaseCheck):
    id = "email.dnssec"
    name = N_("DNSSEC")
    category = "email"
    order = 80

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        ds = await resolve(ctx, target.domain, "DS")
        if ds:
            return [
                self.finding(
                    "ok",
                    _("DNSSEC enabled"),
                    _(
                        "The domain's DNS answers are signed: they are hard to forge in order "
                        "to redirect your visitors or your mail."
                    ),
                    evidence="\n".join(r.to_text() for r in ds[:3]),
                    references=REF,
                )
            ]
        return [
            self.finding(
                "info",
                _("DNSSEC not enabled"),
                _(
                    "The domain's DNS answers are not signed. This is not a flaw in itself, but "
                    "DNSSEC protects against forged records (website, email, SPF/DKIM/DMARC)."
                ),
                fix=_(
                    "Enable DNSSEC at your DNS host, then publish the provided DS record at your "
                    "registrar."
                ),
                references=REF,
            )
        ]


register(DnssecCheck())
