"""MX : présence et fournisseur de messagerie."""

from __future__ import annotations

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.dns import mx_records
from sonde.core.finding import Finding
from sonde.core.target import Target
from sonde.i18n import N_, _

# suffixe d'hôte MX -> fournisseur
PROVIDERS: list[tuple[str, str]] = [
    ("aspmx.l.google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("google.com", "Google Workspace"),
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("outlook.com", "Microsoft 365"),
    ("pphosted.com", "Proofpoint"),
    ("ppe-hosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("barracudanetworks.com", "Barracuda"),
    ("mail.ovh.net", "OVHcloud"),
    ("mx.ovh.net", "OVHcloud"),
    ("ovh.net", "OVHcloud"),
    ("mail.gandi.net", "Gandi"),
    ("ionos.fr", "IONOS"),
    ("ionos.com", "IONOS"),
    ("kundenserver.de", "IONOS"),
    ("zoho.com", "Zoho Mail"),
    ("zoho.eu", "Zoho Mail"),
    ("protonmail.ch", "Proton Mail"),
    ("messagingengine.com", "Fastmail"),
    ("mailgun.org", "Mailgun"),
    ("o2switch.net", "o2switch"),
    ("ik.me", "Infomaniak"),
    ("infomaniak.ch", "Infomaniak"),
    ("icloud.com", "iCloud Mail"),
    ("yahoodns.net", "Yahoo"),
    ("secureserver.net", "GoDaddy"),
    ("registrar-servers.com", "Namecheap"),
    ("orange.fr", "Orange"),
    ("wanadoo.fr", "Orange"),
    ("free.fr", "Free"),
    ("sfr.fr", "SFR"),
]


def identify_provider(hosts: list[str]) -> str | None:
    for host in hosts:
        for suffix, name in PROVIDERS:
            if host == suffix or host.endswith("." + suffix):
                return name
    return None


class MxCheck(BaseCheck):
    id = "email.mx"
    name = N_("MX (incoming email)")
    category = "email"
    order = 10

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        records = await mx_records(ctx, target.domain)
        ref = [
            "https://www.rfc-editor.org/rfc/rfc5321#section-5",
            "https://www.rfc-editor.org/rfc/rfc7505",
        ]

        if not records:
            return [
                self.finding(
                    "info",
                    _("No MX record"),
                    _(
                        "This domain declares no server to receive email. That is normal if it "
                        "is not used for email; it must still be protected against spoofing "
                        "(SPF “-all” and DMARC “reject”)."
                    ),
                    fix=f"{target.domain}. IN MX 0 .   ; "
                    + _("“null MX”: explicitly declares that no email is accepted"),
                    references=ref,
                )
            ]

        if len(records) == 1 and records[0][1] == "":
            return [
                self.finding(
                    "info",
                    _("Domain configured to receive no email (null MX)"),
                    _(
                        "The domain explicitly states that it accepts no email. Good practice "
                        "for a domain that neither sends nor receives messages."
                    ),
                    evidence="MX 0 .",
                    references=ref,
                )
            ]

        hosts = [h for _pref, h in records if h]
        provider = identify_provider(hosts)
        evidence = "\n".join(f"{pref} {host}" for pref, host in records)
        title = (
            _("Mail servers (MX) present — provider: {provider}", provider=provider)
            if provider
            else _("Mail servers (MX) present")
        )
        detail = (
            _("The domain can receive email, via {provider}.", provider=provider)
            if provider
            else _("The domain can receive email; the provider could not be identified.")
        )
        if len(hosts) == 1:
            detail += " " + _(
                "A single MX server is declared: during an outage, email depends on senders "
                "retrying (acceptable with large providers that handle redundancy internally)."
            )
        return [self.finding("ok", title, detail, evidence=evidence, references=ref)]


register(MxCheck())
