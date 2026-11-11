"""/.well-known/security.txt (RFC 9116)."""

from __future__ import annotations

import re
from datetime import UTC, datetime

import httpx

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.finding import Finding
from sonde.core.http import fetch_text
from sonde.core.target import Target
from sonde.i18n import N_, _, get_lang

REF = ["https://www.rfc-editor.org/rfc/rfc9116", "https://securitytxt.org/"]


def parse_fields(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            out.setdefault(k.strip().lower(), []).append(v.strip())
    return out


def _parse_expires(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class SecurityTxtCheck(BaseCheck):
    id = "web.security_txt"
    name = N_("security.txt")
    category = "web"
    order = 7

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        d = target.domain
        url = f"https://{d}/.well-known/security.txt"
        template = (
            f"# {url}\nContact: mailto:security@{d}\n"
            f"Expires: {datetime.now(UTC).year + 1}-01-01T00:00:00.000Z\n"
            f"Preferred-Languages: {'fr, en' if get_lang() == 'fr' else 'en'}\n"
            f"Policy: https://{d}/security"
        )
        try:
            resp, text = await fetch_text(ctx, url, max_bytes=64_000)
        except httpx.HTTPError:
            return []  # site injoignable : déjà signalé par web.https

        fields = parse_fields(text) if resp.status_code == 200 else {}
        looks_real = "contact" in fields or "expires" in fields
        if resp.status_code != 200 or not looks_real:
            return [
                self.finding(
                    "info",
                    _("security.txt missing"),
                    _(
                        "This standard file says whom to report a security flaw to. Without "
                        "it, a researcher who finds a problem does not know whom to warn."
                    ),
                    fix=template,
                    evidence=f"{url} → HTTP {resp.status_code}"
                    + (
                        ""
                        if resp.status_code != 200
                        else " " + _("(content without Contact field)")
                    ),
                    references=REF,
                )
            ]

        problems = []
        if "contact" not in fields:
            problems.append(_("Contact field missing (required)"))
        if "expires" not in fields:
            problems.append(_("Expires field missing (required)"))
        else:
            exp = _parse_expires(fields["expires"][0])
            if exp is None:
                problems.append(_("Expires unreadable (ISO 8601 format expected)"))
            elif exp < datetime.now(UTC):
                problems.append(_("file expired since {date}", date=f"{exp:%Y-%m-%d}"))
            elif len(fields["expires"]) > 1:
                problems.append(_("several Expires fields"))
        for c in fields.get("contact", []):
            if not re.match(r"^(mailto:|https://|tel:)", c, re.IGNORECASE):
                problems.append(
                    _("Contact “{value}” must be a URI (mailto:, https:, tel:)", value=c)
                )
        ev = f"{url}\n{text.strip()[:400]}"
        if problems:
            return [
                self.finding(
                    "warn",
                    _("Invalid security.txt"),
                    _(
                        "The file exists but is not compliant: {problems}.",
                        problems="; ".join(problems),
                    ),
                    fix=template,
                    evidence=ev,
                    references=REF,
                )
            ]
        return [
            self.finding(
                "ok",
                _("security.txt present and valid"),
                _("A security contact is published for reporting vulnerabilities."),
                evidence=ev,
                references=REF,
            )
        ]


register(SecurityTxtCheck())
