"""Cookies posés par la page d'accueil : Secure, HttpOnly, SameSite."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.finding import Finding, Severity, worst
from sonde.core.http import fetch_home
from sonde.core.target import Target
from sonde.i18n import N_, _

REF = [
    "https://developer.mozilla.org/docs/Web/HTTP/Cookies#security",
    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
]


@dataclass
class Cookie:
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    raw: str = ""
    missing: list[str] = field(default_factory=list)


def parse_set_cookie(value: str) -> Cookie:
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    c = Cookie(name=name, raw=value)
    for attr in parts[1:]:
        key, _sep, val = attr.partition("=")
        key = key.strip().lower()
        if key == "secure":
            c.secure = True
        elif key == "httponly":
            c.httponly = True
        elif key == "samesite":
            c.samesite = val.strip().lower() or "invalid"
    if name.startswith("__Secure-") or name.startswith("__Host-"):
        c.secure = c.secure or False  # le navigateur rejette le cookie si Secure manque
    return c


class CookiesCheck(BaseCheck):
    id = "web.cookies"
    name = N_("Cookies")
    category = "web"
    order = 5

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        try:
            home = await fetch_home(ctx, target)
        except httpx.HTTPError:
            return []
        raws: list[str] = []
        for resp in home.all_responses:
            raws.extend(resp.headers.get_list("set-cookie"))
        if not raws:
            return [
                self.finding(
                    "ok",
                    _("No cookie set on the home page"),
                    _(
                        "The home page sets no cookie; nothing to secure here. Session cookies "
                        "often appear after login, which is not tested."
                    ),
                    references=REF,
                )
            ]
        cookies = [parse_set_cookie(r) for r in raws]
        findings: list[Finding] = []
        for c in cookies:
            findings.append(self._cookie_finding(c))
        return findings

    def _cookie_finding(self, c: Cookie) -> Finding:
        issues: list[tuple[Severity, str, str]] = []
        if not c.secure:
            issues.append(
                (
                    Severity.WARN,
                    _("Secure missing"),
                    _("the cookie may be sent in clear text over http:// and intercepted"),
                )
            )
        if not c.httponly:
            issues.append(
                (
                    Severity.WARN,
                    _("HttpOnly missing"),
                    _("an injected script (XSS) can read the cookie and steal the session"),
                )
            )
        if c.samesite is None:
            issues.append(
                (
                    Severity.INFO,
                    _("SameSite not specified"),
                    _("browsers apply “Lax” by default, better make it explicit"),
                )
            )
        elif c.samesite == "none" and not c.secure:
            issues.append(
                (
                    Severity.WARN,
                    _("SameSite=None without Secure"),
                    _("combination rejected by modern browsers"),
                )
            )
        elif c.samesite == "invalid":
            issues.append((Severity.INFO, _("Empty SameSite"), _("value ignored by browsers")))

        ev = f"Set-Cookie: {c.raw[:200]}"
        if not issues:
            return self.finding(
                "ok",
                _("Cookie “{name}” properly protected", name=c.name),
                _("The cookie is marked Secure, HttpOnly and SameSite."),
                evidence=ev,
                references=REF,
            )
        sev = worst([s for s, _lbl, _why in issues])
        labels = ", ".join(lbl for _sev, lbl, _why in issues)
        explain = "; ".join(f"{lbl}: {why}" for _sev, lbl, why in issues)
        wanted = [a for a in ("Secure", "HttpOnly") if a.lower() not in c.raw.lower()]
        if c.samesite is None:
            wanted.append("SameSite=Lax")
        fix = (
            f"Set-Cookie: {c.name}=…; Path=/; {'; '.join(wanted)}\n"
            "# PHP: session.cookie_secure=1, session.cookie_httponly=1, "
            "session.cookie_samesite=Lax\n"
            "# Nginx (proxy): proxy_cookie_flags ~ secure httponly samesite=lax;"
        )
        return self.finding(
            sev,
            _("Cookie “{name}”: {labels}", name=c.name, labels=labels),
            _(
                "The cookie “{name}” lacks some protection attributes ({explain}). For a mere "
                "preference cookie the impact is low; for a session cookie it matters.",
                name=c.name,
                explain=explain,
            ),
            fix=fix,
            evidence=ev,
            references=REF,
        )


register(CookiesCheck())
