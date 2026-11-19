"""Cookies posés par la page d'accueil : Secure, HttpOnly, SameSite.

La gravité dépend du rôle du cookie, deviné d'après son nom uniquement (aucune requête
supplémentaire : on ne lit que les en-têtes Set-Cookie de la page d'accueil, déjà en cache).
"""

from __future__ import annotations

import math
import re
from urllib.parse import unquote
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum

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


class Kind(StrEnum):
    SESSION = "session"  # session / authentification : vol = prise de compte
    CSRF = "csrf"  # jeton anti-CSRF : souvent lu par le JS exprès (pas de HttpOnly attendu)
    THIRD_PARTY = "third_party"  # mesure d'audience, pub, CDN / anti-bot
    PREFERENCE = "preference"  # langue, consentement, thème…
    UNKNOWN = "unknown"


# Ordre important : le premier motif qui correspond gagne.
_KIND_PATTERNS: list[tuple[Kind, re.Pattern[str]]] = [
    (
        Kind.THIRD_PARTY,
        re.compile(
            r"^(_ga|_gid|_gat|_gcl_|_fbp|_fbc|_hj|__utm|_clck|_clsk|_pk_|_uet|mp_|ajs_|__hs"
            r"|hubspot|_ttp|_pin_|__cf_bm|cf_clearance|_cfuvid|awsalb|__stripe_|nr_)",
            re.I,
        ),
    ),
    (Kind.CSRF, re.compile(r"(xsrf|csrf)", re.I)),
    (
        Kind.PREFERENCE,
        re.compile(
            r"^(lang|locale|language|currency|pll_language|wp-settings|cookielawinfo"
            r"|viewed_cookie_policy|cookieconsent|cookie_consent|cmplz_|tarteaucitron"
            r"|axeptio|didomi|euconsent|theme)",
            re.I,
        ),
    ),
    (
        Kind.SESSION,
        re.compile(
            r"^(phpsessid|jsessionid|asp\.net_sessionid|aspsessionid\w*|connect\.sid|sid"
            r"|cfid|cftoken|\.aspnetcore\.\w+|\.aspxauth)$"
            r"|^(wordpress_logged_in_|wordpress_sec_|wp_woocommerce_session_|prestashop-)"
            r"|sess|auth|token|jwt|login|remember",
            re.I,
        ),
    ),
]


def classify(name: str) -> Kind:
    for kind, pattern in _KIND_PATTERNS:
        if pattern.search(name):
            return kind
    return Kind.UNKNOWN


# Heuristique sur la valeur, pour les noms inconnus : un identifiant de session est long,
# d'apparence aléatoire. Seuils volontairement prudents (faux positif = un warn, pas un crit).
_TOKEN_CHARS = re.compile(r"^[A-Za-z0-9_\-+/=.~]+$")
_JWT = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
MIN_TOKEN_LEN = 20
MIN_ENTROPY = 3.3  # bits/caractère ; hex aléatoire ≈ 3,7-4, base64 ≈ 4,5-5,5


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(k / n * math.log2(k / n) for k in Counter(s).values())


def looks_like_secret(value: str) -> bool:
    # Décodée d'abord : du JSON ou une liste encodés (%7B, %2C…) ne passent plus le filtre.
    v = unquote(value.strip().strip('"'))
    if _JWT.match(v):
        return True
    if len(v) < MIN_TOKEN_LEN or not _TOKEN_CHARS.match(v) or v.isdigit():
        return False
    return shannon_entropy(v) >= MIN_ENTROPY


def mask(raw: str) -> str:
    """Set-Cookie sans la valeur : un rapport partagé ne doit pas fuiter une session."""
    first, sep, rest = raw.partition(";")
    name, eq, value = first.partition("=")
    if not eq:
        return raw
    value = value.strip()
    shown = value[:4] + "…" if len(value) > 8 else "…" if value else ""
    return f"{name.strip()}={shown}{sep}{rest}"


@dataclass
class Cookie:
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    raw: str = ""
    missing: list[str] = field(default_factory=list)
    kind: Kind = Kind.UNKNOWN
    guessed: bool = False  # session déduite de la valeur, pas du nom
    value_len: int = 0


def parse_set_cookie(value: str) -> Cookie:
    parts = [p.strip() for p in value.split(";")]
    name, _eq, cval = parts[0].partition("=") if parts else ("", "", "")
    name = name.strip()
    c = Cookie(name=name, raw=value, kind=classify(name), value_len=len(cval.strip()))
    if c.kind is Kind.UNKNOWN and looks_like_secret(cval):
        c.kind, c.guessed = Kind.SESSION, True
    for attr in parts[1:]:
        key, _sep, val = attr.partition("=")
        key = key.strip().lower()
        if key == "secure":
            c.secure = True
        elif key == "httponly":
            c.httponly = True
        elif key == "samesite":
            c.samesite = val.strip().lower() or "invalid"
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
        if c.name.startswith(("__Secure-", "__Host-")) and not c.secure:
            issues.append(
                (
                    Severity.WARN,
                    _("{prefix} prefix without Secure", prefix=c.name.split("-", 1)[0] + "-"),
                    _("the browser rejects this cookie outright"),
                )
            )
        elif not c.secure:
            issues.append(
                (
                    Severity.WARN,
                    _("Secure missing"),
                    _("the cookie may be sent in clear text over http:// and intercepted"),
                )
            )
        # Un jeton anti-CSRF « double submit » doit être lisible par le JS : HttpOnly
        # absent est voulu, on ne le signale pas.
        if not c.httponly and c.kind is not Kind.CSRF:
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

        ev = f"Set-Cookie: {mask(c.raw)[:200]}"
        if not issues:
            return self.finding(
                "ok",
                _("Cookie “{name}” properly protected", name=c.name),
                _("The cookie is marked Secure, HttpOnly and SameSite."),
                evidence=ev,
                references=REF,
            )
        sev = _severity_for(c, issues)
        labels = ", ".join(lbl for _sev, lbl, _why in issues)
        explain = "; ".join(f"{lbl}: {why}" for _sev, lbl, why in issues)
        wanted = []
        if not c.secure:
            wanted.append("Secure")
        if not c.httponly and c.kind is not Kind.CSRF:
            wanted.append("HttpOnly")
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
            _detail(c, explain),
            fix=fix,
            evidence=ev,
            references=REF,
        )


def _severity_for(c: Cookie, issues: list[tuple[Severity, str, str]]) -> Severity:
    sev = worst([s for s, _lbl, _why in issues])
    if c.kind in (Kind.THIRD_PARTY, Kind.PREFERENCE):
        # Pas de secret dedans : on informe, sans pénaliser le score.
        return min(sev, Severity.INFO, key=lambda s: s.rank)
    if c.kind is Kind.SESSION and c.guessed:
        # Simple soupçon d'après la valeur : jamais plus que warn.
        return min(sev, Severity.WARN, key=lambda s: s.rank)
    if c.kind is Kind.SESSION and not c.secure and not c.httponly:
        # Session interceptable en clair ET lisible par une XSS.
        return Severity.CRIT
    return sev


def _detail(c: Cookie, explain: str) -> str:
    if c.kind is Kind.SESSION and c.guessed:
        return _(
            "“{name}” has a random-looking value of {length} characters, probably a session "
            "identifier or token ({explain}). If so, whoever steals it takes over the session.",
            name=c.name,
            length=c.value_len,
            explain=explain,
        )
    if c.kind is Kind.SESSION:
        return _(
            "“{name}” looks like a session or authentication cookie ({explain}). Whoever "
            "steals it takes over the user's session: fix it as a priority.",
            name=c.name,
            explain=explain,
        )
    if c.kind is Kind.CSRF:
        return _(
            "“{name}” looks like an anti-CSRF token ({explain}). It is normal for the page's "
            "JavaScript to read it, so HttpOnly is not required.",
            name=c.name,
            explain=explain,
        )
    if c.kind is Kind.THIRD_PARTY:
        return _(
            "“{name}” looks like an analytics, advertising or CDN cookie ({explain}). It holds "
            "no session: low impact, often set by a third-party tool.",
            name=c.name,
            explain=explain,
        )
    if c.kind is Kind.PREFERENCE:
        return _(
            "“{name}” looks like a preference cookie (language, consent, theme…) ({explain}). "
            "It holds no secret: low impact.",
            name=c.name,
            explain=explain,
        )
    return _(
        "The cookie “{name}” lacks some protection attributes ({explain}). For a mere "
        "preference cookie the impact is low; for a session cookie it matters.",
        name=c.name,
        explain=explain,
    )


register(CookiesCheck())
