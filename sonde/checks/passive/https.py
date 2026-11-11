"""HTTPS : redirection HTTP→HTTPS (chaîne, codes) et HSTS."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

import httpx

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.finding import Finding
from sonde.core.http import fetch_home
from sonde.core.target import Target
from sonde.i18n import N_, _

REF_REDIRECT = [
    "https://developer.mozilla.org/docs/Web/HTTP/Redirections",
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
]
REF_HSTS = [
    "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
    "https://hstspreload.org/",
]
MAX_HOPS = 5
SIX_MONTHS = 15_552_000
ONE_YEAR = 31_536_000

NGINX_FIX = (
    "# Nginx\nserver {{\n    listen 80;\n    server_name {d} www.{d};\n"
    "    return 301 https://$host$request_uri;\n}}"
)
# NGINX_FIX passe par str.format (accolades doublées) ; APACHE_FIX est utilisé tel quel.
APACHE_FIX = (
    "# Apache (.htaccess / VirtualHost :80)\nRewriteEngine On\n"
    "RewriteCond %{HTTPS} off\n"
    "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]"
)


class HttpsCheck(BaseCheck):
    id = "web.https"
    name = N_("HTTPS redirect + HSTS")
    category = "web"
    order = 1

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._redirect(target, ctx))
        findings.extend(await self._hsts(target, ctx))
        return findings

    # ------------------------------------------------------------ HTTP -> HTTPS

    async def _redirect(self, target: Target, ctx: Context) -> list[Finding]:
        d = target.domain
        fix = NGINX_FIX.format(d=d) + "\n\n" + APACHE_FIX
        chain: list[str] = []
        url = target.http_url
        try:
            for _hop in range(MAX_HOPS):
                resp = await ctx.http.get(url, follow_redirects=False)
                location = resp.headers.get("location")
                chain.append(f"{resp.status_code} {url}" + (f" → {location}" if location else ""))
                if not (300 <= resp.status_code < 400 and location):
                    break
                url = urljoin(url, location)
                if urlsplit(url).scheme == "https":
                    break
            else:
                return [
                    self.finding(
                        "warn",
                        _("HTTP: too many redirects"),
                        _("More than {n} redirects without reaching HTTPS.", n=MAX_HOPS),
                        fix=fix,
                        evidence="\n".join(chain),
                        references=REF_REDIRECT,
                    )
                ]
        except httpx.HTTPError as exc:
            return [
                self.finding(
                    "info",
                    _("HTTP (port 80) does not respond"),
                    _(
                        "The site cannot be reached over http://. This is not a vulnerability, "
                        "but a visitor typing the domain without “https://” will get an error "
                        "instead of being redirected."
                    ),
                    fix=_("Open port 80 with a simple 301 redirect to HTTPS:") + "\n" + fix,
                    evidence=f"{target.http_url} → {type(exc).__name__}",
                    references=REF_REDIRECT,
                )
            ]

        final = urlsplit(url)
        evidence = "\n".join(chain)
        if final.scheme != "https":
            return [
                self.finding(
                    "crit",
                    _("The site is served over unencrypted HTTP"),
                    _(
                        "The http:// version of the site answers without redirecting to "
                        "https://. Visitors can browse in clear text: passwords, forms and pages "
                        "can be read and modified by a third party on the network."
                    ),
                    fix=fix,
                    evidence=evidence,
                    references=REF_REDIRECT,
                )
            ]

        first_code = int(chain[0].split()[0])
        out = []
        if first_code in (302, 303, 307):
            out.append(
                self.finding(
                    "info",
                    _("Temporary HTTPS redirect ({code})", code=first_code),
                    _(
                        "The redirect to HTTPS works but uses a “temporary” status code. A "
                        "permanent code (301 or 308) is better remembered by browsers and "
                        "search engines."
                    ),
                    fix=fix,
                    evidence=evidence,
                    references=REF_REDIRECT,
                )
            )
        if len(chain) > 1:  # la chaîne s'arrête dès l'arrivée en HTTPS
            out.append(
                self.finding(
                    "info",
                    _("Chain of {n} redirects before HTTPS", n=len(chain)),
                    _(
                        "Several hops are needed before reaching HTTPS; each HTTP hop is a "
                        "chance for interception. A single redirect is enough."
                    ),
                    fix=fix,
                    evidence=evidence,
                    references=REF_REDIRECT,
                )
            )
        if not out:
            out.append(
                self.finding(
                    "ok",
                    _("HTTP → HTTPS redirect in place"),
                    _(
                        "A visitor arriving over http:// is immediately sent to the encrypted "
                        "version of the site."
                    ),
                    evidence=evidence,
                    references=REF_REDIRECT,
                )
            )
        return out

    # ------------------------------------------------------------ HSTS

    async def _hsts(self, target: Target, ctx: Context) -> list[Finding]:
        try:
            home = await fetch_home(ctx, target)
        except httpx.HTTPError as exc:
            return [
                self.finding(
                    "crit",
                    _("Site unreachable over HTTPS"),
                    _(
                        "The https:// version of the site does not respond: encrypted browsing "
                        "is impossible."
                    ),
                    fix=_("Check that the server listens on port 443 with a valid certificate."),
                    evidence=f"{target.url} → {type(exc).__name__}: {exc}",
                    references=REF_HSTS,
                )
            ]
        if home.response.url.scheme != "https":
            return [
                self.finding(
                    "crit",
                    _("HTTPS redirects to HTTP"),
                    _("The secure version of the site sends the visitor to the unencrypted one."),
                    fix=_("Remove the redirect to http://; serve the whole site over HTTPS."),
                    evidence=" → ".join(str(r.url) for r in home.all_responses),
                    references=REF_HSTS,
                )
            ]

        hsts_fix = (
            "# Nginx\nadd_header Strict-Transport-Security "
            '"max-age=31536000; includeSubDomains" always;\n\n'
            "# Apache\nHeader always set Strict-Transport-Security "
            '"max-age=31536000; includeSubDomains"'
        )
        # HSTS ne compte que sur une réponse HTTPS ; on prend la première réponse https.
        https_resp = next(r for r in home.all_responses if r.url.scheme == "https")
        value = https_resp.headers.get("strict-transport-security")
        if not value:
            return [
                self.finding(
                    "warn",
                    _("HSTS missing"),
                    _(
                        "Without HSTS, the browser tries http:// again on every visit typed by "
                        "hand; an attacker on the network can intercept that first exchange "
                        "before the redirect."
                    ),
                    fix=hsts_fix,
                    evidence=_("{url}: no Strict-Transport-Security header", url=https_resp.url),
                    references=REF_HSTS,
                )
            ]
        m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
        if not m:
            return [
                self.finding(
                    "warn",
                    _("Invalid HSTS (max-age missing)"),
                    _("The HSTS header is present but has no duration: browsers ignore it."),
                    fix=hsts_fix,
                    evidence=f"Strict-Transport-Security: {value}",
                    references=REF_HSTS,
                )
            ]
        max_age = int(m.group(1))
        subdomains = bool(re.search(r"includesubdomains", value, re.IGNORECASE))
        preload = bool(re.search(r"\bpreload\b", value, re.IGNORECASE))
        ev = f"Strict-Transport-Security: {value}"
        out = []
        if max_age == 0:
            out.append(
                self.finding(
                    "warn",
                    _("HSTS disabled (max-age=0)"),
                    _("max-age=0 tells browsers to forget HSTS: no protection."),
                    fix=hsts_fix,
                    evidence=ev,
                    references=REF_HSTS,
                )
            )
        elif max_age < SIX_MONTHS:
            out.append(
                self.finding(
                    "warn",
                    _("HSTS too short ({seconds} s)", seconds=max_age),
                    _(
                        "The HSTS duration is under 6 months: the protection fades quickly "
                        "between visits. Recommendation: at least 1 year."
                    ),
                    fix=hsts_fix,
                    evidence=ev,
                    references=REF_HSTS,
                )
            )
        else:
            detail = _("Browsers that have already visited the site will refuse any unencrypted "
                       "connection.")  # fmt: skip
            if not subdomains:
                detail += " " + _("Subdomains are not covered (includeSubDomains missing).")
            if preload:
                detail += " " + _("The site is a candidate for the browsers' preload list.")
            out.append(
                self.finding(
                    "ok",
                    _("HSTS enabled (preload)") if preload else _("HSTS enabled"),
                    detail,
                    evidence=ev,
                    references=REF_HSTS,
                )
            )
            if not subdomains:
                out.append(
                    self.finding(
                        "info",
                        _("HSTS without includeSubDomains"),
                        _(
                            "Subdomains (www, api, …) do not benefit from HSTS. Add it if all "
                            "subdomains are served over HTTPS."
                        ),
                        fix=hsts_fix,
                        evidence=ev,
                        references=REF_HSTS,
                    )
                )
        return out


register(HttpsCheck())
