"""En-têtes de sécurité HTTP de la page d'accueil."""

from __future__ import annotations

import re

import httpx

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.finding import Finding
from sonde.core.http import fetch_home
from sonde.core.target import Target
from sonde.i18n import N_, _

MDN = "https://developer.mozilla.org/docs/Web/HTTP/Headers/"
OWASP = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"


def _fix(name: str, value: str) -> str:
    return (
        f'# Nginx\nadd_header {name} "{value}" always;\n\n'
        f'# Apache\nHeader always set {name} "{value}"'
    )


def parse_csp(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for directive in value.split(";"):
        parts = directive.strip().split()
        if parts:
            out.setdefault(parts[0].lower(), [p.strip().lower() for p in parts[1:]])
    return out


_DANGEROUS = {
    "'unsafe-inline'": N_(
        "'unsafe-inline' allows scripts written in the page: XSS is no longer blocked"
    ),
    "'unsafe-eval'": N_("'unsafe-eval' allows eval(): weakens XSS protection"),
    "*": N_("“*” allows scripts from any site"),
    "http:": N_("“http:” allows unencrypted scripts"),
    "https:": N_("“https:” allows scripts from any HTTPS site"),
    "data:": N_("“data:” allows injecting an inline script"),
}


def csp_script_issues(policies: list[str]) -> list[str]:
    """Problèmes de script-src communs à TOUTES les policies (une seule stricte suffit)."""
    per_policy: list[set[str]] = []
    for raw in policies:
        csp = parse_csp(raw)
        sources = csp.get("script-src", csp.get("default-src"))
        if sources is None:
            per_policy.append({"<absent>"})
            continue
        has_nonce_or_hash = any(
            s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sources
        )
        bad = {s for s in sources if s in _DANGEROUS}
        if has_nonce_or_hash and "'strict-dynamic'" in sources:
            bad.discard("'unsafe-inline'")  # ignoré par les navigateurs dans ce cas
            bad -= {"*", "http:", "https:"}
        per_policy.append(bad)
    common = set.intersection(*per_policy) if per_policy else set()
    if "<absent>" in common:
        return [_("neither script-src nor default-src: scripts are not restricted")]
    return [_(_DANGEROUS[s]) for s in sorted(common - {"<absent>"})]


class HeadersCheck(BaseCheck):
    id = "web.headers"
    name = N_("Security headers")
    category = "web"
    order = 4

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        try:
            home = await fetch_home(ctx, target)
        except httpx.HTTPError:
            return []  # déjà signalé par web.https
        h = home.response.headers
        findings: list[Finding] = []
        findings.extend(self._csp(h))
        findings.append(self._clickjacking(h))
        findings.append(self._nosniff(h))
        findings.append(self._referrer(h))
        findings.append(self._permissions(h))
        findings.extend(self._isolation(h))
        findings.extend(self._legacy(h))
        return findings

    # ------------------------------------------------------------ CSP

    def _csp(self, h: httpx.Headers) -> list[Finding]:
        policies = h.get_list("content-security-policy")
        report_only = h.get_list("content-security-policy-report-only")
        ref = [MDN + "Content-Security-Policy", OWASP]
        fix = _fix(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; object-src 'none'; "
            "frame-ancestors 'self'; base-uri 'self'",
        )
        if not policies:
            if report_only:
                return [
                    self.finding(
                        "warn",
                        _("CSP in “report-only” mode only"),
                        _(
                            "A CSP is defined but only in observation mode: nothing is blocked. "
                            "It is a test step that should be completed."
                        ),
                        fix=_(
                            "Once reports are clean, rename the header to Content-Security-Policy."
                        ),  # fmt: skip
                        evidence="Content-Security-Policy-Report-Only: " + report_only[0][:200],
                        references=ref,
                    )
                ]
            return [
                self.finding(
                    "warn",
                    _("Content-Security-Policy missing"),
                    _(
                        "The CSP tells the browser where the site may load scripts, styles and "
                        "images from. Without it, an injection flaw (XSS) has free rein."
                    ),
                    fix=fix + "\n" + _("# adapt: list the CDNs/domains actually used"),
                    references=ref,
                )
            ]
        evidence = "\n".join("Content-Security-Policy: " + p[:300] for p in policies)
        issues = csp_script_issues(policies)
        out = []
        if issues:
            out.append(
                self.finding(
                    "warn",
                    _("Permissive CSP for scripts"),
                    _(
                        "A CSP is present but its script rules largely cancel its protection: "
                        "{issues}.",
                        issues="; ".join(issues),
                    ),
                    fix=_(
                        "Remove 'unsafe-inline'/'unsafe-eval'/'*' from script-src; use nonces "
                        "('nonce-…') or hashes for inline scripts."
                    ),
                    evidence=evidence,
                    references=ref,
                )
            )
        else:
            out.append(
                self.finding(
                    "ok",
                    _("Content-Security-Policy present and restrictive for scripts"),
                    _("The browser only runs explicitly allowed scripts."),
                    evidence=evidence,
                    references=ref,
                )
            )
        merged = parse_csp(policies[0])
        if "object-src" not in merged and merged.get("default-src") is None:
            out.append(
                self.finding(
                    "info",
                    _("CSP: object-src not restricted"),
                    _(
                        "Without “object-src 'none'” or default-src, plugins (Flash, Java…) can "
                        "still be loaded."
                    ),
                    fix=_("Add “object-src 'none'” to the CSP."),
                    evidence=evidence,
                    references=ref,
                )
            )
        return out

    # ------------------------------------------------------------ autres en-têtes

    def _clickjacking(self, h: httpx.Headers) -> Finding:
        ref = [MDN + "X-Frame-Options", MDN + "Content-Security-Policy/frame-ancestors"]
        xfo = h.get("x-frame-options", "").strip().upper()
        fa = None
        for p in h.get_list("content-security-policy"):
            fa = parse_csp(p).get("frame-ancestors", fa)
        if fa is not None:
            if "*" in fa or any(s in ("http:", "https:") for s in fa):
                return self.finding(
                    "warn",
                    _("frame-ancestors too permissive"),
                    _(
                        "The CSP allows any site to display your pages in a frame "
                        "(“clickjacking”: a visitor clicks on your site without knowing it)."
                    ),
                    fix=_("frame-ancestors 'self' (or 'none')"),
                    evidence="frame-ancestors " + " ".join(fa),
                    references=ref,
                )
            return self.finding(
                "ok",
                _("Clickjacking protection (frame-ancestors)"),
                _("Only allowed sites can display your pages in a frame."),
                evidence="frame-ancestors " + " ".join(fa),
                references=ref,
            )
        if xfo in ("DENY", "SAMEORIGIN"):
            return self.finding(
                "ok",
                _("Clickjacking protection (X-Frame-Options: {value})", value=xfo),
                _("Your pages cannot be embedded in a frame by another site."),
                evidence=f"X-Frame-Options: {xfo}",
                references=ref,
            )
        if xfo.startswith("ALLOW-FROM"):
            return self.finding(
                "warn",
                _("Obsolete X-Frame-Options: ALLOW-FROM"),
                _("Browsers no longer understand this syntax: in practice there is no protection."),
                fix=_("Replace with the CSP directive: frame-ancestors 'self' https://partner.tld"),
                evidence=f"X-Frame-Options: {xfo}",
                references=ref,
            )
        return self.finding(
            "warn",
            _("No clickjacking protection"),
            _(
                "Neither X-Frame-Options nor frame-ancestors: any site can display yours in an "
                "invisible frame and hijack your visitors' clicks."
            ),
            fix=_fix("X-Frame-Options", "SAMEORIGIN")
            + "\n"
            + _("# or, in the CSP: frame-ancestors 'self'"),
            references=ref,
        )

    def _nosniff(self, h: httpx.Headers) -> Finding:
        ref = [MDN + "X-Content-Type-Options"]
        v = h.get("x-content-type-options", "").strip().lower()
        if v == "nosniff":
            return self.finding(
                "ok",
                "X-Content-Type-Options: nosniff",
                _("The browser respects the declared file type instead of guessing it."),
                evidence="X-Content-Type-Options: nosniff",
                references=ref,
            )
        return self.finding(
            "warn",
            _("X-Content-Type-Options missing"),
            _(
                "Without “nosniff”, the browser may interpret a harmless file (image, text) as "
                "a script, which makes some attacks easier."
            ),
            fix=_fix("X-Content-Type-Options", "nosniff"),
            evidence=f"X-Content-Type-Options: {v or _('(missing)')}",
            references=ref,
        )

    def _referrer(self, h: httpx.Headers) -> Finding:
        ref = [MDN + "Referrer-Policy"]
        v = h.get("referrer-policy", "").strip().lower()
        safe = {
            "no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin",
            "origin", "origin-when-cross-origin",
        }  # fmt: skip
        values = [p.strip() for p in v.split(",") if p.strip()]
        if values and values[-1] in safe:
            return self.finding(
                "ok",
                f"Referrer-Policy: {values[-1]}",
                _("The full address of visited pages is not sent to third-party sites."),
                evidence=f"Referrer-Policy: {v}",
                references=ref,
            )
        if values and values[-1] in ("unsafe-url", "no-referrer-when-downgrade"):
            return self.finding(
                "warn",
                _("Permissive Referrer-Policy ({value})", value=values[-1]),
                _(
                    "The full URL of pages (including parameters) is sent to the third-party "
                    "sites your links point to."
                ),
                fix=_fix("Referrer-Policy", "strict-origin-when-cross-origin"),
                evidence=f"Referrer-Policy: {v}",
                references=ref,
            )
        return self.finding(
            "info",
            _("Referrer-Policy missing"),
            _(
                "Browsers apply a reasonable default, but making it explicit prevents URL leaks "
                "to third-party sites."
            ),
            fix=_fix("Referrer-Policy", "strict-origin-when-cross-origin"),
            evidence=f"Referrer-Policy: {v or _('(missing)')}",
            references=ref,
        )

    def _permissions(self, h: httpx.Headers) -> Finding:
        ref = [MDN + "Permissions-Policy"]
        v = h.get("permissions-policy", "").strip()
        if v:
            return self.finding(
                "ok",
                _("Permissions-Policy present"),
                _(
                    "The site restricts sensitive browser features (camera, microphone, "
                    "geolocation…) available to the page and its frames."
                ),
                evidence=f"Permissions-Policy: {v[:200]}",
                references=ref,
            )
        return self.finding(
            "info",
            _("Permissions-Policy missing"),
            _(
                "Optional: this header explicitly forbids use of the camera, microphone or "
                "geolocation by the page and the third-party content it embeds."
            ),
            fix=_fix("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
            references=ref,
        )

    def _isolation(self, h: httpx.Headers) -> list[Finding]:
        ref = [MDN + "Cross-Origin-Opener-Policy", MDN + "Cross-Origin-Resource-Policy"]
        coop = h.get("cross-origin-opener-policy", "").strip().lower()
        corp = h.get("cross-origin-resource-policy", "").strip().lower()
        missing = _("(missing)")
        ev = f"COOP: {coop or missing}\nCORP: {corp or missing}"
        if coop in ("same-origin", "same-origin-allow-popups") and corp in (
            "same-origin",
            "same-site",
        ):
            return [
                self.finding(
                    "ok",
                    _("Cross-origin isolation (COOP + CORP)"),
                    _("The site is isolated from windows and resources of other origins."),
                    evidence=ev,
                    references=ref,
                )
            ]
        return [
            self.finding(
                "info",
                _("COOP / CORP missing or partial"),
                _(
                    "Optional: these headers isolate the site from other tabs and prevent other "
                    "sites from embedding your resources. Mostly useful for applications "
                    "handling sensitive data."
                ),
                fix=_fix("Cross-Origin-Opener-Policy", "same-origin")
                + "\n\n"
                + _fix("Cross-Origin-Resource-Policy", "same-origin"),
                evidence=ev,
                references=ref,
            )
        ]

    def _legacy(self, h: httpx.Headers) -> list[Finding]:
        out = []
        xss = h.get("x-xss-protection", "").strip()
        if xss and re.match(r"^\s*1", xss):
            out.append(
                self.finding(
                    "info",
                    _("Obsolete X-XSS-Protection"),
                    _(
                        "This filter was removed from browsers and could itself create flaws. "
                        "It is useless; the CSP replaces it."
                    ),
                    fix=_fix("X-XSS-Protection", "0") + "\n" + _("# or simply remove the header"),
                    evidence=f"X-XSS-Protection: {xss}",
                    references=[MDN + "X-XSS-Protection"],
                )
            )
        return out


register(HeadersCheck())
