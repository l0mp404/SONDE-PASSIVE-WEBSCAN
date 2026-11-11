"""Fuites d'information : en-têtes bavards, meta generator, CMS et versions."""

from __future__ import annotations

import json
import re

import httpx

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.finding import Finding
from sonde.core.http import fetch_home, fetch_text
from sonde.core.target import Target
from sonde.i18n import N_, _

REF = [
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
    "https://developer.wordpress.org/advanced-administration/security/hardening/",
]
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)*")
# « WordPress 6.4.2 », « Drupal 10 (https://www.drupal.org) », « Joomla! - Open Source… »
_NAME_VERSION_RE = re.compile(r"^\s*([A-Za-z][\w!.+ -]*?)[\s/]+v?(\d+(?:\.\d+)*)\b")


def split_generator(value: str) -> tuple[str, str | None]:
    """'WordPress 6.4.2' -> ('WordPress', '6.4.2') ; sans version -> (valeur, None)."""
    if m := _NAME_VERSION_RE.match(value):
        return m.group(1).strip(" -"), m.group(2)
    v = _VERSION_RE.search(value)
    return (_VERSION_RE.sub("", value).strip(" -v") or value), (v.group(0) if v else None)


_GENERATOR_RE = re.compile(
    r"<meta\s+[^>]*name\s*=\s*[\"']generator[\"'][^>]*content\s*=\s*[\"']([^\"']+)[\"']"
    r"|<meta\s+[^>]*content\s*=\s*[\"']([^\"']+)[\"'][^>]*name\s*=\s*[\"']generator[\"']",
    re.IGNORECASE,
)
_WP_VER_RE = re.compile(r"/wp-includes/[^\"'\s]*?\?ver=(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)

# (indice dans le HTML, nom du CMS)
CMS_HINTS: list[tuple[str, str]] = [
    ("/wp-content/", "WordPress"),
    ("/wp-includes/", "WordPress"),
    ("Joomla!", "Joomla"),
    ("/media/jui/", "Joomla"),
    ("/media/system/js/", "Joomla"),
    ("Drupal", "Drupal"),
    ("/sites/default/files/", "Drupal"),
    ("TYPO3", "TYPO3"),
    ("/typo3conf/", "TYPO3"),
    ("PrestaShop", "PrestaShop"),
    ("/modules/ps_", "PrestaShop"),
    ("cdn.shopify.com", "Shopify"),
    ("static.wixstatic.com", "Wix"),
    ("static.parastorage.com", "Wix"),
    ("squarespace.com", "Squarespace"),
    ("assets-global.website-files.com", "Webflow"),
    ("cdn.prod.website-files.com", "Webflow"),
    ("js.hs-scripts.com", "HubSpot CMS"),
    ("/skin/frontend/", "Magento"),
    ("/static/frontend/", "Magento"),
    ("ghost.org", "Ghost"),
]
LEAKY_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")


def detect_cms(html: str, headers: httpx.Headers) -> tuple[str | None, str | None, str]:
    """-> (cms, version, source) à partir du generator, des en-têtes puis des indices HTML."""
    m = _GENERATOR_RE.search(html)
    if m:
        gen = (m.group(1) or m.group(2)).strip()
        name, version = split_generator(gen)
        return name, version, f'<meta name="generator" content="{gen}">'
    xg = headers.get("x-generator")
    if xg:
        name, version = split_generator(xg)
        return name, version, f"X-Generator: {xg}"
    if headers.get("x-shopify-stage") or headers.get("x-shopid"):
        return "Shopify", None, _("header {name}", name="X-Shopify-*")
    if headers.get("x-wix-request-id"):
        return "Wix", None, _("header {name}", name="X-Wix-Request-Id")
    if headers.get("x-drupal-cache") or headers.get("x-drupal-dynamic-cache"):
        return "Drupal", None, _("header {name}", name="X-Drupal-Cache")
    for hint, name in CMS_HINTS:
        if hint.lower() in html.lower():
            return name, None, _("“{hint}” found in the page", hint=hint)
    return None, None, ""


class LeaksCheck(BaseCheck):
    id = "web.leaks"
    name = N_("Information leaks")
    category = "web"
    order = 6

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        try:
            home = await fetch_home(ctx, target)
        except httpx.HTTPError:
            return []
        h = home.response.headers
        findings: list[Finding] = []

        for name in LEAKY_HEADERS:
            value = h.get(name)
            if value:
                findings.append(self._header_finding(name, value))

        cms, version, source = detect_cms(home.html, h)
        if cms == "WordPress" and not version:
            m = _WP_VER_RE.search(home.html)
            if m:
                version, source = m.group(1), _("?ver= parameter on a /wp-includes/ file")
        if cms:
            findings.append(self._cms_finding(cms, version, source))
            if cms == "WordPress":
                findings.extend(await self._wordpress_extras(target, ctx, home.url))

        if not findings:
            findings.append(
                self.finding(
                    "ok",
                    _("No obvious information leak"),
                    _("Neither the page nor the headers reveal the technology or versions used."),
                    references=REF,
                )
            )
        return findings

    def _header_finding(self, name: str, value: str) -> Finding:
        pretty = "-".join(p.capitalize() for p in name.split("-"))
        has_version = bool(_VERSION_RE.search(value))
        ev = f"{pretty}: {value}"
        fix = {
            "server": (
                "# Nginx\nserver_tokens off;\n\n# Apache\nServerTokens Prod\nServerSignature Off"
            ),
            "x-powered-by": (
                "# PHP (php.ini)\nexpose_php = Off\n\n# Express.js\napp.disable('x-powered-by')\n\n"
                "# Nginx (proxy)\nproxy_hide_header X-Powered-By;"
            ),
        }.get(name, f"# Nginx\nproxy_hide_header {pretty};\n# Apache\nHeader unset {pretty}")
        if has_version:
            return self.finding(
                "warn",
                _("Server version exposed ({header})", header=pretty),
                _(
                    "The {header} header reveals the exact software version. An attacker "
                    "immediately knows which known flaws to try.",
                    header=pretty,
                ),
                fix=fix,
                evidence=ev,
                references=REF,
            )
        return self.finding(
            "info",
            _("Technology disclosed ({header})", header=pretty),
            _(
                "The {header} header names the software used, without version. Minor, but "
                "easy to hide.",
                header=pretty,
            ),
            fix=fix,
            evidence=ev,
            references=REF,
        )

    def _cms_finding(self, cms: str, version: str | None, source: str) -> Finding:
        if version:
            return self.finding(
                "warn",
                _("{cms} {version}: version visible", cms=cms, version=version),
                _(
                    "The exact version of {cms} is publicly readable. If it is not up to date, "
                    "the corresponding flaws are known to everyone.",
                    cms=cms,
                ),
                fix=(
                    _("# WordPress (theme functions.php)") + "\n"
                    "remove_action('wp_head', 'wp_generator');\n"
                    "add_filter('script_loader_src', fn($s) => remove_query_arg('ver', $s));\n"
                    "add_filter('style_loader_src', fn($s) => remove_query_arg('ver', $s));"
                    if cms == "WordPress"
                    else _(
                        "Disable the generator tag in the {cms} configuration and keep the "
                        "CMS up to date.",
                        cms=cms,
                    )  # fmt: skip
                ),
                evidence=source,
                references=REF,
            )
        return self.finding(
            "info",
            _("CMS identified: {cms}", cms=cms),
            _(
                "The site uses {cms}. This is not a vulnerability, but it must be kept up to "
                "date (core, themes, plugins).",
                cms=cms,
            ),
            evidence=source,
            references=REF,
        )

    async def _wordpress_extras(self, target: Target, ctx: Context, base_url: str) -> list[Finding]:
        out: list[Finding] = []
        base = base_url.rstrip("/")
        # readme.html : version du cœur en clair
        try:
            resp, text = await fetch_text(ctx, f"{base}/readme.html", max_bytes=64_000)
            if resp.status_code == 200 and "wordpress" in text.lower():
                m = re.search(r"Version\s+(\d+\.\d+(?:\.\d+)?)", text)
                out.append(
                    self.finding(
                        "warn",
                        _(
                            "WordPress: /readme.html accessible (version {version})",
                            version=m.group(1),
                        )
                        if m
                        else _("WordPress: /readme.html accessible"),
                        _(
                            "The readme.html file shipped with WordPress is public; it confirms "
                            "the CMS and often its version."
                        ),
                        fix=_("Delete readme.html (and license.txt) on every update, or:")
                        + "\n# Nginx\nlocation ~* ^/(readme\\.html|license\\.txt)$ { return 404; }",
                        evidence=f"{base}/readme.html → 200",
                        references=REF,
                    )
                )
        except httpx.HTTPError:
            pass
        # API REST : énumération possible des utilisateurs
        try:
            resp, text = await fetch_text(ctx, f"{base}/wp-json/", max_bytes=64_000)
            if resp.status_code == 200:
                try:
                    data = json.loads(text)
                except ValueError:
                    data = None
                if isinstance(data, dict) and "namespaces" in data:
                    out.append(
                        self.finding(
                            "info",
                            _("WordPress: public REST API (/wp-json/)"),
                            _(
                                "The REST API is open without authentication. That is normal "
                                "for WordPress, but /wp-json/wp/v2/users often lists author "
                                "logins, useful for a password attack."
                            ),
                            fix=_(
                                "Restrict /wp-json/wp/v2/users to logged-in users (security "
                                "plugin or rest_endpoints filter) and enable login attempt "
                                "limiting."
                            ),
                            evidence=f"{base}/wp-json/ → 200, "
                            + _("{n} namespaces", n=len(data.get("namespaces", []))),
                            references=REF,
                        )
                    )
        except httpx.HTTPError:
            pass
        return out


register(LeaksCheck())
