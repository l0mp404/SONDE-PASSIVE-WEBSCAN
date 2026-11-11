"""Contenu mixte basique : ressources http:// chargées par la page d'accueil HTTPS."""

from __future__ import annotations

import re

import httpx

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.finding import Finding
from sonde.core.http import fetch_home
from sonde.core.target import Target
from sonde.i18n import N_, _

REF = ["https://developer.mozilla.org/docs/Web/Security/Mixed_content"]

_TAG_RE = re.compile(
    r"<(script|img|link|iframe|source|video|audio|object|embed|form|track)\b([^>]*)>", re.IGNORECASE
)
_ATTR_RE = re.compile(r"""(\w[\w-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")
# Ressources activement exécutées/rendues (bloquées par les navigateurs).
ACTIVE = {"script", "iframe", "link", "object", "embed", "form"}
_LINK_FETCHED_REL = {
    "stylesheet",
    "icon",
    "preload",
    "prefetch",
    "modulepreload",
    "manifest",
    "shortcut",
}


def find_mixed(html: str) -> list[tuple[str, str]]:
    """-> [(tag, url http://)] pour chaque ressource en clair référencée."""
    out: list[tuple[str, str]] = []
    for m in _TAG_RE.finditer(html):
        tag = m.group(1).lower()
        attrs = {
            k.lower(): (v1 or v2 or v3 or "") for k, v1, v2, v3 in _ATTR_RE.findall(m.group(2))
        }
        if tag == "link":
            rels = set(attrs.get("rel", "").lower().split())
            if not rels & _LINK_FETCHED_REL:
                continue  # canonical, alternate… ne sont pas chargés
        url_attr = "action" if tag == "form" else "data" if tag == "object" else "src"
        url = attrs.get(url_attr) or (attrs.get("href") if tag == "link" else None)
        if url and url.lower().startswith("http://"):
            out.append((tag, url))
        # srcset : plusieurs URL
        for cand in attrs.get("srcset", "").split(","):
            u = cand.strip().split(" ")[0]
            if u.lower().startswith("http://"):
                out.append((tag, u))
    return out


class MixedContentCheck(BaseCheck):
    id = "web.mixed_content"
    name = N_("Mixed content")
    category = "web"
    order = 8

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        try:
            home = await fetch_home(ctx, target)
        except httpx.HTTPError:
            return []
        if home.response.url.scheme != "https":
            return []  # déjà signalé par web.https
        mixed = find_mixed(home.html)
        if not mixed:
            return [
                self.finding(
                    "ok",
                    _("No mixed content on the home page"),
                    _("All resources of the page are loaded over HTTPS."),
                    references=REF,
                )
            ]
        forms = [(t, u) for t, u in mixed if t == "form"]
        active = [(t, u) for t, u in mixed if t in ACTIVE and t != "form"]
        passive = [(t, u) for t, u in mixed if t not in ACTIVE]
        ev = "\n".join(f"<{t}> {u}" for t, u in mixed[:10]) + ("\n…" if len(mixed) > 10 else "")
        fix = (
            _("Replace http:// URLs with https:// (or relative URLs) in the code and the "
              "database.") + "\n"
            + _("# Safety net (automatic rewriting by the browser):") + "\n"
            + 'add_header Content-Security-Policy "upgrade-insecure-requests" always;'
        )  # fmt: skip
        findings: list[Finding] = []
        if forms:
            findings.append(
                self.finding(
                    "crit",
                    _("Form submitted over unencrypted HTTP"),
                    _(
                        "A form on the page sends its data to an http:// address: what the "
                        "visitor types travels in clear text."
                    ),
                    fix=fix,
                    evidence="\n".join(f"<form> {u}" for _tag, u in forms),
                    references=REF,
                )
            )
        if active:
            findings.append(
                self.finding(
                    "warn",
                    _("Active mixed content ({n} resource(s))", n=len(active)),
                    _(
                        "Scripts, styles or frames are referenced over http://. Browsers block "
                        "them: broken features, and a sign of an incomplete HTTPS migration."
                    ),
                    fix=fix,
                    evidence=ev,
                    references=REF,
                )
            )
        if passive:
            findings.append(
                self.finding(
                    "warn",
                    _("Passive mixed content ({n} resource(s))", n=len(passive)),
                    _(
                        "Images or media are loaded over http://. The browser shows a “not "
                        "secure” warning and this content can be replaced in transit."
                    ),
                    fix=fix,
                    evidence=ev,
                    references=REF,
                )
            )
        return findings


register(MixedContentCheck())
