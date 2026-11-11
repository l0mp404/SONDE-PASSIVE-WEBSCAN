"""Option de scan web : sous-domaines publics (crt.sh).

Facultatif (`--crtsh`) : aucune requête n'est envoyée à la cible, seulement à crt.sh (journaux de
transparence des certificats, publics). Aucune donnée personnelle ; la note n'est jamais affectée.

La réponse de crt.sh n'est pas maîtrisée (un domaine populaire peut produire des dizaines de
Mo) : elle est lue en flux et coupée à MAX_RESPONSE_BYTES, et seuls MAX_RAW_NAMES noms bruts
sont examinés.
"""

from __future__ import annotations

import json

import httpx

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.finding import Finding
from sonde.core.http import fetch_limited
from sonde.core.target import InvalidTarget, Target, parse_target
from sonde.i18n import N_, _

CRTSH_URL = "https://crt.sh/"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 Mo lus au plus
MAX_RAW_NAMES = 10_000  # noms bruts examinés au plus (avant validation)
MAX_NAMES = 500  # sous-domaines retenus au plus
LIST_LIMIT = 30  # affichés dans le constat
SENSITIVE_WORDS = (
    "admin", "vpn", "jenkins", "gitlab", "git", "jira", "confluence", "grafana", "kibana", "sonar",
    "staging", "stage", "preprod", "dev", "test", "intranet", "owa", "webmail", "rdp", "ssh",
    "backup", "db", "sql", "phpmyadmin", "sso", "ldap", "citrix", "remote",
)  # fmt: skip


def is_sensitive(name: str) -> bool:
    labels = name.split(".")[:-2]
    return any(
        word == label or label.startswith(word + "-") or label.endswith("-" + word)
        for label in labels
        for word in SENSITIVE_WORDS
    )


def parse_crtsh(text: str | bytes, *, max_names: int = MAX_RAW_NAMES) -> tuple[set[str], bool]:
    """Noms issus du JSON de crt.sh (`name_value` peut contenir plusieurs noms séparés par \\n).

    -> (noms, limite atteinte). Au plus `max_names` noms bruts sont retenus."""
    try:
        data = json.loads(text)
    except ValueError:
        return set(), False
    names: set[str] = set()
    for entry in data if isinstance(data, list) else []:
        if isinstance(entry, dict) and isinstance(entry.get("name_value"), str):
            for name in entry["name_value"].split("\n"):
                if len(names) >= max_names:
                    return names, True
                names.add(name)
    return names, False


def _inside(names, domain: str) -> tuple[list[str], int]:
    """(noms valides du domaine audité, nombre de noms étrangers écartés)."""
    keep: set[str] = set()
    foreign = 0
    for raw in names:
        try:
            name = parse_target(str(raw).strip().lower().lstrip("*.")).domain
        except InvalidTarget:
            continue
        if name == domain or name.endswith("." + domain):
            keep.add(name)
        else:
            foreign += 1
    return sorted(keep)[:MAX_NAMES], foreign


def _listing(items: list[str]) -> str:
    more = len(items) - LIST_LIMIT
    return "\n".join(items[:LIST_LIMIT]) + ("\n" + _("… and {n} more", n=more) if more > 0 else "")


class CrtshCheck(BaseCheck):
    id = "web.crtsh"
    name = N_("Public subdomains (crt.sh)")
    category = "web"
    optional = True
    contacts_target = False  # seul crt.sh est interrogé
    order = 120
    timeout = 60.0  # crt.sh est parfois lent

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        unavailable = _("Public subdomains could not be listed.")
        try:
            resp, body, truncated = await fetch_limited(
                ctx,
                CRTSH_URL,
                max_bytes=MAX_RESPONSE_BYTES,
                params={"q": f"%.{target.domain}", "output": "json"},
                timeout=45.0,
            )
        except httpx.HTTPError as exc:
            return [self.finding("info", _("crt.sh unreachable"), unavailable,
                                 evidence=type(exc).__name__)]  # fmt: skip
        if resp.status_code != 200:
            return [self.finding("info", _("crt.sh unavailable"), unavailable,
                                 evidence=f"HTTP {resp.status_code}")]  # fmt: skip
        if truncated:
            return [self.finding(
                "info", _("crt.sh response too large"),
                _("The crt.sh answer exceeds {mb} MB and was not processed. The domain has too "
                  "many certificates to list them this way.", mb=MAX_RESPONSE_BYTES // 2**20),
                evidence=_("response cut at {mb} MB", mb=MAX_RESPONSE_BYTES // 2**20),
            )]  # fmt: skip
        raw_names, capped = parse_crtsh(body, max_names=MAX_RAW_NAMES)
        names, _foreign = _inside(raw_names, target.domain)
        others = [n for n in names if n != target.domain]
        if not others:
            return [self.finding("info", _("No known public subdomain"),
                                 _("No other name appears in public certificates."))]  # fmt: skip
        sensitive = [n for n in others if is_sensitive(n)]
        detail = _(
            "Every name in a certificate is known to everyone: it is attack surface to keep up "
            "to date. These names are only listed; none of them was contacted."
        )
        if capped:
            detail += " " + _("Partial list: only the first {n} names returned by crt.sh "
                              "were processed.", n=MAX_RAW_NAMES)  # fmt: skip
        elif len(names) >= MAX_NAMES:
            detail += " " + _("Partial list: limited to {n} subdomains.", n=MAX_NAMES)
        out = [self.finding(
            "info", _("{n} subdomain(s) visible in public certificates", n=len(others)),
            detail,
            fix=_("Remove unused subdomains and keep the others up to date."),
            evidence=_listing(others),
        )]  # fmt: skip
        if sensitive:
            out.append(self.finding(
                "info", _("{n} name(s) suggesting an admin or test service", n=len(sensitive)),
                _("Names like admin, vpn, jenkins or staging attract attackers. Their presence "
                  "in a certificate does not prove they are reachable."),
                fix=_("Check that they are protected (VPN, IP allow-list, strong authentication) "
                      "or remove them."),
                evidence=_listing(sensitive),
            ))  # fmt: skip
        return out


register(CrtshCheck())
