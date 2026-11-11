"""SPF : unicité, qualificatif final, nombre de requêtes DNS (limite de 10)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.dns import mx_records, txt_records
from sonde.core.finding import Finding
from sonde.core.target import Target
from sonde.i18n import N_, _

REF = [
    "https://www.rfc-editor.org/rfc/rfc7208",
    "https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4",
]
_SPF_RE = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)
LOOKUP_LIMIT = 10
_HARD_STOP = 25  # on arrête d'explorer au-delà (déjà largement hors limite)
_MAX_DEPTH = 12

# Mécanismes qui déclenchent une requête DNS (RFC 7208 §4.6.4)
_DNS_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}


@dataclass
class _State:
    lookups: int = 0
    visited: set[str] = field(default_factory=set)
    issues: list[str] = field(default_factory=list)
    has_ptr: bool = False
    truncated: bool = False


def is_spf(record: str) -> bool:
    return bool(_SPF_RE.match(record.strip()))


def _terms(record: str) -> list[tuple[str, str, str]]:
    """-> liste de (qualificatif, nom, valeur) ; pour un modificateur, qualificatif ''."""
    out = []
    for raw in record.split()[1:]:
        if m := re.match(r"^([A-Za-z0-9_.\-]+)=(.*)$", raw):  # redirect=, exp=
            out.append(("", m.group(1).lower(), m.group(2)))
        elif m := re.match(r"^([+\-~?]?)([A-Za-z0-9]+)(?:[:/](.*))?$", raw):
            out.append((m.group(1), m.group(2).lower(), m.group(3) or ""))
    return out


async def _spf_for(ctx: Context, domain: str) -> list[str]:
    return [r for r in await txt_records(ctx, domain) if is_spf(r)]


async def _walk(ctx: Context, record: str, st: _State, depth: int) -> str | None:
    """Parcourt `record` ; renvoie le qualificatif final effectif ('+','-','~','?') ou None."""
    final: str | None = None
    redirect: str | None = None
    has_all = False
    for qual, name, value in _terms(record):
        if name == "all":
            has_all = True
            final = qual or "+"
            continue
        if name == "redirect":
            redirect = value
        if name in _DNS_MECHANISMS:
            st.lookups += 1
        if name == "ptr":
            st.has_ptr = True
        if name == "include" and value:
            await _follow(ctx, value, st, depth, label="include")

    if not has_all and redirect:
        final = await _follow(ctx, redirect, st, depth, label="redirect")
    return final


async def _follow(ctx: Context, domain: str, st: _State, depth: int, *, label: str) -> str | None:
    domain = domain.lower().rstrip(".")
    if "%" in domain:  # macros SPF : non résolubles statiquement
        return None
    if domain in st.visited:
        st.issues.append(_("SPF loop detected via “{domain}”", domain=domain))
        return None
    if st.lookups > _HARD_STOP or depth >= _MAX_DEPTH:
        st.truncated = True
        return None
    st.visited.add(domain)
    records = await _spf_for(ctx, domain)
    if not records:
        st.issues.append(_("{label}:{domain} points to no SPF record", label=label, domain=domain))
        return None
    if len(records) > 1:
        st.issues.append(
            _("{label}:{domain} publishes several SPF records", label=label, domain=domain)
        )
        return None
    final = await _walk(ctx, records[0], st, depth + 1)
    # Le qualificatif d'un include n'est pas le « final » du domaine : seul redirect le propage.
    return final if label == "redirect" else None


class SpfCheck(BaseCheck):
    id = "email.spf"
    name = N_("SPF")
    category = "email"
    order = 20

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        d = target.domain
        records = await _spf_for(ctx, d)

        if not records:
            has_mx = any(h for _pref, h in await mx_records(ctx, d))
            if has_mx:
                return [
                    self.finding(
                        "crit",
                        _("SPF missing"),
                        _(
                            "No SPF rule says which servers may send email on behalf of this "
                            "domain. Anyone can therefore impersonate you, and your real email "
                            "may end up in spam."
                        ),
                        fix=f'{d}. IN TXT "v=spf1 mx include:_spf.your-provider.tld -all"\n'
                        + _(
                            "; replace the include with your provider's (e.g. Google: "
                            "include:_spf.google.com; Microsoft 365: "
                            "include:spf.protection.outlook.com)"
                        ),
                        references=REF,
                    )
                ]
            return [
                self.finding(
                    "warn",
                    _("SPF missing (domain without email)"),
                    _(
                        "The domain receives no email but does not forbid sending on its "
                        "behalf: it can be used for spoofing."
                    ),
                    fix=f'{d}. IN TXT "v=spf1 -all"',
                    references=REF,
                )
            ]

        if len(records) > 1:
            return [
                self.finding(
                    "crit",
                    _("Several SPF records"),
                    _(
                        "The domain publishes several SPF rules. In that case receiving servers "
                        "ignore SPF entirely (“permerror”): the protection does not work."
                    ),
                    fix=_(
                        "Merge into ONE SINGLE TXT record starting with v=spf1 (group the "
                        "“include:” terms and keep a single “-all” at the end)."
                    ),
                    evidence="\n".join(records),
                    references=REF,
                )
            ]

        record = records[0]
        st = _State()
        st.visited.add(d)
        final = await _walk(ctx, record, st, 0)
        findings: list[Finding] = []

        findings.append(self._qualifier_finding(d, record, final))
        findings.append(self._lookup_finding(st))
        for issue in st.issues:
            findings.append(
                self.finding(
                    "crit",
                    _("SPF: invalid reference"),
                    _(
                        "An SPF rule is broken ({issue}). A single invalid include makes the "
                        "whole record unusable (“permerror”).",
                        issue=issue,
                    ),
                    fix=_("Fix or remove the faulty reference in the SPF record."),
                    evidence=issue,
                    references=REF,
                )
            )
        if st.has_ptr:
            findings.append(
                self.finding(
                    "info",
                    _("SPF: deprecated “ptr” mechanism"),
                    _(
                        "The standard discourages the “ptr” mechanism: it is slow, unreliable "
                        "and costs DNS lookups."
                    ),
                    fix=_("Replace “ptr” with explicit “ip4:”, “ip6:” or “include:”."),
                    evidence=record,
                    references=REF,
                )
            )
        return findings

    def _qualifier_finding(self, domain: str, record: str, final: str | None) -> Finding:
        if final == "+":
            return self.finding(
                "crit",
                _("SPF: “+all” allows everyone"),
                _(
                    "The rule ends with “+all” (or a bare “all”): it allows any server on the "
                    "internet to send email on your behalf. That is worse than having no SPF."
                ),
                fix=_fix_all(record, "-all"),
                evidence=record,
                references=REF,
            )
        if final == "?":
            return self.finding(
                "warn",
                _("SPF: neutral “?all”"),
                _(
                    "The rule ends with “?all”: receiving servers must draw no conclusion. "
                    "Spoofed email is therefore not blocked."
                ),
                fix=_fix_all(record, "-all"),
                evidence=record,
                references=REF,
            )
        if final == "~":
            return self.finding(
                "warn",
                _("SPF: “~all” (soft fail)"),
                _(
                    "The rule ends with “~all”: unauthorized email is only marked suspicious, "
                    "not rejected. Acceptable while testing, but the protection is partial."
                ),
                fix=_fix_all(record, "-all")
                + "\n"
                + _("; once DMARC is in place and legitimate senders are validated"),
                evidence=record,
                references=REF,
            )
        if final == "-":
            return self.finding(
                "ok",
                _("SPF: strict policy (“-all”)"),
                _(
                    "Only the listed servers may send email for this domain; the others are "
                    "rejected."
                ),
                evidence=record,
                references=REF,
            )
        return self.finding(
            "warn",
            _("SPF: no final “all”"),
            _(
                "The record ends with neither “-all” nor “~all”: without an explicit "
                "conclusion, any unlisted server is treated as neutral."
            ),
            fix=_fix_all(record, "-all"),
            evidence=record,
            references=REF,
        )

    def _lookup_finding(self, st: _State) -> Finding:
        n = st.lookups
        shown = f"{n}+" if st.truncated else str(n)
        if n > LOOKUP_LIMIT:
            return self.finding(
                "crit",
                _("SPF: {n} DNS lookups (limit: {limit})", n=shown, limit=LOOKUP_LIMIT),
                _(
                    "The standard limits SPF to 10 DNS lookups (include, a, mx, exists, "
                    "redirect). Beyond that, receivers reject the rule (“permerror”) and SPF "
                    "protects nothing anymore, including your legitimate email."
                ),
                fix=_(
                    "Remove useless “include:” terms, replace “a”/“mx” with “ip4:”/“ip6:”, or "
                    "“flatten” SPF with a dedicated service."
                ),
                evidence=f"{shown} lookups",
                references=REF,
            )
        return self.finding(
            "ok",
            _("SPF: {n}/{limit} DNS lookups", n=shown, limit=LOOKUP_LIMIT),
            _("The number of DNS lookups triggered by SPF is within the limit of 10.")
            + (" " + _("Careful, it is close to the limit.") if n >= 9 else ""),
            evidence=f"{shown} lookups",
            references=REF,
        )


def _fix_all(record: str, wanted: str) -> str:
    fixed = re.sub(r"(?<!\S)[+\-~?]?all(?!\S)", wanted, record, flags=re.IGNORECASE)
    if fixed == record and wanted not in record:
        fixed = f"{record} {wanted}"
    return f'"{fixed}"'


register(SpfCheck())
