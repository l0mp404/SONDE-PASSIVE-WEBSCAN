"""DMARC : présence, politique, rapports (rua), pct."""

from __future__ import annotations

import re

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.dns import txt_records
from sonde.core.finding import Finding
from sonde.core.target import Target
from sonde.i18n import N_, _

REF = [
    "https://www.rfc-editor.org/rfc/rfc7489",
    "https://dmarc.org/overview/",
]
_DMARC_RE = re.compile(r"^v\s*=\s*DMARC1\s*(;|$)", re.IGNORECASE)


def parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags.setdefault(k.strip().lower(), v.strip())
    return tags


def _candidates(domain: str) -> list[str]:
    """domaine, puis ses parents (jusqu'à 2 labels) : DMARC se rabat sur le domaine parent."""
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


class DmarcCheck(BaseCheck):
    id = "email.dmarc"
    name = N_("DMARC")
    category = "email"
    order = 40

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        found_at: str | None = None
        records: list[str] = []
        for cand in _candidates(target.domain):
            recs = [
                r for r in await txt_records(ctx, f"_dmarc.{cand}") if _DMARC_RE.match(r.strip())
            ]
            if recs:
                found_at, records = cand, recs
                break

        d = target.domain
        if not records:
            return [
                self.finding(
                    "crit",
                    _("DMARC missing"),
                    _(
                        "No DMARC policy is published. Receiving servers do not know what to do "
                        "with email spoofing your domain (fake invoices, phishing…), and you "
                        "receive no report."
                    ),
                    fix=f'_dmarc.{d}. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@{d}"\n'
                    + _(
                        "; start with “p=none” to watch the reports, then move to "
                        "“p=quarantine” and finally “p=reject”"
                    ),
                    references=REF,
                )
            ]
        if len(records) > 1:
            return [
                self.finding(
                    "crit",
                    _("DMARC: several records"),
                    _(
                        "Several DMARC records are published: the standard then requires "
                        "ignoring all of them. Result: no DMARC protection."
                    ),
                    fix=_(
                        "Keep only ONE TXT record on _dmarc.{domain} (merge the “rua=” values "
                        "if needed).",
                        domain=found_at,
                    ),
                    evidence="\n".join(records),
                    references=REF,
                )
            ]

        record = records[0]
        tags = parse_tags(record)
        inherited = found_at != d
        where = found_at if inherited else None
        findings: list[Finding] = []

        policy = tags.get("p", "").lower()
        if inherited and tags.get("sp"):
            policy = tags["sp"].lower()
        findings.append(self._policy_finding(policy, record, where, found_at or d))

        if "rua" not in tags or not tags["rua"]:
            findings.append(
                self.finding(
                    "info",
                    _("DMARC: no report address (rua)"),
                    _(
                        "Without a “rua” address, you do not receive the reports showing who "
                        "sends email on your behalf: hard to spot spoofing or to move safely "
                        "to “reject”."
                    ),
                    fix=_("Add to the record:") + f" rua=mailto:dmarc@{found_at or d}",
                    evidence=record,
                    references=REF,
                )
            )
        elif not re.search(r"mailto:", tags["rua"], re.IGNORECASE):
            findings.append(
                self.finding(
                    "warn",
                    _("DMARC: invalid “rua” address"),
                    _("The report address does not start with “mailto:”: it will be ignored."),
                    fix="rua=mailto:dmarc@" + (found_at or d),
                    evidence=record,
                    references=REF,
                )
            )

        pct = tags.get("pct")
        if pct is not None and policy in ("quarantine", "reject"):
            try:
                pct_n = int(pct)
            except ValueError:
                pct_n = None
            if pct_n is None or not 0 <= pct_n <= 100:
                findings.append(
                    self.finding(
                        "warn",
                        _("DMARC: invalid “pct” value"),
                        _("The enforcement percentage is not an integer between 0 and 100."),
                        evidence=record,
                        references=REF,
                    )
                )
            elif pct_n < 100:
                findings.append(
                    self.finding(
                        "warn",
                        _("DMARC: policy applied to only {pct}%", pct=pct_n),
                        _(
                            "With pct={pct}, only {pct}% of fraudulent email is subject to the "
                            "policy; the rest gets through. Meant for a gradual rollout, not "
                            "as a final state.",
                            pct=pct_n,
                        ),
                        fix=_("Once reports are checked: remove “pct=” (or set pct=100)."),
                        evidence=record,
                        references=REF,
                    )
                )
        return findings

    def _policy_finding(
        self, policy: str, record: str, inherited_from: str | None, at: str
    ) -> Finding:
        def title(msgid: str) -> str:
            if inherited_from is None:
                return _(msgid)
            return _("{title} (inherited from _dmarc.{domain})",
                     title=_(msgid), domain=inherited_from)  # fmt: skip

        if policy == "reject":
            return self.finding(
                "ok",
                title(N_("DMARC: “reject” policy")),
                _(
                    "Email spoofing the domain is refused by compatible receivers: this is the "
                    "maximum protection level."
                ),
                evidence=record,
                references=REF,
            )
        if policy == "quarantine":
            return self.finding(
                "ok",
                title(N_("DMARC: “quarantine” policy")),
                _(
                    "Email spoofing the domain is sent to spam. Good protection level; "
                    "“reject” is the final step."
                ),
                evidence=record,
                references=REF,
            )
        if policy == "none":
            return self.finding(
                "warn",
                title(N_("DMARC: “none” policy (monitoring only)")),
                _(
                    "DMARC is in observation mode: spoofed email is flagged in reports but "
                    "still delivered. It is a starting step, not a protection."
                ),
                fix=_("After analyzing the reports and adjusting SPF/DKIM:")
                + f'\n_dmarc.{at}. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@{at}"',
                evidence=record,
                references=REF,
            )
        return self.finding(
            "warn",
            title(N_("DMARC: “p” policy missing or invalid")),
            _(
                "The DMARC record exists but its policy (p=none|quarantine|reject) is missing "
                "or unknown: it has no effect."
            ),
            fix=f'_dmarc.{at}. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@{at}"',
            evidence=record,
            references=REF,
        )


register(DmarcCheck())
