"""MTA-STS : enregistrement TXT + récupération et validation de la policy.

La policy est récupérée par le client HTTP commun : garde anti-SSRF (mta-sts.<domaine> doit
résoudre vers une adresse publique), sans redirection (RFC 8461), lecture plafonnée.
"""

from __future__ import annotations

import re

import httpx

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.dns import mx_records, txt_records
from sonde.core.finding import Finding
from sonde.core.http import decode_body, fetch_limited
from sonde.core.netguard import BlockedDestination
from sonde.core.target import Target
from sonde.i18n import N_, _

REF = ["https://www.rfc-editor.org/rfc/rfc8461"]
_TXT_RE = re.compile(r"^v\s*=\s*STSv1\s*(;|$)", re.IGNORECASE)
MAX_POLICY_BYTES = 64 * 1024


def parse_policy(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out.setdefault(k.strip().lower(), []).append(v.strip())
    return out


def mx_matches(pattern: str, host: str) -> bool:
    """Motif MTA-STS : exact, ou « *.exemple.fr » (un seul label à gauche)."""
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return "." in host and host.split(".", 1)[1] == pattern[2:]
    return pattern == host


class MtaStsCheck(BaseCheck):
    id = "email.mta_sts"
    name = N_("MTA-STS")
    category = "email"
    order = 50

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        d = target.domain
        txts = [r for r in await txt_records(ctx, f"_mta-sts.{d}") if _TXT_RE.match(r.strip())]
        if not txts:
            return [
                self.finding(
                    "info",
                    _("MTA-STS not configured"),
                    _(
                        "MTA-STS requires servers that send you email to encrypt it in transit "
                        "(TLS) and to verify your server, which prevents an attacker from "
                        "downgrading or intercepting the connection. It is an additional "
                        "protection, recommended but optional."
                    ),
                    fix=f'_mta-sts.{d}. IN TXT "v=STSv1; id=20260101000000"\n'
                    + _("# + file https://mta-sts.{d}/.well-known/mta-sts.txt:", d=d)
                    + "\nversion: STSv1\nmode: testing\nmx: mx.your-provider.tld\nmax_age: 86400",
                    references=REF,
                )
            ]
        if len(txts) > 1:
            return [
                self.finding(
                    "warn",
                    _("MTA-STS: several TXT records"),
                    _("Several “v=STSv1” records are published: senders then ignore MTA-STS."),
                    fix=_("Keep a single TXT record on _mta-sts.{d}", d=d),
                    evidence="\n".join(txts),
                    references=REF,
                )
            ]
        txt = txts[0]
        if not re.search(r"\bid\s*=\s*[A-Za-z0-9]{1,32}\b", txt):
            return [
                self.finding(
                    "warn",
                    _("MTA-STS: “id” missing"),
                    _(
                        "The TXT record must contain an “id” (changed on every policy update); "
                        "without it the record is ignored."
                    ),
                    fix=f'_mta-sts.{d}. IN TXT "v=STSv1; id=20260101000000"',
                    evidence=txt,
                    references=REF,
                )
            ]

        url = f"https://mta-sts.{d}/.well-known/mta-sts.txt"
        try:
            # RFC 8461 : les redirections ne sont pas suivies. Un octet de plus que la limite
            # permet de distinguer « exactement 64 Ko » de « tronqué ».
            resp, body, too_big = await fetch_limited(ctx, url, max_bytes=MAX_POLICY_BYTES + 1)
        except BlockedDestination as exc:
            return [self._unreachable(url, txt, str(exc))]
        except httpx.HTTPError as exc:
            return [self._unreachable(url, txt, f"{type(exc).__name__}: {exc}")]
        if resp.status_code != 200:
            return [self._unreachable(url, txt, f"HTTP {resp.status_code}")]
        if too_big:
            return [self._unreachable(url, txt, _("policy too large (>64 KB)"))]
        text = decode_body(resp, body)

        pol = parse_policy(text)
        problems = []
        if pol.get("version", [""])[0] != "STSv1":
            problems.append(_("version: STSv1 missing"))
        mode = pol.get("mode", [""])[0].lower()
        if mode not in ("enforce", "testing", "none"):
            problems.append(_("invalid mode (enforce|testing|none)"))
        patterns = pol.get("mx", [])
        if not patterns and mode != "none":
            problems.append(_("no mx: line"))
        try:
            max_age = int(pol.get("max_age", [""])[0])
        except ValueError:
            max_age = None
            problems.append(_("max_age missing or invalid"))
        if problems:
            return [
                self.finding(
                    "warn",
                    _("MTA-STS: invalid policy"),
                    _(
                        "The policy file is malformed, senders will ignore it: {problems}.",
                        problems="; ".join(problems),
                    ),
                    fix=_("Expected format:")
                    + "\nversion: STSv1\nmode: enforce\nmx: mx.your-provider.tld\nmax_age: 604800",
                    evidence=text[:400],
                    references=REF,
                )
            ]

        findings: list[Finding] = []
        evidence = f"{url}\n{text.strip()[:400]}"
        if mode == "enforce":
            findings.append(
                self.finding(
                    "ok",
                    _("MTA-STS: “enforce” mode"),
                    _(
                        "Compatible senders refuse to deliver your email without valid TLS to "
                        "your MX servers."
                    ),
                    evidence=evidence,
                    references=REF,
                )
            )
        elif mode == "testing":
            findings.append(
                self.finding(
                    "info",
                    _("MTA-STS: “testing” mode"),
                    _(
                        "The policy is published in test mode: anomalies are reported (if "
                        "TLS-RPT is enabled) but no email is blocked."
                    ),
                    fix=_("When reports are clean: mode: enforce (and change the TXT id)."),
                    evidence=evidence,
                    references=REF,
                )
            )
        else:
            findings.append(
                self.finding(
                    "warn",
                    _("MTA-STS: “none” mode"),
                    _("The policy is published but disabled: no protection is applied."),
                    fix=_("mode: enforce (after a “testing” phase), then change the TXT id."),
                    evidence=evidence,
                    references=REF,
                )
            )

        if max_age is not None and mode == "enforce" and max_age < 86400:
            findings.append(
                self.finding(
                    "warn",
                    _("MTA-STS: short max_age ({seconds} s)", seconds=max_age),
                    _(
                        "Less than one day greatly limits the protection (senders forget the "
                        "policy very quickly). Aim for at least one week."
                    ),
                    fix="max_age: 604800",
                    evidence=f"max_age: {max_age}",
                    references=REF,
                )
            )

        if mode in ("enforce", "testing") and patterns:
            hosts = [h for _pref, h in await mx_records(ctx, d) if h]
            uncovered = [h for h in hosts if not any(mx_matches(p, h) for p in patterns)]
            if uncovered:
                findings.append(
                    self.finding(
                        "crit" if mode == "enforce" else "warn",
                        _("MTA-STS: an MX is not covered by the policy"),
                        _(
                            "Some actual MX servers are not listed in the policy: in “enforce” "
                            "mode, email to them will be REFUSED."
                        )
                        if mode == "enforce"
                        else _("Some actual MX servers are not listed in the policy."),
                        fix=_("Add to the policy:")
                        + " "
                        + " / ".join(f"mx: {h}" for h in uncovered),
                        evidence=_("MX not covered: {hosts}", hosts=", ".join(uncovered)),
                        references=REF,
                    )
                )
        return findings

    def _unreachable(self, url: str, txt: str, why: str) -> Finding:
        return self.finding(
            "warn",
            _("MTA-STS: policy unreachable"),
            _(
                "The DNS record announces MTA-STS but the policy file cannot be retrieved (valid "
                "HTTPS required, no redirect): the protection cannot apply."
            ),
            fix=_(
                "Serve {url} over HTTPS (valid certificate for mta-sts.<domain>), status 200, "
                "no redirect.",
                url=url,
            ),
            evidence=f"{url} → {why}\n{txt}",
            references=REF,
        )


register(MtaStsCheck())
