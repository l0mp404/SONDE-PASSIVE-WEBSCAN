"""DKIM : sélecteurs courants (+ sélecteur fourni) et taille de clé."""

from __future__ import annotations

import asyncio
import base64
import binascii
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.dns import txt_records
from sonde.core.finding import Finding
from sonde.core.target import Target, parse_dkim_selector
from sonde.i18n import N_, _

REF = [
    "https://www.rfc-editor.org/rfc/rfc6376",
    "https://www.rfc-editor.org/rfc/rfc8301",
]
COMMON_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2",
    "s1", "s2", "mail", "dkim", "mandrill", "smtp",
]  # fmt: skip


@dataclass
class DkimKey:
    selector: str
    record: str
    kind: str  # "rsa" | "ed25519" | "revoked" | "invalid" | "other"
    bits: int | None = None


def parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def analyze_key(selector: str, record: str) -> DkimKey:
    tags = parse_tags(record)
    algo = tags.get("k", "rsa").lower()
    p = re.sub(r"\s+", "", tags.get("p", ""))
    if not p:
        return DkimKey(selector, record, "revoked")
    try:
        der = base64.b64decode(p, validate=True)
    except (binascii.Error, ValueError):
        return DkimKey(selector, record, "invalid")
    if algo == "ed25519":
        # RFC 8463 : clé brute de 32 octets (certains publient du SPKI)
        if len(der) == 32:
            return DkimKey(selector, record, "ed25519", 256)
    try:
        key = serialization.load_der_public_key(der)
    except ValueError:
        return DkimKey(selector, record, "invalid")
    if isinstance(key, rsa.RSAPublicKey):
        return DkimKey(selector, record, "rsa", key.key_size)
    if isinstance(key, ed25519.Ed25519PublicKey):
        return DkimKey(selector, record, "ed25519", 256)
    return DkimKey(selector, record, "other")


def _is_dkim(record: str) -> bool:
    tags = parse_tags(record)
    return tags.get("v", "DKIM1").upper() == "DKIM1" and "p" in tags


class DkimCheck(BaseCheck):
    id = "email.dkim"
    name = N_("DKIM")
    category = "email"
    order = 30

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        selectors = list(COMMON_SELECTORS)
        custom = None
        if ctx.dkim_selector:
            custom = parse_dkim_selector(ctx.dkim_selector)  # défense en profondeur
            if custom not in selectors:
                selectors.append(custom)

        results = await asyncio.gather(
            *(txt_records(ctx, f"{s}._domainkey.{target.domain}") for s in selectors),
            return_exceptions=True,
        )
        if all(isinstance(r, BaseException) for r in results):
            raise next(r for r in results if isinstance(r, BaseException))

        keys: list[DkimKey] = []
        for sel, res in zip(selectors, results, strict=True):
            if isinstance(res, BaseException):
                continue  # une erreur ponctuelle ne vaut pas « absent » mais ne bloque pas
            for rec in res:
                if _is_dkim(rec):
                    keys.append(analyze_key(sel, rec))

        if not keys:
            tried = _("selectors tried: {names}", names=", ".join(selectors))
            if custom:
                return [
                    self.finding(
                        "warn",
                        _("DKIM: selector “{selector}” not found", selector=custom),
                        _(
                            "No DKIM key is published for the given selector. Without a valid "
                            "DKIM signature, email is easier to spoof or lands in spam."
                        ),
                        fix=_("Publish the key provided by your sending service:")
                        + f' {custom}._domainkey.{target.domain}. IN TXT "v=DKIM1; k=rsa; p=…"',
                        evidence=tried,
                        references=REF,
                    )
                ]
            return [
                self.finding(
                    "info",
                    _("DKIM: no key found (common selectors)"),
                    _(
                        "No DKIM key was found among the usual selector names. This does not "
                        "prove there is no DKIM: the selector may have a custom name. Check "
                        "the header of a received email (field “DKIM-Signature: … s=NAME”) "
                        "then run again with --dkim-selector."
                    ),
                    fix=_("sonde-passif scan <domain> --dkim-selector NAME"),
                    evidence=tried,
                    references=REF,
                )
            ]

        revoked = [k for k in keys if k.kind == "revoked"]
        findings = [self._key_finding(target, k) for k in keys if k.kind != "revoked"]
        if len(revoked) == 1:
            findings.append(self._key_finding(target, revoked[0]))
        elif revoked:
            # Certains domaines publient une clé vide pour tous les sélecteurs : un seul constat.
            names = ", ".join(k.selector for k in revoked)
            findings.append(
                self.finding(
                    "info",
                    _("DKIM: {n} revoked selectors (empty key)", n=len(revoked)),
                    _(
                        "These selectors exist but their key is empty: they were deliberately "
                        "disabled. No risk, provided they are no longer used."
                    ),
                    evidence=_("revoked selectors: {names}", names=names),
                    references=REF,
                )
            )
        return findings

    def _key_finding(self, target: Target, k: DkimKey) -> Finding:
        name = f"{k.selector}._domainkey.{target.domain}"
        ev = f"{name}\n{_short(k.record)}"
        if k.kind == "revoked":
            return self.finding(
                "info",
                _("DKIM “{selector}”: revoked key", selector=k.selector),
                _(
                    "This selector exists but its key is empty: it was deliberately disabled. "
                    "No risk, provided it is no longer used."
                ),
                evidence=ev,
                references=REF,
            )
        if k.kind == "invalid":
            return self.finding(
                "warn",
                _("DKIM “{selector}”: unreadable key", selector=k.selector),
                _(
                    "The published public key is malformed: signatures cannot be verified. "
                    "Often caused by a truncated copy-paste."
                ),
                fix=_(
                    "Publish the key again exactly as provided by your sending service (TXT "
                    "strings longer than 255 characters must be split)."
                ),
                evidence=ev,
                references=REF,
            )
        if k.kind == "ed25519":
            return self.finding(
                "ok",
                _("DKIM “{selector}”: Ed25519 key", selector=k.selector),
                _(
                    "Modern, robust key. Also keep an RSA 2048 key for receivers that do not "
                    "support Ed25519."
                ),
                evidence=ev,
                references=REF,
            )
        if k.kind == "other" or k.bits is None:
            return self.finding(
                "info",
                _("DKIM “{selector}”: key type not assessed", selector=k.selector),
                _("A DKIM key is present but Sonde does not analyze its type."),
                evidence=ev,
                references=REF,
            )
        bits = k.bits
        if bits < 1024:
            return self.finding(
                "crit",
                _(
                    "DKIM “{selector}”: RSA key too weak ({bits} bits)",
                    selector=k.selector,
                    bits=bits,
                ),
                _(
                    "A key under 1024 bits can be broken with modest means: an attacker could "
                    "forge signed email on behalf of the domain."
                ),
                fix=_(
                    "Generate a new 2048-bit RSA key (from your email provider) and publish the "
                    "new TXT record; remove the old one after the switch."
                ),
                evidence=f"{ev}\n" + _("size: {bits} bits", bits=bits),
                references=REF,
            )
        if bits == 1024:
            return self.finding(
                "warn",
                _("DKIM “{selector}”: 1024-bit RSA key", selector=k.selector),
                _(
                    "A 1024-bit key is now considered insufficient in the medium term; 2048 "
                    "bits is the current recommendation."
                ),
                fix=_(
                    "Regenerate the key as 2048-bit RSA at your provider and publish the new "
                    "TXT record."
                ),
                evidence=f"{ev}\n" + _("size: {bits} bits", bits=bits),
                references=REF,
            )
        return self.finding(
            "ok",
            _("DKIM “{selector}”: {bits}-bit RSA key", selector=k.selector, bits=bits),
            _("The published DKIM key has a satisfactory size."),
            evidence=f"{ev}\n" + _("size: {bits} bits", bits=bits),
            references=REF,
        )


def _short(record: str, n: int = 120) -> str:
    return record if len(record) <= n else record[:n] + "…"


register(DkimCheck())
