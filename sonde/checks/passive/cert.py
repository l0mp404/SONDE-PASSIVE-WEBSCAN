"""Certificat TLS : validité, jours restants, émetteur, couverture du domaine, chaîne."""

from __future__ import annotations

from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from sonde.checks.base import BaseCheck, register
from sonde.core.context import Context
from sonde.core.finding import Finding
from sonde.core.target import Target
from sonde.core.tls import probe
from sonde.i18n import N_, _

REF = [
    "https://developer.mozilla.org/docs/Glossary/Digital_certificate",
    "https://letsencrypt.org/docs/",
]


def fix_renew(d: str) -> str:
    return (
        _("Renew the certificate (e.g. Let's Encrypt, free and automatable):")
        + f"\nsudo certbot --nginx -d {d} -d www.{d}\n"
        + _("# or at your hosting provider: enable automatic renewal")
    )


def hostname_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return "." in host and host.split(".", 1)[1] == pattern[2:]
    return pattern == host


def _name_attr(name: x509.Name, oid) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else None


def san_dns_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    return list(ext.value.get_values_for_type(x509.DNSName))


class CertCheck(BaseCheck):
    id = "web.cert"
    name = N_("TLS certificate")
    category = "web"
    order = 2

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        report = await probe(ctx, target)
        if report.handshake is None or report.handshake.cert_der is None:
            return [
                self.finding(
                    "crit",
                    _("No TLS certificate presented"),
                    _(
                        "The server did not provide a certificate: encrypted connection is impossible."
                    ),
                    fix=fix_renew(target.domain),
                    references=REF,
                )
            ]
        cert = x509.load_der_x509_certificate(report.handshake.cert_der)
        d = target.domain
        now = datetime.now(UTC)
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
        days = (not_after - now).days
        issuer = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME) or _name_attr(
            cert.issuer, NameOID.COMMON_NAME
        )
        subject_cn = _name_attr(cert.subject, NameOID.COMMON_NAME)
        sans = san_dns_names(cert)
        evidence = _(
            "Subject: {subject}\nIssuer: {issuer}\nValid from {start} to {end} ({days} days left)"
            "\nSAN: {sans}",
            subject=subject_cn,
            issuer=issuer,
            start=f"{not_before:%Y-%m-%d}",
            end=f"{not_after:%Y-%m-%d}",
            days=days,
            sans=", ".join(sans[:8]) + ("…" if len(sans) > 8 else ""),
        )
        findings: list[Finding] = []
        fix = fix_renew(d)

        # --- validité temporelle
        if now > not_after:
            findings.append(
                self.finding(
                    "crit",
                    _("Certificate expired {n} day(s) ago", n=-days),
                    _(
                        "The certificate is no longer valid: browsers show a red warning page "
                        "and most visitors turn back."
                    ),
                    fix=fix,
                    evidence=evidence,
                    references=REF,
                )
            )
        elif now < not_before:
            findings.append(
                self.finding(
                    "crit",
                    _("Certificate not yet valid"),
                    _("The validity start date is in the future: browsers reject it."),
                    fix=_("Check the server clock and reissue the certificate."),
                    evidence=evidence,
                    references=REF,
                )
            )
        elif days <= 7:
            findings.append(
                self.finding(
                    "crit",
                    _("Certificate expires in {n} day(s)", n=days),
                    _(
                        "The certificate is about to expire. After that, the site will show a "
                        "security warning to every visitor."
                    ),
                    fix=fix,
                    evidence=evidence,
                    references=REF,
                )
            )
        elif days <= 30:
            findings.append(
                self.finding(
                    "warn",
                    _("Certificate expires in {n} days", n=days),
                    _(
                        "The certificate expires soon. If renewal is not automated, schedule it "
                        "now."
                    ),
                    fix=fix,
                    evidence=evidence,
                    references=REF,
                )
            )

        # --- couverture du domaine
        covered = any(hostname_matches(n, d) for n in sans)
        if not covered:
            findings.append(
                self.finding(
                    "crit",
                    _("The certificate does not cover this domain"),
                    _(
                        "The certificate presented was not issued for “{d}”: browsers show a "
                        "“wrong name” error.",
                        d=d,
                    ),
                    fix=_(
                        "Reissue a certificate including {d} in its alternative names (SAN).", d=d
                    )
                    + "\n"
                    + fix,  # fmt: skip
                    evidence=evidence,
                    references=REF,
                )
            )
        elif not any(hostname_matches(n, f"www.{d}") for n in sans) and not d.startswith("www."):
            findings.append(
                self.finding(
                    "info",
                    _("The certificate does not cover www.{d}", d=d),
                    _(
                        "Visitors typing “www.” will see a certificate error. Ignore this if "
                        "the www subdomain is not used."
                    ),
                    fix=_("Add www.{d} to the certificate SANs.", d=d),
                    evidence=evidence,
                    references=REF,
                )
            )

        # --- chaîne de confiance
        if not report.verified:
            findings.append(
                self.finding(
                    "crit",
                    _("Untrusted certificate (invalid chain of trust)"),
                    _(
                        "The certificate is not validated by trusted authorities: self-signed, "
                        "unknown authority or missing intermediate certificate. Browsers show a "
                        "security warning."
                    ),
                    fix=_(
                        "Install the full chain (certificate + intermediates, “fullchain.pem”) "
                        "provided by the certificate authority."
                    ),
                    evidence=evidence + "\n" + _("Error: {error}", error=report.verify_error),
                    references=REF,
                )
            )

        # --- robustesse cryptographique
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
            findings.append(
                self.finding(
                    "warn",
                    _("Weak RSA key ({bits} bits)", bits=key.key_size),
                    _("A key under 2048 bits is considered insufficient."),
                    fix=_("Reissue the certificate with an RSA 2048+ or ECDSA P-256 key."),
                    evidence=evidence,
                    references=REF,
                )
            )
        sig = cert.signature_hash_algorithm
        if sig is not None and isinstance(sig, hashes.SHA1 | hashes.MD5):
            findings.append(
                self.finding(
                    "crit",
                    _("Obsolete {algo} signature", algo=sig.name.upper()),
                    _(
                        "The certificate's signature algorithm is broken: modern browsers "
                        "reject it."
                    ),
                    fix=_("Reissue the certificate (SHA-256)."),
                    evidence=evidence,
                    references=REF,
                )
            )

        if not findings:
            key_desc = _key_desc(key)
            findings.append(
                self.finding(
                    "ok",
                    _("Valid certificate ({n} days left)", n=days),
                    _(
                        "Certificate issued by {issuer}, trusted by browsers, covering the "
                        "domain. Key: {key}.",
                        issuer=issuer,
                        key=key_desc,
                    ),
                    evidence=evidence,
                    references=REF,
                )
            )
        elif all(f.severity in ("info",) for f in findings):
            findings.insert(
                0,
                self.finding(
                    "ok",
                    _("Valid certificate ({n} days left)", n=days),
                    _(
                        "Certificate issued by {issuer}, trusted by browsers, covering the domain.",
                        issuer=issuer,
                    ),
                    evidence=evidence,
                    references=REF,
                ),
            )
        return findings


def _key_desc(key) -> str:
    if isinstance(key, rsa.RSAPublicKey):
        return _("RSA {bits} bits", bits=key.key_size)
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA {key.curve.name}"
    if isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        return type(key).__name__.replace("PublicKey", "")
    return type(key).__name__


register(CertCheck())
