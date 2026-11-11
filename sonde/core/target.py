"""Normalisation et validation stricte de la cible.

Toute chaîne venant de l'utilisateur DOIT passer par `parse_target` avant d'être
utilisée ailleurs (DNS, HTTP, subprocess...). Le reste du code ne manipule que des
objets `Target`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import idna

from sonde.i18n import _


class InvalidTarget(ValueError):
    """La cible fournie n'est pas un nom de domaine acceptable."""


# Un label ASCII (après punycode) : lettres, chiffres, tirets internes, 1-63 car.
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_CONTROL_OR_SPACE_RE = re.compile(r"[\x00-\x20\x7f]")
_ALLOWED_PORTS = {None, 80, 443}


class InvalidSelector(ValueError):
    """Sélecteur DKIM invalide."""


_SELECTOR_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))*$")


def parse_dkim_selector(raw: str) -> str:
    """Valide un sélecteur DKIM fourni par l'utilisateur (il finit dans un nom DNS)."""
    sel = raw.strip().lower() if isinstance(raw, str) else ""
    if not sel or len(sel) > 100 or not _SELECTOR_RE.match(sel):
        raise InvalidSelector(_("invalid DKIM selector: {value}", value=repr(raw)))
    return sel


@dataclass(frozen=True, slots=True)
class Target:
    domain: str  # forme ASCII (punycode), minuscules, sans point final
    unicode_domain: str  # forme affichable

    @property
    def url(self) -> str:
        return f"https://{self.domain}/"

    @property
    def http_url(self) -> str:
        return f"http://{self.domain}/"

    def __str__(self) -> str:
        return self.domain


def parse_target(raw: str) -> Target:
    """Valide `raw` (domaine ou URL http/https) et renvoie un `Target`."""
    if not isinstance(raw, str) or not raw:
        raise InvalidTarget(_("empty target"))
    raw = raw.strip()
    if not raw or len(raw) > 2048:
        raise InvalidTarget(_("empty or too long target"))
    if _CONTROL_OR_SPACE_RE.search(raw):
        raise InvalidTarget(_("spaces and control characters are not allowed"))

    host = _extract_host(raw)
    return _validate_host(host)


def _extract_host(raw: str) -> str:
    if "://" in raw:
        parts = urlsplit(raw)
        if parts.scheme.lower() not in ("http", "https"):
            raise InvalidTarget(_("unsupported scheme: {scheme}", scheme=repr(parts.scheme)))
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise InvalidTarget(_("credentials in the URL are not allowed"))
        try:
            port = parts.port
        except ValueError as exc:
            raise InvalidTarget(_("invalid port")) from exc
        if port not in _ALLOWED_PORTS:
            raise InvalidTarget(_("unsupported port: {port}", port=port))
        if parts.hostname is None:
            raise InvalidTarget(_("missing host"))
        return parts.hostname
    # Domaine nu : aucun séparateur d'URL toléré.
    if any(c in raw for c in "/\\?#@:[]%"):
        raise InvalidTarget(_("forbidden character in the domain"))
    return raw


def _validate_host(host: str) -> Target:
    host = host.rstrip(".").lower() if host.endswith(".") else host.lower()
    if not host:
        raise InvalidTarget(_("empty domain"))

    # IP littérales refusées (IPv4 ; IPv6 déjà exclue par les ':').
    if re.fullmatch(r"[0-9.]+", host) or re.fullmatch(r"0x[0-9a-f.]+", host):
        raise InvalidTarget(_("an IP address is not a domain"))

    try:
        ascii_host = idna.encode(host, uts46=True, std3_rules=True).decode("ascii")
    except (idna.IDNAError, UnicodeError) as exc:
        raise InvalidTarget(_("invalid domain: {error}", error=exc)) from exc

    ascii_host = ascii_host.lower()
    if len(ascii_host) > 253:
        raise InvalidTarget(_("domain too long (>253)"))
    labels = ascii_host.split(".")
    if len(labels) < 2:
        raise InvalidTarget(_("a full domain name is required (e.g. example.com)"))
    if not all(_LABEL_RE.match(label) for label in labels):
        raise InvalidTarget(_("invalid domain label"))
    if not _TLD_RE.match(labels[-1]):
        raise InvalidTarget(_("invalid TLD"))

    try:
        unicode_host = idna.decode(ascii_host)
    except (idna.IDNAError, UnicodeError):
        unicode_host = ascii_host
    return Target(domain=ascii_host, unicode_domain=unicode_host)
