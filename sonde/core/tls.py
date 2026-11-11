"""Sonde TLS native (ssl + asyncio) : certificat, chaîne, versions acceptées.

`connect()` est le seul point qui touche le réseau. Il passe par la garde anti-SSRF : le nom
est résolu une fois, toutes ses adresses doivent être publiques, et la connexion TCP vise
l'adresse vérifiée (le nom d'origine sert au SNI et à la vérification du certificat).
"""

from __future__ import annotations

import asyncio
import ssl
from contextlib import suppress
from dataclasses import dataclass, field

import certifi

from sonde.core.context import Context
from sonde.core.netguard import Resolver, resolve_public
from sonde.core.target import Target

VERSIONS: dict[str, ssl.TLSVersion] = {
    "TLS 1.0": ssl.TLSVersion.TLSv1,
    "TLS 1.1": ssl.TLSVersion.TLSv1_1,
    "TLS 1.2": ssl.TLSVersion.TLSv1_2,
    "TLS 1.3": ssl.TLSVersion.TLSv1_3,
}


@dataclass(slots=True)
class Handshake:
    protocol: str | None
    cipher: str | None
    cert_der: bytes | None


@dataclass(slots=True)
class TlsReport:
    verified: bool
    verify_error: str | None
    handshake: Handshake | None  # None si aucune connexion TLS n'a abouti
    # version -> True (acceptée) / False (refusée) / None (non testable)
    versions: dict[str, bool | None] = field(default_factory=dict)


async def connect(
    host: str,
    *,
    port: int = 443,
    verify: bool = True,
    min_version: ssl.TLSVersion | None = None,
    max_version: ssl.TLSVersion | None = None,
    timeout: float = 10.0,
    resolver: Resolver | None = None,
) -> Handshake:
    """Ouvre une connexion TLS, lit les infos de session, referme.

    Lève ssl.SSLError / OSError, ou BlockedDestination si `host` n'est pas public."""
    if verify:
        # Magasin certifi (comme httpx) : le Python de python.org n'embarque pas de CA système.
        sslctx = ssl.create_default_context(cafile=certifi.where())
    else:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        sslctx.check_hostname = False
        sslctx.verify_mode = ssl.CERT_NONE
    if min_version is not None:
        sslctx.minimum_version = min_version
    if max_version is not None:
        sslctx.maximum_version = max_version
    if min_version is not None and min_version < ssl.TLSVersion.TLSv1_2:
        # OpenSSL 3 refuse TLS < 1.2 au niveau de sécurité par défaut.
        sslctx.set_ciphers("ALL:@SECLEVEL=0")

    _reader, writer = await asyncio.wait_for(_open(host, port, sslctx, resolver), timeout)
    try:
        obj = writer.get_extra_info("ssl_object")
        cipher = obj.cipher()
        return Handshake(
            protocol=obj.version(),
            cipher=cipher[0] if cipher else None,
            cert_der=obj.getpeercert(binary_form=True),
        )
    finally:
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()


async def _open(host: str, port: int, sslctx: ssl.SSLContext, resolver: Resolver | None):
    """Connexion TLS vers une adresse vérifiée publique de `host` (essayées dans l'ordre)."""
    last: OSError | None = None
    for address in await resolve_public(host, port, resolver):
        try:
            return await asyncio.open_connection(address, port, ssl=sslctx, server_hostname=host)
        except ssl.SSLError:
            raise  # réponse TLS du serveur : inutile d'essayer une autre adresse
        except OSError as exc:
            last = exc
    assert last is not None
    raise last


async def probe(ctx: Context, target: Target) -> TlsReport:
    """Rapport TLS partagé entre checks. Lève OSError/TimeoutError si le port 443 ne répond pas."""
    return await ctx.shared(f"tls:{target.domain}", lambda: _probe(ctx, target.domain))


async def _probe(ctx: Context, host: str) -> TlsReport:
    t, r = ctx.tls_timeout, ctx.addr_resolver
    verified, verify_error, hs = True, None, None
    try:
        hs = await connect(host, verify=True, timeout=t, resolver=r)
    except ssl.SSLCertVerificationError as exc:
        verified, verify_error = False, exc.verify_message or str(exc)
    except ssl.SSLError as exc:
        verified, verify_error = False, f"{exc.reason or exc}"
    if hs is None:
        # Certificat non reconnu : on le récupère quand même pour l'analyser.
        hs = await connect(host, verify=False, timeout=t, resolver=r)

    results = await asyncio.gather(
        *(_try_version(host, v, t, r) for v in VERSIONS.values()), return_exceptions=False
    )
    return TlsReport(
        verified=verified,
        verify_error=verify_error,
        handshake=hs,
        versions=dict(zip(VERSIONS, results, strict=True)),
    )


async def _try_version(
    host: str, version: ssl.TLSVersion, timeout: float, resolver: Resolver | None
) -> bool | None:
    try:
        await connect(
            host,
            verify=False,
            min_version=version,
            max_version=version,
            timeout=timeout,
            resolver=resolver,
        )
        return True
    except ssl.SSLError:
        return False  # handshake refusé : version non supportée
    except ValueError:
        return None  # OpenSSL local ne sait pas parler cette version
    except (OSError, TimeoutError):
        return None
