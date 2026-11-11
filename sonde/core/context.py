from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TypeVar

import dns.asyncresolver
import httpx

from sonde import USER_AGENT
from sonde.core.netguard import GuardedTransport, Resolver, system_resolve

HTTP_TIMEOUT = 10.0
DNS_TIMEOUT = 5.0
TLS_TIMEOUT = 10.0
CHECK_TIMEOUT = 30.0

T = TypeVar("T")


@dataclass(slots=True)
class Context:
    """Ressources partagées par les checks d'un scan."""

    http: httpx.AsyncClient
    resolver: dns.asyncresolver.Resolver
    dkim_selector: str | None = None
    check_timeout: float = CHECK_TIMEOUT
    tls_timeout: float = TLS_TIMEOUT
    # Résolution d'adresses avant toute connexion (garde anti-SSRF, voir sonde.core.netguard)
    addr_resolver: Resolver = system_resolve
    # Résultats partagés entre checks (requêtes DNS, page d'accueil, sonde TLS…)
    cache: dict[str, asyncio.Future] = field(default_factory=dict)

    async def shared(self, key: str, factory: Callable[[], Awaitable[T]]) -> T:
        """Exécute `factory()` une seule fois par clé ; les appels suivants attendent le résultat.

        Protégé par `shield` : le timeout d'un check n'annule pas le travail partagé.
        """
        fut = self.cache.get(key)
        if fut is None:
            fut = asyncio.ensure_future(factory())
            self.cache[key] = fut
        return await asyncio.shield(fut)


def make_http_client(*, resolver: Resolver | None = None, **kwargs) -> httpx.AsyncClient:
    """Client HTTP dont CHAQUE connexion (redirections comprises) passe par la garde anti-SSRF."""
    kwargs.setdefault("timeout", HTTP_TIMEOUT)
    kwargs.setdefault("headers", {"User-Agent": USER_AGENT})
    kwargs.setdefault("follow_redirects", False)
    kwargs.setdefault("max_redirects", 5)
    kwargs.setdefault("transport", GuardedTransport(resolver=resolver))
    # Pas de proxy ni de .netrc venant de l'environnement : la garde doit voir la vraie cible.
    kwargs["trust_env"] = False
    return httpx.AsyncClient(**kwargs)


def make_resolver() -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    return resolver


def make_context(*, dkim_selector: str | None = None) -> Context:
    return Context(http=make_http_client(), resolver=make_resolver(), dkim_selector=dkim_selector)
