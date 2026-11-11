"""Anti-SSRF guard: Sonde never opens a connection to a non-public IP address.

A public tool fed with arbitrary domains must not become a way to reach the operator's
internal network (loopback, LAN, cloud metadata at 169.254.169.254…) through a DNS record
pointing at a private address or a redirect towards one.

Every outgoing connection goes through `connect_public()`:

1. the host name is resolved ONCE;
2. if ANY of its addresses is not public, nothing is contacted (`BlockedDestination`);
3. the TCP connection is opened to the address that was just checked, never to the name
   again, so a DNS answer that changes between check and connection (DNS rebinding) has no
   effect. TLS keeps the original name for SNI and certificate verification.

HTTP: `GuardedTransport` applies this to every request, including each redirect hop (httpx
sends each hop through the transport), and only allows http/https on ports 80/443.
TLS (`sonde.core.tls`) calls `resolve_public()` directly.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Iterable

import httpcore
import httpx

from sonde.i18n import _

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})
_DEFAULT_PORTS = {"http": 80, "https": 443}

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
# (host, port) -> list of IP addresses (strings)
Resolver = Callable[[str, int], Awaitable[list[str]]]

_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")


class BlockedDestination(httpx.ConnectError):
    """Connection refused by the guard (non-public address, forbidden port or scheme).

    Subclass of httpx.ConnectError: for the checks it is an unreachable destination."""

    def __init__(self, message: str, *, host: str = "", addresses: Iterable[str] = ()) -> None:
        super().__init__(message)
        self.host = host
        self.addresses = list(addresses)


# ------------------------------------------------------------------ classification


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses carried inside an IPv6 one (6to4, Teredo, NAT64)."""
    out: list[ipaddress.IPv4Address] = []
    if ip.sixtofour is not None:
        out.append(ip.sixtofour)
    if ip.teredo is not None:
        out.extend(ip.teredo)
    if ip in _NAT64:
        out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return out


def is_public_ip(value: str | IPAddress) -> bool:
    """True only for a globally routable unicast address.

    Refused: loopback, private (RFC 1918, ULA fc00::/7), link-local (169.254/16, fe80::/10),
    shared/CGNAT (100.64/10), reserved, multicast, unspecified, documentation ranges, and
    IPv6 addresses that embed one of those (IPv4-mapped ::ffff:a.b.c.d, 6to4, Teredo, NAT64).
    Anything unparsable is refused."""
    try:
        ip = value if not isinstance(value, str) else ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_public_ip(ip.ipv4_mapped)
        if ip in _NAT64:  # 64:ff9b::a.b.c.d (réseaux IPv6 seuls) : seule l'IPv4 compte
            return is_public_ip(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if ip.scope_id:  # fe80::1%en0 : always local
            return False
        if any(not is_public_ip(v4) for v4 in _embedded_ipv4(ip)):
            return False
        if ip.is_site_local:
            return False
    return bool(
        ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_unspecified
    )


# ------------------------------------------------------------------ resolution


async def system_resolve(host: str, port: int) -> list[str]:
    """System resolution (getaddrinfo), duplicates removed, order kept."""
    infos = await asyncio.get_running_loop().getaddrinfo(
        host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )
    seen: dict[str, None] = {}
    for *_ignored, sockaddr in infos:
        seen.setdefault(str(sockaddr[0]), None)
    return list(seen)


async def resolve_public(host: str, port: int, resolver: Resolver | None = None) -> list[str]:
    """Addresses of `host`, all checked public. BlockedDestination if any is not public.

    Resolution errors (socket.gaierror…) are propagated unchanged."""
    addresses = await (resolver or system_resolve)(host, port)
    if not addresses:
        raise OSError(f"no address for {host}")
    blocked = [a for a in addresses if not is_public_ip(a)]
    if blocked:
        raise BlockedDestination(
            _(
                "{host} resolves to a non-public address ({addresses}): connection refused",
                host=host,
                addresses=", ".join(blocked),
            ),
            host=host,
            addresses=blocked,
        )
    return addresses


async def non_public_addresses(host: str, resolver: Resolver | None = None) -> list[str]:
    """Non-public addresses of `host` ([] if all public or if resolution fails)."""
    try:
        addresses = await (resolver or system_resolve)(host, 443)
    except (OSError, UnicodeError):
        return []
    return [a for a in addresses if not is_public_ip(a)]


# ------------------------------------------------------------------ HTTP


def check_url(url: httpx.URL) -> None:
    """Only http/https, only ports 80/443. BlockedDestination otherwise."""
    scheme = url.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedDestination(_("URL scheme not allowed: {scheme}", scheme=scheme or "?"))
    port = url.port or _DEFAULT_PORTS[scheme]
    if port not in ALLOWED_PORTS:
        raise BlockedDestination(
            _("port {port} not allowed (80/443 only): {url}", port=port, url=str(url)),
            host=url.host,
        )


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """httpcore network backend: resolves, checks, then connects to the verified IP."""

    def __init__(
        self, inner: httpcore.AsyncNetworkBackend, resolver: Resolver | None = None
    ) -> None:
        self._inner = inner
        self._resolver = resolver

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ) -> httpcore.AsyncNetworkStream:
        if port not in ALLOWED_PORTS:
            raise BlockedDestination(
                _("port {port} not allowed (80/443 only): {url}", port=port, url=host),
                host=host,
            )
        try:
            addresses = await asyncio.wait_for(resolve_public(host, port, self._resolver), timeout)
        except (OSError, UnicodeError) as exc:
            raise httpcore.ConnectError(f"{host}: {exc}") from exc
        except TimeoutError as exc:
            raise httpcore.ConnectTimeout(f"{host}: DNS timeout") from exc
        last: Exception | None = None
        for address in addresses:
            try:
                return await self._inner.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        assert last is not None
        raise last

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):  # noqa: ANN001
        raise BlockedDestination(_("Unix sockets are not allowed"))

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class GuardedTransport(httpx.AsyncHTTPTransport):
    """httpx transport that applies the guard to every request (and so every redirect)."""

    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        # httpcore exposes no public setter: the pool attribute is checked by the tests
        # (dependency versions are pinned in requirements.lock).
        pool = self._pool
        inner = network_backend or pool._network_backend
        pool._network_backend = GuardedBackend(inner, resolver)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        check_url(request.url)
        return await super().handle_async_request(request)
