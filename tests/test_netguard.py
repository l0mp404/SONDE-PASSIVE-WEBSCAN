"""Garde anti-SSRF : classification des adresses, transport HTTP, redirections, TLS, MTA-STS."""

from __future__ import annotations

import asyncio
import ssl

import httpcore
import httpx
import pytest
from sonde.core.netguard import BlockedDestination, GuardedTransport, is_public_ip

from sonde.checks.base import BaseCheck
from sonde.checks.passive.mta_sts import MtaStsCheck
from sonde.core import netguard, tls
from sonde.core.context import Context, make_http_client, make_resolver
from sonde.core.runner import NON_PUBLIC_CHECK_ID, run_scan
from sonde.core.target import parse_target

# ------------------------------------------------------------------ classification

NON_PUBLIC = [
    "127.0.0.1", "127.8.9.10", "0.0.0.0", "10.0.0.1", "172.16.5.4", "192.168.1.1",
    "169.254.169.254",  # métadonnées cloud
    "100.64.0.1",  # CGNAT
    "192.0.2.1", "198.51.100.7", "203.0.113.9",  # documentation
    "198.18.0.1",  # benchmark
    "224.0.0.1", "239.255.255.250",  # multicast
    "240.0.0.1", "255.255.255.255",  # réservé / broadcast
    "::1", "::", "fe80::1", "fe80::1%lo0", "fc00::1", "fd12:3456::1", "fec0::1",
    "ff02::1",  # multicast IPv6
    "2001:db8::1",  # documentation IPv6
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",  # IPv4-mapped
    "::ffff:7f00:1",  # IPv4-mapped écrit en hexadécimal
    "::127.0.0.1",  # IPv4-compatible (déprécié)
    "2002:7f00:1::1",  # 6to4 embarquant 127.0.0.1
    "2002:c0a8:101::1",  # 6to4 embarquant 192.168.1.1
    "64:ff9b::10.0.0.1",  # NAT64 embarquant une adresse privée
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
    "not-an-ip", "",
]  # fmt: skip
PUBLIC = [
    "93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888",
    "::ffff:8.8.8.8", "64:ff9b::808:808",
]  # fmt: skip


@pytest.mark.parametrize("address", NON_PUBLIC)
def test_non_public_addresses_are_refused(address):
    assert not is_public_ip(address)


@pytest.mark.parametrize("address", PUBLIC)
def test_public_addresses_are_allowed(address):
    assert is_public_ip(address)


# ------------------------------------------------------------------ outillage


def fake_resolver(table: dict[str, list[str]]):
    calls: list[str] = []

    async def resolve(host: str, port: int) -> list[str]:
        calls.append(host)
        if host not in table:
            raise OSError(f"unknown host {host}")
        return table[host]

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


class RecordingBackend(httpcore.AsyncMockBackend):
    """Backend simulé qui note l'hôte réellement passé à connect_tcp."""

    def __init__(self, responses: list[bytes]) -> None:
        super().__init__([])
        self._responses = list(responses)
        self.connected: list[tuple[str, int]] = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.connected.append((host, port))
        return httpcore.AsyncMockStream([self._responses.pop(0)])


def response(status: int, headers: dict[str, str] | None = None, body: bytes = b"") -> bytes:
    reason = {200: "OK", 301: "Moved Permanently", 302: "Found"}.get(status, "X")
    lines = [f"HTTP/1.1 {status} {reason}", f"Content-Length: {len(body)}"]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def client(backend, table) -> httpx.AsyncClient:
    resolver = fake_resolver(table)
    transport = GuardedTransport(resolver=resolver, network_backend=backend)
    return make_http_client(transport=transport)


def run(coro):
    return asyncio.run(coro)


# ------------------------------------------------------------------ transport HTTP


def test_transport_installs_the_guard_on_the_pool():
    transport = GuardedTransport()
    assert isinstance(transport._pool._network_backend, netguard.GuardedBackend)


def test_default_client_uses_guarded_transport_without_env_proxies(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:3128")

    async def go():
        c = make_http_client()
        try:
            assert isinstance(c._transport, GuardedTransport)
            assert not any(t for t in c._mounts.values())  # aucun proxy monté
        finally:
            await c.aclose()

    run(go())


def test_connects_to_the_verified_ip_not_the_name():
    backend = RecordingBackend([response(200, body=b"hi")])

    async def go():
        async with client(backend, {"public.test": ["93.184.216.34"]}) as c:
            return await c.get("http://public.test/")

    resp = run(go())
    assert resp.status_code == 200
    assert backend.connected == [("93.184.216.34", 80)]


@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"])
def test_request_to_private_address_is_blocked(address):
    backend = RecordingBackend([response(200)])

    async def go():
        async with client(backend, {"evil.test": [address]}) as c:
            await c.get("http://evil.test/")

    with pytest.raises(BlockedDestination) as info:
        run(go())
    assert address in str(info.value)
    assert backend.connected == []  # rien n'a été contacté


def test_mixed_public_and_private_answers_are_blocked():
    backend = RecordingBackend([response(200)])

    async def go():
        async with client(backend, {"mixed.test": ["93.184.216.34", "10.0.0.1"]}) as c:
            await c.get("https://mixed.test/")

    with pytest.raises(BlockedDestination):
        run(go())
    assert backend.connected == []


def test_ip_literal_url_is_checked_too():
    backend = RecordingBackend([response(200)])

    async def go():
        async with client(backend, {"127.0.0.1": ["127.0.0.1"]}) as c:
            await c.get("http://127.0.0.1/")

    with pytest.raises(BlockedDestination):
        run(go())


def test_redirect_hop_to_private_address_is_blocked():
    backend = RecordingBackend([response(302, {"Location": "http://internal.test/admin"})])
    table = {"public.test": ["93.184.216.34"], "internal.test": ["192.168.0.10"]}

    async def go():
        async with client(backend, table) as c:
            await c.get("http://public.test/", follow_redirects=True)

    with pytest.raises(BlockedDestination):
        run(go())
    assert backend.connected == [("93.184.216.34", 80)]  # seul le premier saut est parti


def test_redirect_to_metadata_ip_literal_is_blocked():
    backend = RecordingBackend([response(301, {"Location": "http://169.254.169.254/latest/"})])
    table = {"public.test": ["93.184.216.34"], "169.254.169.254": ["169.254.169.254"]}

    async def go():
        async with client(backend, table) as c:
            await c.get("http://public.test/", follow_redirects=True)

    with pytest.raises(BlockedDestination):
        run(go())


@pytest.mark.parametrize(
    "location",
    ["http://public2.test:8080/", "https://public2.test:22/", "http://public2.test:6379/"],
)
def test_redirect_to_other_port_is_blocked(location):
    backend = RecordingBackend([response(302, {"Location": location})])
    table = {"public.test": ["93.184.216.34"], "public2.test": ["93.184.216.35"]}

    async def go():
        async with client(backend, table) as c:
            await c.get("http://public.test/", follow_redirects=True)

    with pytest.raises(BlockedDestination):
        run(go())
    assert len(backend.connected) == 1


@pytest.mark.parametrize("location", ["ftp://public.test/", "file:///etc/passwd", "gopher://x/"])
def test_redirect_to_other_scheme_is_blocked(location):
    backend = RecordingBackend([response(302, {"Location": location})])

    async def go():
        async with client(backend, {"public.test": ["93.184.216.34"]}) as c:
            await c.get("http://public.test/", follow_redirects=True)

    with pytest.raises(httpx.HTTPError):  # BlockedDestination ou UnsupportedProtocol
        run(go())
    assert len(backend.connected) == 1


def test_initial_request_to_non_standard_port_is_blocked():
    backend = RecordingBackend([response(200)])

    async def go():
        async with client(backend, {"public.test": ["93.184.216.34"]}) as c:
            await c.get("http://public.test:8000/")

    with pytest.raises(BlockedDestination):
        run(go())
    assert backend.connected == []


def test_redirect_between_public_hosts_still_works():
    backend = RecordingBackend(
        [response(301, {"Location": "https://www.public.test/"}), response(200, body=b"ok")]
    )
    table = {"public.test": ["93.184.216.34"], "www.public.test": ["2606:4700::1"]}

    async def go():
        async with client(backend, table) as c:
            return await c.get("http://public.test/", follow_redirects=True)

    resp = run(go())
    assert resp.status_code == 200 and resp.text == "ok"
    assert backend.connected == [("93.184.216.34", 80), ("2606:4700::1", 443)]


def test_resolution_failure_is_an_ordinary_connect_error():
    backend = RecordingBackend([])

    async def go():
        async with client(backend, {}) as c:
            await c.get("https://nowhere.test/")

    with pytest.raises(httpx.ConnectError) as info:
        run(go())
    assert not isinstance(info.value, BlockedDestination)


# ------------------------------------------------------------------ TLS


def test_tls_connect_refuses_private_address(monkeypatch):
    opened = []

    async def fake_open_connection(*args, **kwargs):  # ne doit jamais être appelé
        opened.append((args, kwargs))
        raise AssertionError("connection attempted")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    resolver = fake_resolver({"evil.test": ["127.0.0.1"]})
    with pytest.raises(BlockedDestination):
        run(tls.connect("evil.test", resolver=resolver, timeout=2))
    assert opened == []


def test_tls_connect_targets_verified_ip_and_keeps_sni(monkeypatch):
    seen = {}

    async def fake_open_connection(host, port, *, ssl, server_hostname):
        seen.update(host=host, port=port, sni=server_hostname)
        raise ConnectionRefusedError("stop here")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    resolver = fake_resolver({"public.test": ["93.184.216.34"]})
    with pytest.raises(ConnectionRefusedError):
        run(tls.connect("public.test", resolver=resolver, timeout=2))
    assert seen == {"host": "93.184.216.34", "port": 443, "sni": "public.test"}


def test_tls_ssl_error_is_not_retried_on_other_addresses(monkeypatch):
    calls = []

    async def fake_open_connection(host, port, **kwargs):
        calls.append(host)
        raise ssl.SSLError("handshake failure")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    resolver = fake_resolver({"public.test": ["93.184.216.34", "93.184.216.35"]})
    with pytest.raises(ssl.SSLError):
        run(tls.connect("public.test", resolver=resolver, timeout=2))
    assert calls == ["93.184.216.34"]


# ------------------------------------------------------------------ MTA-STS


def test_mta_sts_policy_host_on_private_address_is_not_fetched(monkeypatch):
    from sonde.checks.passive import mta_sts

    async def fake_txt(ctx, name):
        return ["v=STSv1; id=20260101"]

    monkeypatch.setattr(mta_sts, "txt_records", fake_txt)
    backend = RecordingBackend([response(200, body=b"version: STSv1\n")])
    resolver = fake_resolver({"mta-sts.example.com": ["10.0.0.5"]})

    async def go():
        http = make_http_client(
            transport=GuardedTransport(resolver=resolver, network_backend=backend)
        )
        ctx = Context(http=http, resolver=make_resolver(), addr_resolver=resolver)
        try:
            return await MtaStsCheck().run(parse_target("example.com"), ctx)
        finally:
            await http.aclose()

    findings = run(go())
    assert backend.connected == []
    assert [f.title for f in findings] == ["MTA-STS: policy unreachable"]
    assert "10.0.0.5" in findings[0].evidence


# ------------------------------------------------------------------ pré-vol du runner


class _Probe(BaseCheck):
    def __init__(self, check_id: str, category: str, *, contacts_target: bool = True) -> None:
        self.id, self.name, self.category = check_id, "TLS certificate", category
        self.contacts_target = contacts_target
        self.ran = False

    async def run(self, target, ctx):
        self.ran = True
        return [self.finding("ok", "ran", "ran")]


def test_runner_skips_web_checks_when_target_is_private():
    web, crtsh, email = (
        _Probe("web.x", "web"),
        _Probe("web.crtsh", "web", contacts_target=False),
        _Probe("email.x", "email"),
    )
    resolver = fake_resolver({"intranet.example.com": ["10.0.0.7"]})

    async def go():
        http = make_http_client()
        ctx = Context(http=http, resolver=make_resolver(), addr_resolver=resolver)
        try:
            return await run_scan(parse_target("intranet.example.com"), [web, crtsh, email], ctx)
        finally:
            await http.aclose()

    result = run(go())
    assert not web.ran and crtsh.ran and email.ran
    assert "web.x" in result.checks_failed
    assert "web" not in result.categories  # pas de note web trompeuse
    notice = [f for f in result.findings if f.check_id == NON_PUBLIC_CHECK_ID]
    assert len(notice) == 1 and notice[0].severity == "info"
    assert notice[0].evidence == "10.0.0.7"
    assert notice[0].title_en.startswith("Target resolves to a non-public IP address")


def test_runner_runs_everything_for_a_public_target():
    web = _Probe("web.x", "web")
    resolver = fake_resolver({"example.com": ["93.184.216.34"]})

    async def go():
        http = make_http_client()
        ctx = Context(http=http, resolver=make_resolver(), addr_resolver=resolver)
        try:
            return await run_scan(parse_target("example.com"), [web], ctx)
        finally:
            await http.aclose()

    result = run(go())
    assert web.ran and result.checks_failed == [] and result.categories == ["web"]
