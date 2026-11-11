"""Récupération partagée de la page d'accueil HTTPS (une seule requête pour tous les checks)."""

from __future__ import annotations

import codecs
from dataclasses import dataclass

import httpx

from sonde.core.context import Context
from sonde.core.target import Target

MAX_BODY = 2 * 1024 * 1024  # on ne lit jamais plus de 2 Mo


@dataclass(slots=True)
class HomePage:
    response: httpx.Response  # réponse finale (après redirections)
    history: list[httpx.Response]  # redirections intermédiaires
    html: str
    truncated: bool

    @property
    def url(self) -> str:
        return str(self.response.url)

    @property
    def all_responses(self) -> list[httpx.Response]:
        return [*self.history, self.response]


async def fetch_home(ctx: Context, target: Target) -> HomePage:
    """GET https://<domaine>/ en suivant les redirections. Lève httpx.HTTPError si injoignable."""
    return await ctx.shared(f"home:{target.domain}", lambda: _fetch(ctx, target))


async def fetch_text(
    ctx: Context, url: str, *, max_bytes: int = MAX_BODY, **kwargs
) -> tuple[httpx.Response, str]:
    """GET `url` (sans suivre les redirections) en lisant au plus `max_bytes`."""
    resp, body, _truncated = await fetch_limited(ctx, url, max_bytes=max_bytes, **kwargs)
    return resp, decode_body(resp, body)


async def fetch_limited(
    ctx: Context, url: str, *, max_bytes: int = MAX_BODY, **kwargs
) -> tuple[httpx.Response, bytes, bool]:
    """GET `url` en flux, coupé à `max_bytes`. -> (réponse, corps, tronqué).

    `kwargs` : params, timeout… (sans suivre les redirections)."""
    async with ctx.http.stream("GET", url, follow_redirects=False, **kwargs) as resp:
        body, truncated = await _read_limited(resp, max_bytes)
    return resp, body, truncated


async def _fetch(ctx: Context, target: Target) -> HomePage:
    async with ctx.http.stream("GET", target.url, follow_redirects=True) as resp:
        body, truncated = await _read_limited(resp, MAX_BODY)
    return HomePage(
        response=resp, history=list(resp.history), html=decode_body(resp, body), truncated=truncated
    )


async def _read_limited(resp: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    size = 0
    async for chunk in resp.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= max_bytes:
            return b"".join(chunks)[:max_bytes], True
    return b"".join(chunks), False


def decode_body(resp: httpx.Response, body: bytes) -> str:
    enc = resp.charset_encoding or "utf-8"
    try:
        codecs.lookup(enc)
    except LookupError:
        enc = "utf-8"
    return body.decode(enc, "replace")
