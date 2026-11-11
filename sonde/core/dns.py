"""Helpers DNS partagés par les checks.

- NXDOMAIN / NoAnswer => liste vide (l'enregistrement n'existe pas).
- Timeout / SERVFAIL => exception (le runner la transforme en « contrôle non réalisé »,
  on ne conclut jamais « absent » sur une erreur réseau).
- Les requêtes identiques sont dédupliquées via `ctx.shared`.
"""

from __future__ import annotations

import dns.resolver
from dns.rdata import Rdata

from sonde.core.context import Context


async def resolve(ctx: Context, name: str, rtype: str) -> list[Rdata]:
    name, rtype = name.lower().rstrip("."), rtype.upper()
    return list(await ctx.shared(f"dns:{name}:{rtype}", lambda: _resolve(ctx, name, rtype)))


async def _resolve(ctx: Context, name: str, rtype: str) -> list[Rdata]:
    try:
        answer = await ctx.resolver.resolve(name, rtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return list(answer)


async def txt_records(ctx: Context, name: str) -> list[str]:
    """Enregistrements TXT, chaque enregistrement ayant ses chaînes concaténées."""
    return [
        "".join(part.decode("utf-8", "replace") for part in rdata.strings)  # type: ignore[attr-defined]
        for rdata in await resolve(ctx, name, "TXT")
    ]


async def mx_records(ctx: Context, domain: str) -> list[tuple[int, str]]:
    """(préférence, hôte) triés. Un « null MX » (RFC 7505) donne l'hôte vide ''."""
    out = [
        (r.preference, str(r.exchange).rstrip(".").lower())  # type: ignore[attr-defined]
        for r in await resolve(ctx, domain, "MX")
    ]
    return sorted(out)
