"""Orchestration asynchrone des checks."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from sonde.checks.base import Check
from sonde.core.context import Context
from sonde.core.finding import Finding, Severity, worst
from sonde.core.netguard import non_public_addresses
from sonde.core.target import Target
from sonde.i18n import N_, _

log = logging.getLogger(__name__)

MAX_PARALLEL = 8
# Constat émis quand la cible pointe vers une adresse non publique (contrôles web non lancés).
NON_PUBLIC_CHECK_ID = "web.public_address"


@dataclass(slots=True)
class CheckEvent:
    kind: Literal["started", "finished"]
    check: Check
    findings: list[Finding] = field(default_factory=list)
    worst: Severity | None = None


@dataclass(slots=True)
class ScanResult:
    target: Target
    started_at: datetime
    ended_at: datetime
    findings: list[Finding]
    checks_run: list[str] = field(default_factory=list)  # ids de tous les checks lancés
    checks_failed: list[str] = field(default_factory=list)  # … dont erreur/timeout/non lancés
    categories: list[str] = field(default_factory=list)  # catégories notées (web/email)
    lang: str = "en"  # langue des textes des constats

    def to_dict(self) -> dict:
        return {
            "target": self.target.domain,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat(),
            "lang": self.lang,
            "checks_run": self.checks_run,
            "checks_failed": self.checks_failed,
            "findings": [f.to_dict() for f in self.findings],
        }


EventCallback = Callable[[CheckEvent], None]


def contacts_target(check: Check) -> bool:
    """False pour les checks qui n'interrogent qu'un service tiers (ex. crt.sh)."""
    return getattr(check, "contacts_target", True)


async def run_scan(
    target: Target,
    checks: Sequence[Check],
    ctx: Context,
    *,
    lang: str = "en",
    on_event: EventCallback | None = None,
    max_parallel: int = MAX_PARALLEL,
) -> ScanResult:
    started = datetime.now(UTC)
    sem = asyncio.Semaphore(max_parallel)
    failed: list[str] = []
    extra: list[Finding] = []
    categories = {c.category for c in checks}

    # Garde anti-SSRF : une cible qui résout vers une adresse privée n'est jamais contactée.
    to_run = list(checks)
    web = [c for c in checks if c.category == "web" and contacts_target(c)]
    blocked = await non_public_addresses(target.domain, ctx.addr_resolver) if web else []
    if blocked:
        to_run = [c for c in checks if c not in web]
        failed.extend(c.id for c in web)
        categories.discard("web")  # rien de noté côté web : pas de note trompeuse
        extra.append(non_public_finding(target, blocked))
        if on_event:
            for c in web:
                on_event(CheckEvent("finished", c, [], Severity.INFO))

    async def run_one(check: Check) -> list[Finding]:
        async with sem:
            if on_event:
                on_event(CheckEvent("started", check))
            findings, ok = await _safe_run(check, target, ctx)
            if not ok:
                failed.append(check.id)
            if on_event:
                on_event(
                    CheckEvent("finished", check, findings, worst([f.severity for f in findings]))
                )
            return findings

    results = await asyncio.gather(*(run_one(c) for c in to_run))
    return ScanResult(
        target=target,
        started_at=started,
        ended_at=datetime.now(UTC),
        findings=[*extra, *(f for fs in results for f in fs)],
        checks_run=[c.id for c in checks],
        checks_failed=sorted(failed),
        categories=sorted(categories),
        lang=lang,
    )


def non_public_finding(target: Target, addresses: list[str]) -> Finding:
    title = _("Target resolves to a non-public IP address: web checks skipped")
    return Finding(
        check_id=NON_PUBLIC_CHECK_ID,
        category="web",
        severity=Severity.INFO,
        title=title,
        title_en=title.en,
        detail=_(
            "{domain} points to a private, local or reserved address. To avoid reaching an "
            "internal network (SSRF), Sonde never connects to such addresses: the website was "
            "not contacted and is not graded. DNS-based email checks still ran.",
            domain=target.domain,
        ),
        fix=_(
            "If this domain is meant to be public, publish public A/AAAA records. "
            "Internal hosts are outside the scope of this tool."
        ),
        evidence=", ".join(addresses),
    )


def check_timeout(check: Check, ctx: Context) -> float:
    """Délai du check : celui qu'il déclare (ex. crt.sh, lent), sinon le défaut du scan."""
    return float(getattr(check, "timeout", None) or ctx.check_timeout)


async def _safe_run(check: Check, target: Target, ctx: Context) -> tuple[list[Finding], bool]:
    """Exécute un check avec timeout. -> (findings, réussi). Une erreur devient un finding info."""
    limit = check_timeout(check, ctx)
    try:
        found = await asyncio.wait_for(check.run(target, ctx), timeout=limit)
        return list(found), True
    except TimeoutError:
        return [_failure(check, _("timed out ({seconds} s)", seconds=f"{limit:g}"))], False
    except Exception as exc:  # noqa: BLE001 — un check ne doit jamais faire tomber le scan
        log.debug("check %s failed", check.id, exc_info=True)  # la cause est dans le constat
        return [_failure(check, f"{type(exc).__name__}: {exc}")], False


_FAILED_TITLE = N_("Check not completed: {name}")


def _failure(check: Check, reason: str) -> Finding:
    title = _(_FAILED_TITLE, name=_(check.name))
    return Finding(
        check_id=check.id,
        category=check.category,
        severity=Severity.INFO,
        title=title,
        title_en=title.en,
        detail=_("This check could not complete; its result is not assessed."),
        evidence=reason,
    )
