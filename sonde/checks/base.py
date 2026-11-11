from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, Protocol, runtime_checkable

from sonde.core.context import Context
from sonde.core.finding import Finding, Severity
from sonde.core.target import Target


@runtime_checkable
class Check(Protocol):
    id: str
    name: str  # en anglais, marqué N_() : traduit à l'affichage avec _()
    category: Literal["web", "email"]

    async def run(self, target: Target, ctx: Context) -> list[Finding]: ...


class BaseCheck:
    """Socle optionnel : fournit `finding()` qui remplit check_id/category."""

    id: str
    name: str
    category: Literal["web", "email"]
    order: int = 100  # ordre d'affichage
    optional: bool = False  # option de scan : n'est exécuté que sur demande explicite
    contacts_target: bool = True  # False : n'interroge qu'un service tiers (ex. crt.sh)

    def finding(
        self,
        severity: Severity | str,
        title: str,
        detail: str,
        *,
        fix: str = "",
        evidence: str = "",
        references: list[str] | None = None,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            category=self.category,
            severity=Severity(severity),
            title=title,
            detail=detail,
            fix=fix,
            evidence=evidence,
            references=list(references or []),
        )


_REGISTRY: list[Check] = []


def register(check: Check) -> Check:
    if any(c.id == check.id for c in _REGISTRY):
        raise ValueError(f"check already registered: {check.id}")
    _REGISTRY.append(check)
    return check


def get_checks(*, only: str | None = None, extras: Sequence[str] = ()) -> list[Check]:
    """Checks à exécuter (tous passifs).

    Les checks `optional` (options de scan) ne tournent que s'ils figurent dans `extras`."""
    _load_builtin_checks()
    selected = [
        c
        for c in _REGISTRY
        if (only is None or c.category == only)
        and (not getattr(c, "optional", False) or c.id in extras)
    ]
    return sorted(selected, key=lambda c: getattr(c, "order", 100))


def _load_builtin_checks() -> None:
    import sonde.checks.passive  # noqa: F401  (l'import enregistre les checks)
