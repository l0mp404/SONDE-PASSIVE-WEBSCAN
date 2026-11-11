"""Comparaison de deux scans : nouveaux problèmes, problèmes corrigés, évolutions.

Un « problème » est un finding `crit` ou `warn`. Deux findings sont « le même problème »
s'ils ont le même check et le même titre ANGLAIS (`title_en`, indépendant de la langue du
scan) une fois les nombres neutralisés (« expires in 20 days » = « expires in 19 days »).

Un check qui n'a pas tourné (ou a échoué) dans l'un des deux scans n'est PAS comparé : on
ne déclare jamais « corrigé » un problème simplement parce qu'on ne l'a pas re-testé.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sonde.core.finding import Finding, Severity
from sonde.storage.db import StoredScan

_PROBLEMS = (Severity.CRIT, Severity.WARN)


def issue_key(f: Finding) -> tuple[str, str]:
    return f.check_id, re.sub(r"\d+", "#", (f.title_en or f.title).lower())


@dataclass(slots=True)
class Change:
    finding: Finding  # version la plus récente (ou l'ancienne pour un problème corrigé)
    before: Severity | None = None
    after: Severity | None = None


@dataclass(slots=True)
class ScanDiff:
    old: StoredScan
    new: StoredScan
    new_issues: list[Change] = field(default_factory=list)
    fixed: list[Change] = field(default_factory=list)
    worsened: list[Change] = field(default_factory=list)
    improved: list[Change] = field(default_factory=list)
    persistent: list[Change] = field(default_factory=list)  # toujours ouverts, même gravité
    unchanged: int = 0
    not_compared: list[str] = field(default_factory=list)  # checks absents/en échec d'un scan

    @property
    def has_changes(self) -> bool:
        return bool(self.new_issues or self.fixed or self.worsened or self.improved)


def _problems(scan: StoredScan, comparable: set[str]) -> dict[tuple[str, str], Finding]:
    out: dict[tuple[str, str], Finding] = {}
    for f in scan.findings:
        if f.check_id in comparable and f.severity in _PROBLEMS:
            key = issue_key(f)
            if key not in out or f.severity.rank > out[key].severity.rank:
                out[key] = f
    return out


def diff_scans(old: StoredScan, new: StoredScan) -> ScanDiff:
    ran_both = set(old.checks_run) & set(new.checks_run)
    broken = set(old.checks_failed) | set(new.checks_failed)
    comparable = ran_both - broken
    result = ScanDiff(old=old, new=new)
    result.not_compared = sorted((set(old.checks_run) | set(new.checks_run)) - comparable)

    before = _problems(old, comparable)
    after = _problems(new, comparable)

    for key, f in after.items():
        if key not in before:
            result.new_issues.append(Change(f, None, f.severity))
            continue
        b = before[key].severity
        if f.severity == b:
            result.unchanged += 1
            result.persistent.append(Change(f, b, f.severity))
        elif f.severity.rank > b.rank:
            result.worsened.append(Change(f, b, f.severity))
        else:
            result.improved.append(Change(f, b, f.severity))
    for key, f in before.items():
        if key not in after:
            result.fixed.append(Change(f, f.severity, None))

    by_rank = lambda c: -c.finding.severity.rank  # noqa: E731
    for bucket in (
        result.new_issues,
        result.fixed,
        result.worsened,
        result.improved,
        result.persistent,
    ):
        bucket.sort(key=by_rank)
    return result
