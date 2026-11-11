from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Literal

Category = Literal["web", "email"]


class Severity(StrEnum):
    CRIT = "crit"
    WARN = "warn"
    INFO = "info"
    OK = "ok"

    @property
    def rank(self) -> int:
        """Plus grand = plus grave."""
        return _RANK[self]


_RANK = {Severity.CRIT: 3, Severity.WARN: 2, Severity.INFO: 1, Severity.OK: 0}


def worst(severities: list[Severity]) -> Severity:
    return max(severities, key=lambda s: s.rank, default=Severity.OK)


@dataclass(slots=True)
class Finding:
    check_id: str
    category: Category
    severity: Severity
    title: str  # dans la langue du scan
    detail: str  # explication simple, pour un lecteur non technique
    fix: str = ""  # correctif concret, prêt à coller
    evidence: str = ""  # donnée brute courte
    references: list[str] = field(default_factory=list)
    # Titre en anglais, quelle que soit la langue du scan : clé stable pour `diff`.
    title_en: str = ""

    def __post_init__(self) -> None:
        self.severity = Severity(self.severity)
        self.title_en = self.title_en or getattr(self.title, "en", None) or str(self.title)
        # Les textes traduits (sonde.i18n.Msg) redeviennent des str simples.
        for name in ("title", "detail", "fix", "evidence", "title_en"):
            setattr(self, name, str(getattr(self, name)))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
