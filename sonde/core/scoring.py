"""Score 0-100 et note A-F.

Règles (brief) : départ 100 ; crit −15, warn −5, info/ok 0 ; la pénalité est plafonnée
**par check** (un « domaine de problème » : SPF, en-têtes, certificat…) pour qu'un seul
sujet ne détruise pas tout le score. Scores web et email séparés ; le global est la
moyenne des catégories effectivement auditées (une seule si `--only`).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from sonde.core.finding import Finding, Severity

PENALTY: dict[Severity, int] = {
    Severity.CRIT: 15,
    Severity.WARN: 5,
    Severity.INFO: 0,
    Severity.OK: 0,
}
CAP_PER_CHECK = 30

# (seuil minimal, note), du meilleur au pire
GRADES: list[tuple[int, str]] = [(90, "A"), (75, "B"), (55, "C"), (35, "D"), (20, "E"), (0, "F")]


def grade_for(score: int) -> str:
    for threshold, letter in GRADES:
        if score >= threshold:
            return letter
    return "F"


@dataclass(frozen=True, slots=True)
class Score:
    value: int
    grade: str

    @classmethod
    def of(cls, value: int) -> Score:
        value = max(0, min(100, value))
        return cls(value, grade_for(value))


@dataclass(frozen=True, slots=True)
class ScanScores:
    web: Score | None
    email: Score | None
    overall: Score

    def to_dict(self) -> dict:
        def one(s: Score | None):
            return None if s is None else {"score": s.value, "grade": s.grade}

        return {"web": one(self.web), "email": one(self.email), "overall": one(self.overall)}


def category_score(findings: Iterable[Finding], category: str) -> Score:
    per_check: dict[str, int] = defaultdict(int)
    for f in findings:
        if f.category == category:
            per_check[f.check_id] += PENALTY[f.severity]
    penalty = sum(min(p, CAP_PER_CHECK) for p in per_check.values())
    return Score.of(100 - penalty)


def compute_scores(findings: list[Finding], categories: Iterable[str]) -> ScanScores:
    """`categories` : catégories réellement auditées (une catégorie non auditée n'a pas de note)."""
    cats = set(categories)
    web = category_score(findings, "web") if "web" in cats else None
    email = category_score(findings, "email") if "email" in cats else None
    present = [s.value for s in (web, email) if s is not None]
    overall = Score.of(round(sum(present) / len(present))) if present else Score.of(100)
    return ScanScores(web=web, email=email, overall=overall)
