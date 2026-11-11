"""Stockage SQLite local : historique des scans et de leurs constats.

La base peut contenir des données sur des tiers : dossier en 0700, fichier en 0600.
Toutes les requêtes sont paramétrées (jamais de SQL construit par concaténation).
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from sonde.config import db_path as default_db_path
from sonde.core.finding import Finding
from sonde.core.runner import ScanResult
from sonde.core.scoring import ScanScores, Score
from sonde.i18n import _

SCHEMA_VERSION = 1

# Migrations successives : {version cible: [instructions]}. La version 1 est SCHEMA ci-dessous ;
# une future version 2 s'ajoutera ici sans toucher à SCHEMA.
MIGRATIONS: dict[int, list[str]] = {}

SCHEMA = """
CREATE TABLE scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain          TEXT    NOT NULL,
    started_at      TEXT    NOT NULL,
    ended_at        TEXT    NOT NULL,
    lang            TEXT    NOT NULL DEFAULT 'en',
    score_web       INTEGER,
    score_email     INTEGER,
    score_overall   INTEGER NOT NULL,
    grade_web       TEXT,
    grade_email     TEXT,
    grade_overall   TEXT    NOT NULL,
    checks_run      TEXT    NOT NULL DEFAULT '[]',
    checks_failed   TEXT    NOT NULL DEFAULT '[]'
);
CREATE INDEX idx_scans_domain ON scans(domain, id);

CREATE TABLE findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id    TEXT    NOT NULL,
    category    TEXT    NOT NULL CHECK (category IN ('web', 'email')),
    severity    TEXT    NOT NULL CHECK (severity IN ('crit', 'warn', 'info', 'ok')),
    title       TEXT    NOT NULL,
    title_en    TEXT    NOT NULL,
    detail      TEXT    NOT NULL,
    fix         TEXT    NOT NULL,
    evidence    TEXT    NOT NULL,
    refs        TEXT    NOT NULL DEFAULT '[]',
    position    INTEGER NOT NULL
);
CREATE INDEX idx_findings_scan ON findings(scan_id, position);
"""


@dataclass(slots=True)
class StoredScan:
    id: int
    domain: str
    started_at: str
    ended_at: str
    lang: str
    scores: ScanScores
    checks_run: list[str]
    checks_failed: list[str]
    findings: list[Finding] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        c = {"crit": 0, "warn": 0, "info": 0, "ok": 0}
        for f in self.findings:
            c[f.severity.value] += 1
        return c


def _score(value: int | None, grade: str | None) -> Score | None:
    return None if value is None or grade is None else Score(value, grade)


class Database:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        existed = self.path.exists()
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA secure_delete = ON")  # supprimer = écraser, pas seulement délier
        if not existed:
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        try:
            self._migrate()
        except BaseException:
            self._conn.close()
            raise

    # -- cycle de vie

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._conn
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise

    def _migrate(self) -> None:
        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if version == SCHEMA_VERSION:
            return
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                _(
                    "Database {path} uses an unknown schema (version {version}); it was created "
                    "by a newer or pre-release version of Sonde. Move it aside or point SONDE_DB "
                    "to another file.",
                    path=self.path,
                    version=version,
                )
            )
        has_tables = self._conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'scans'"
        ).fetchone()[0]
        if version == 0 and has_tables:
            raise RuntimeError(
                _(
                    "{path} is not a Sonde database (or it is damaged). Move it aside or point "
                    "SONDE_DB to another file.",
                    path=self.path,
                )
            )
        with self._tx() as conn:
            if version == 0:  # base neuve : schéma complet de la version 1
                for statement in filter(None, (s.strip() for s in SCHEMA.split(";\n"))):
                    conn.execute(statement)
                version = 1
            for target in range(version + 1, SCHEMA_VERSION + 1):
                for statement in MIGRATIONS[target]:
                    conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # -- scans

    def save_scan(self, result: ScanResult, scores: ScanScores) -> int:
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO scans (domain, started_at, ended_at, lang, score_web, score_email,"
                " score_overall, grade_web, grade_email, grade_overall, checks_run,"
                " checks_failed) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    result.target.domain,
                    result.started_at.isoformat(),
                    result.ended_at.isoformat(),
                    result.lang,
                    scores.web.value if scores.web else None,
                    scores.email.value if scores.email else None,
                    scores.overall.value,
                    scores.web.grade if scores.web else None,
                    scores.email.grade if scores.email else None,
                    scores.overall.grade,
                    json.dumps(result.checks_run),
                    json.dumps(result.checks_failed),
                ),
            )
            scan_id = int(cur.lastrowid)  # type: ignore[arg-type]
            conn.executemany(
                "INSERT INTO findings (scan_id, check_id, category, severity, title, title_en,"
                " detail, fix, evidence, refs, position) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        scan_id,
                        f.check_id,
                        f.category,
                        f.severity.value,
                        f.title,
                        f.title_en,
                        f.detail,
                        f.fix,
                        f.evidence,
                        json.dumps(f.references),
                        pos,
                    )
                    for pos, f in enumerate(result.findings)
                ],
            )
        return scan_id

    def get_scan(self, scan_id: int) -> StoredScan | None:
        row = self._conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return self._hydrate(row) if row else None

    def list_scans(self, domain: str, limit: int = 20) -> list[StoredScan]:
        """Scans d'un domaine, du plus récent au plus ancien."""
        return self.latest_scans(domain, limit)

    def latest_scans(self, domain: str, n: int = 2) -> list[StoredScan]:
        """Les `n` derniers scans avec findings, du plus récent au plus ancien."""
        rows = self._conn.execute(
            "SELECT * FROM scans WHERE domain = ? ORDER BY id DESC LIMIT ?", (domain, n)
        ).fetchall()
        return [self._hydrate(r) for r in rows]

    def _hydrate(self, row: sqlite3.Row) -> StoredScan:
        scan = StoredScan(
            id=row["id"],
            domain=row["domain"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            lang=row["lang"],
            scores=ScanScores(
                web=_score(row["score_web"], row["grade_web"]),
                email=_score(row["score_email"], row["grade_email"]),
                overall=Score(row["score_overall"], row["grade_overall"]),
            ),
            checks_run=json.loads(row["checks_run"]),
            checks_failed=json.loads(row["checks_failed"]),
        )
        frows = self._conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY position", (scan.id,)
        ).fetchall()
        scan.findings = [
            Finding(
                check_id=r["check_id"],
                category=r["category"],
                severity=r["severity"],
                title=r["title"],
                title_en=r["title_en"],
                detail=r["detail"],
                fix=r["fix"],
                evidence=r["evidence"],
                references=json.loads(r["refs"]),
            )
            for r in frows
        ]
        return scan
