"""Rapports : HTML (Jinja2), PDF (WeasyPrint) et JSON à partir d'un scan enregistré.

Sécurité : les champs `evidence`/`title`/… proviennent du site audité (donc non fiables).
Le gabarit est rendu avec l'échappement automatique, et le rendu PDF refuse de charger
la moindre ressource externe (réseau ou fichiers locaux).

Langue : les textes fixes du rapport suivent `lang` ; les constats restent dans la langue
du scan (ils ont été rédigés au moment du scan).
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from sonde import __version__
from sonde.core.finding import Finding, Severity
from sonde.core.scoring import CAP_PER_CHECK, GRADES, PENALTY, Score
from sonde.i18n import N_, _, get_lang
from sonde.storage.db import StoredScan

TEMPLATE_DIR = Path(__file__).parent / "templates"

MONTHS = {
    "en": [
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December",
    ],
    "fr": [
        "janvier", "février", "mars", "avril", "mai", "juin",
        "juillet", "août", "septembre", "octobre", "novembre", "décembre",
    ],
}  # fmt: skip
SEVERITY_LABEL = {
    Severity.CRIT: N_("Critical"),
    Severity.WARN: N_("Warning"),
    Severity.INFO: N_("Info"),
    Severity.OK: N_("OK"),
}
CATEGORY_TITLE = {"web": N_("Web security"), "email": N_("Email security")}


class ReportError(RuntimeError):
    """Génération de rapport impossible (message destiné à l'utilisateur)."""


def format_date(iso: str, lang: str | None = None) -> str:
    lang = lang or get_lang()
    dt = datetime.fromisoformat(iso).astimezone()
    month = MONTHS.get(lang, MONTHS["en"])[dt.month - 1]
    if lang == "fr":
        return f"{dt.day} {month} {dt.year}"
    return f"{month} {dt.day}, {dt.year}"


def format_datetime(iso: str, lang: str | None = None) -> str:
    lang = lang or get_lang()
    dt = datetime.fromisoformat(iso).astimezone()
    return _("{date} at {time}", lang=lang, date=format_date(iso, lang), time=f"{dt:%H:%M}")


# ------------------------------------------------------------------ contexte


@dataclass(slots=True)
class Section:
    category: str
    title: str
    score: Score | None  # None : catégorie non notée (ex. cible à adresse privée)
    findings: list[Finding]


def _sections(scan: StoredScan, lang: str) -> list[Section]:
    out = []
    for cat, score in (("web", scan.scores.web), ("email", scan.scores.email)):
        items = [f for f in scan.findings if f.category == cat]
        if score is None and not items:
            continue  # catégorie non auditée dans ce scan
        items.sort(key=lambda f: -f.severity.rank)  # tri stable : l'ordre d'origine est gardé
        out.append(Section(cat, _(CATEGORY_TITLE[cat], lang=lang), score, items))
    return out


def build_context(scan: StoredScan, *, lang: str, print_light: bool = False) -> dict:
    return {
        "scan": scan,
        "domain": scan.domain,
        "lang": lang,
        "scores": scan.scores,
        "counts": scan.counts(),
        "sections": _sections(scan, lang),
        "light": print_light,
        "failed_checks": scan.checks_failed,
        "penalty": {s.value: p for s, p in PENALTY.items()},
        "cap": CAP_PER_CHECK,
        "grades": GRADES,
        "version": __version__,
        "severity_label": {s.value: _(label, lang=lang) for s, label in SEVERITY_LABEL.items()},
    }


def _env(lang: str) -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=True,  # indispensable : le contenu vient du site audité
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals["_"] = partial(_, lang=lang)
    env.filters["fmt_datetime"] = partial(format_datetime, lang=lang)
    env.filters["fmt_date"] = partial(format_date, lang=lang)
    return env


# ------------------------------------------------------------------ formats


def render_html(scan: StoredScan, *, lang: str | None = None, print_light: bool = False) -> str:
    """`lang` : langue des textes fixes du rapport (défaut : celle du scan)."""
    lang = lang or scan.lang
    template = _env(lang).get_template("report.html.j2")
    return template.render(**build_context(scan, lang=lang, print_light=print_light))


def render_json(scan: StoredScan) -> str:
    payload = {
        "sonde_version": __version__,
        "scan": {
            "id": scan.id,
            "domain": scan.domain,
            "started_at": scan.started_at,
            "ended_at": scan.ended_at,
            "lang": scan.lang,
            "checks_run": scan.checks_run,
            "checks_failed": scan.checks_failed,
        },
        "scores": scan.scores.to_dict(),
        "counts": scan.counts(),
        "findings": [f.to_dict() for f in scan.findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def _deny_fetcher():
    """Fetcher WeasyPrint qui refuse tous les protocoles (http, https, file, data…).

    Le rapport est autonome : le contenu venant du site audité ne doit jamais pouvoir
    déclencher une requête réseau ni la lecture d'un fichier local pendant le rendu.
    """
    from weasyprint.urls import URLFetcher

    return URLFetcher(allowed_protocols=())


def _ensure_native_libs() -> None:
    """macOS : WeasyPrint cherche Pango dans /opt/homebrew/lib, hors du chemin par défaut."""
    if sys.platform != "darwin":
        return
    current = [p for p in os.environ.get("DYLD_FALLBACK_LIBRARY_PATH", "").split(":") if p]
    for prefix in ("/opt/homebrew/lib", "/usr/local/lib"):
        if Path(prefix, "libpango-1.0.dylib").exists() and prefix not in current:
            current.append(prefix)
    if current:
        os.environ["DYLD_FALLBACK_LIBRARY_PATH"] = ":".join(current)


def html_to_pdf(html: str) -> bytes:
    _ensure_native_libs()
    try:
        import weasyprint
    except (OSError, ImportError) as exc:
        raise ReportError(
            _(
                "PDF export unavailable. Install: pip install --require-hashes -r "
                "requirements-pdf.lock (and on macOS: brew install pango). HTML and JSON "
                "formats work without it."
            )
        ) from exc
    # base_url factice : même les chemins relatifs ne pointent vers aucun fichier réel.
    return weasyprint.HTML(
        string=html,
        base_url="about:blank",
        url_fetcher=_deny_fetcher(),
    ).write_pdf()


def render_pdf(scan: StoredScan, *, lang: str | None = None, print_light: bool = False) -> bytes:
    return html_to_pdf(render_html(scan, lang=lang, print_light=print_light))
