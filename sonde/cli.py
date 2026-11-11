"""Interface en ligne de commande (Typer + Rich) : scan PASSIF uniquement.

Langue : `--lang fr` (option globale, avant la commande) ou SONDE_LANG=fr. Le lanceur
`sonde_passif.py` accepte aussi `--lang` n'importe où sur la ligne.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from sonde import __version__
from sonde.checks.base import Check, get_checks
from sonde.core.context import make_context
from sonde.core.diff import Change, diff_scans
from sonde.core.finding import Severity
from sonde.core.runner import NON_PUBLIC_CHECK_ID, CheckEvent, ScanResult, run_scan
from sonde.core.scoring import ScanScores, Score, compute_scores
from sonde.core.target import InvalidSelector, InvalidTarget, parse_dkim_selector, parse_target
from sonde.i18n import LANGS, _, explicit_lang, get_lang, set_lang
from sonde.report.render import ReportError, render_html, render_json, render_pdf
from sonde.storage.db import Database

app = typer.Typer(
    name="sonde",
    help=_("Sonde (passive) — web + email security audit, public information only."),
    no_args_is_help=True,
    add_completion=False,
)

out = Console()
err = Console(stderr=True)

_BADGES = {
    None: ("[ .. ]", "dim"),
    Severity.OK: ("[ OK ]", "bold green"),
    Severity.INFO: ("[INFO]", "bold cyan"),
    Severity.WARN: ("[WARN]", "bold yellow"),
    Severity.CRIT: ("[CRIT]", "bold red"),
}


_GRADE_STYLE = {
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "dark_orange",
    "E": "red",
    "F": "bold red",
}


def _grade_text(score: Score | None, *, label: str = "") -> Text:
    if score is None:
        return Text(f"{label}—", style="dim")
    return Text.assemble(
        label, (score.grade, _GRADE_STYLE[score.grade]), (f" {score.value}/100", "dim")
    )


def _local(iso: str) -> str:
    return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M")


def _error(label: str, message: object) -> None:
    err.print(f"[bold red]{escape(label)}[/] {escape(str(message))}")


class Only(StrEnum):
    WEB = "web"
    EMAIL = "email"


class ReportFormat(StrEnum):
    HTML = "html"
    PDF = "pdf"
    JSON = "json"


class Lang(StrEnum):
    EN = "en"
    FR = "fr"


assert {lang.value for lang in Lang} == set(LANGS)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"sonde {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version, is_eager=True, help=_("Show the version.")),
    ] = False,
    lang: Annotated[
        Lang | None,
        typer.Option(
            "--lang",
            help=_("Language of messages and reports (en, fr). Default: SONDE_LANG, else en."),
        ),
    ] = None,
) -> None:
    if lang is not None:
        set_lang(lang.value)


# ---------------------------------------------------------------- scan


class _LiveBoard:
    """Tableau live : une ligne par check, mise à jour au fil de l'eau."""

    def __init__(self, checks: list[Check]) -> None:
        self._state: dict[str, Severity | None] = {c.id: None for c in checks}
        self._checks = checks

    def update(self, event: CheckEvent) -> None:
        if event.kind == "finished":
            self._state[event.check.id] = event.worst

    def __rich__(self) -> Group:
        lines = []
        for c in self._checks:
            badge, style = _BADGES[self._state[c.id]]
            lines.append(Text.assemble((badge, style), (f" {c.category:<5} ", "dim"), _(c.name)))
        return Group(*lines)


def _summary(result: ScanResult, scores: ScanScores, scan_id: int | None) -> None:
    counts = {s: 0 for s in Severity}
    for f in result.findings:
        counts[f.severity] += 1
    out.print()
    out.print(
        Text.assemble(
            (f"{result.target.unicode_domain}  ", "bold"),
            (f"{counts[Severity.CRIT]} crit", "red"),
            "  ",
            (f"{counts[Severity.WARN]} warn", "yellow"),
            "  ",
            (f"{counts[Severity.OK]} ok", "green"),
            "  ",
            (f"{counts[Severity.INFO]} info", "cyan"),
        )
    )
    for f in sorted(result.findings, key=lambda f: -f.severity.rank):
        if f.severity in (Severity.CRIT, Severity.WARN) or f.check_id == NON_PUBLIC_CHECK_ID:
            badge, style = _BADGES[f.severity]
            line = Text.assemble((badge, style), f" {f.title}")
            if f.check_id == NON_PUBLIC_CHECK_ID:
                line.append(f"  ({f.evidence})", style="dim")
            out.print(line)
    out.print()
    out.print(
        Text.assemble(
            _("Overall grade: "),
            _grade_text(scores.overall),
            "   ",
            _grade_text(scores.web, label="Web "),
            "   ",
            _grade_text(scores.email, label="Email "),
        )
    )
    if result.checks_failed:
        out.print(
            Text(
                _(
                    "{n} check(s) not completed ({ids}): the grade is indicative.",
                    n=len(result.checks_failed),
                    ids=", ".join(result.checks_failed),
                ),
                style="yellow",
            )
        )
    if scan_id is not None:
        out.print(Text(_("Scan saved as #{id}.", id=scan_id), style="dim"))


@app.command(
    help=_("PASSIVE audit: headers, TLS, DNS, email. No intrusion, no authorization needed.")
)
def scan(
    domain: Annotated[str, typer.Argument(help=_("Domain or URL to audit."))],
    only: Annotated[Only | None, typer.Option("--only", help=_("Limit to web or email."))] = None,
    dkim_selector: Annotated[
        str | None, typer.Option("--dkim-selector", help=_("Additional DKIM selector."))
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help=_("JSON output on stdout (no live display)."))
    ] = False,
    no_save: Annotated[
        bool, typer.Option("--no-save", help=_("Do not save the scan in the history."))
    ] = False,
    crtsh: Annotated[
        bool,
        typer.Option(
            "--crtsh",
            help=_("Option: public subdomains (crt.sh), without contacting the target."),
        ),
    ] = False,
) -> None:
    try:
        target = parse_target(domain)
    except InvalidTarget as exc:
        _error(_("Invalid target:"), exc)
        raise typer.Exit(2) from exc

    selector = None
    if dkim_selector is not None:
        try:
            selector = parse_dkim_selector(dkim_selector)
        except InvalidSelector as exc:
            _error(_("Invalid option:"), exc)
            raise typer.Exit(2) from exc

    checks = get_checks(only=only.value if only else None, extras=["web.crtsh"] if crtsh else [])
    result = asyncio.run(_run(target, checks, selector, live=not json_output))
    scores = compute_scores(result.findings, result.categories)
    scan_id = None if no_save else _save(result, scores)

    if json_output:
        payload = {"scan_id": scan_id, "scores": scores.to_dict(), **result.to_dict()}
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        _summary(result, scores, scan_id)


def _save(result: ScanResult, scores: ScanScores) -> int | None:
    """Enregistre le scan. Un échec de stockage ne doit jamais perdre le résultat affiché."""
    try:
        with Database() as db:
            return db.save_scan(result, scores)
    except (sqlite3.Error, OSError, RuntimeError) as exc:
        err.print(Text.assemble((_("Scan not saved:"), "yellow"), f" {exc}"))
        return None


async def _run(target, checks: list[Check], dkim_selector: str | None, *, live: bool) -> ScanResult:
    ctx = make_context(dkim_selector=dkim_selector)
    lang = get_lang()
    try:
        if not live:
            return await run_scan(target, checks, ctx, lang=lang)
        board = _LiveBoard(checks)
        with Live(board, console=out, refresh_per_second=12, transient=False) as lv:

            def on_event(ev: CheckEvent) -> None:
                board.update(ev)
                lv.refresh()

            return await run_scan(target, checks, ctx, lang=lang, on_event=on_event)
    finally:
        await ctx.http.aclose()


# ---------------------------------------------------------------- rapports


def _open_db() -> Database:
    try:
        return Database()
    except (sqlite3.Error, OSError, RuntimeError) as exc:
        _error(_("History unavailable:"), exc)
        raise typer.Exit(1) from exc


@app.command(help=_("Generate the report of a saved scan (HTML, PDF or JSON)."))
def report(
    scan_id: Annotated[int, typer.Argument(help=_("Scan number (see `history`)."))],
    format: Annotated[
        ReportFormat, typer.Option("--format", "-f", help=_("Report format."))
    ] = ReportFormat.HTML,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help=_("Output file (JSON: stdout if omitted).")),
    ] = None,
    print_light: Annotated[
        bool, typer.Option("--print-light", help=_("Light background, saves ink (printing)."))
    ] = False,
) -> None:
    with _open_db() as db:
        scan = db.get_scan(scan_id)
    if scan is None:
        _error(_("Scan #{id} not found.", id=scan_id), _("(see `history <domain>`)"))
        raise typer.Exit(1)

    # Textes fixes : langue demandée explicitement, sinon celle du scan.
    lang = explicit_lang() or scan.lang
    try:
        if format is ReportFormat.JSON:
            data: bytes = render_json(scan).encode("utf-8")
        elif format is ReportFormat.HTML:
            data = render_html(scan, lang=lang, print_light=print_light).encode("utf-8")
        else:
            data = render_pdf(scan, lang=lang, print_light=print_light)
    except ReportError as exc:
        _error(_("Report failed:"), exc)
        raise typer.Exit(1) from exc

    if output is None and format is ReportFormat.JSON:
        sys.stdout.write(data.decode("utf-8"))
        return
    target_file = output or Path(f"sonde-{scan.domain}-{scan.id}.{format.value}")
    if target_file.is_dir():
        _error(_("{path} is a directory:", path=target_file), _("give a file name."))
        raise typer.Exit(2)
    try:
        target_file.write_bytes(data)
    except OSError as exc:
        _error(_("Cannot write file:"), exc)
        raise typer.Exit(1) from exc
    out.print(
        Text.assemble(
            (_("{fmt} report written:", fmt=format.value.upper()), "green"), f" {target_file}"
        )
    )


def _domain_or_exit(raw: str) -> str:
    try:
        return parse_target(raw).domain
    except InvalidTarget as exc:
        _error(_("Invalid target:"), exc)
        raise typer.Exit(2) from exc


@app.command(help=_("Scan history of a domain."))
def history(
    domain: Annotated[str, typer.Argument(help=_("Domain whose history to show."))],
    limit: Annotated[int, typer.Option("--limit", "-n", min=1, help=_("Number of scans."))] = 20,
) -> None:
    d = _domain_or_exit(domain)
    with _open_db() as db:
        scans = db.list_scans(d, limit)
    if not scans:
        err.print(Text(_("No saved scan for {domain}.", domain=d), style="yellow"))
        raise typer.Exit(1)

    table = Table(
        title=_("History — {domain}", domain=d), title_justify="left", header_style="bold"
    )
    columns = [_("#"), _("Date"), _("Lang"), _("Overall"), "Web", "Email", "Crit", "Warn"]
    for i, col in enumerate(columns):
        table.add_column(col, justify="right" if i in (0, 6, 7) else "left")
    for sc in scans:
        c = sc.counts()
        table.add_row(
            str(sc.id),
            _local(sc.started_at),
            sc.lang,
            _grade_text(sc.scores.overall),
            _grade_text(sc.scores.web),
            _grade_text(sc.scores.email),
            Text(str(c["crit"]), style="red" if c["crit"] else "dim"),
            Text(str(c["warn"]), style="yellow" if c["warn"] else "dim"),
        )
    out.print(table)


def _print_changes(title: str, style: str, changes: list[Change], *, show_arrow: bool) -> None:
    if not changes:
        return
    out.print()
    out.print(Text(f"{title} ({len(changes)})", style=f"bold {style}"))
    for ch in changes:
        sev = ch.after or ch.before
        badge, bstyle = _BADGES[sev]
        line = Text.assemble((badge, bstyle), f" {ch.finding.title}")
        if show_arrow and ch.before and ch.after:
            line.append(f"   ({ch.before.value} → {ch.after.value})", style="dim")
        out.print(line)


@app.command(help=_("Compare the last two scans: new issues / fixed."))
def diff(
    domain: Annotated[str, typer.Argument(help=_("Domain whose last two scans to compare."))],
) -> None:
    d = _domain_or_exit(domain)
    with _open_db() as db:
        latest = db.latest_scans(d, 2)
    if len(latest) < 2:
        err.print(Text(_("At least two scans of {domain} are needed.", domain=d), style="yellow"))
        raise typer.Exit(1)
    new, old = latest
    res = diff_scans(old, new)

    out.print(
        Text.assemble(
            (f"{d}  ", "bold"),
            f"#{old.id} ({_local(old.started_at)}) → #{new.id} ({_local(new.started_at)})",
        )
    )
    out.print(
        Text.assemble(
            _("Grade: "),
            _grade_text(old.scores.overall),
            "  →  ",
            _grade_text(new.scores.overall),
        )
    )
    _print_changes(_("New issues"), "red", res.new_issues, show_arrow=False)
    _print_changes(_("Worsened"), "red", res.worsened, show_arrow=True)
    _print_changes(_("Fixed"), "green", res.fixed, show_arrow=False)
    _print_changes(_("Improved"), "green", res.improved, show_arrow=True)
    out.print()
    if not res.has_changes:
        out.print(Text(_("No change between the two scans."), style="green"))
    out.print(Text(_("{n} unchanged issue(s).", n=res.unchanged), style="dim"))
    if res.not_compared:
        out.print(
            Text.assemble(
                (_("Not compared (missing or failed in one of the scans):"), "yellow"),
                f" {', '.join(res.not_compared)}",
            )
        )
