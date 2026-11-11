"""crt.sh plafonné, base SQLite neuve, diff multilingue, rapports, lanceur, CLI."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import UTC, datetime

import httpcore
import pytest
import sonde_passif
from sonde.core.netguard import GuardedTransport
from typer.testing import CliRunner

from sonde import i18n
from sonde.checks.passive import extras
from sonde.checks.passive.extras import CrtshCheck, parse_crtsh
from sonde.core.context import Context, make_http_client, make_resolver
from sonde.core.diff import diff_scans
from sonde.core.finding import Finding, Severity
from sonde.core.runner import ScanResult
from sonde.core.scoring import compute_scores
from sonde.core.target import parse_target
from sonde.report.render import render_html, render_json
from sonde.storage.db import SCHEMA_VERSION, Database

# ------------------------------------------------------------------ crt.sh


class _ChunkedBackend(httpcore.AsyncMockBackend):
    """Répond 200 avec un corps en plusieurs morceaux (chunked) de `size` octets au total."""

    def __init__(self, body: bytes, chunk: int = 64 * 1024) -> None:
        super().__init__([])
        head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        parts = [head]
        for i in range(0, len(body), chunk):
            piece = body[i : i + chunk]
            parts.append(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
        parts.append(b"0\r\n\r\n")
        self._parts = parts

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        return httpcore.AsyncMockStream(list(self._parts))


async def _public(host, port):
    return ["93.184.216.34"]


def _crtsh(body: bytes):
    async def go():
        transport = GuardedTransport(resolver=_public, network_backend=_ChunkedBackend(body))
        http = make_http_client(transport=transport)
        ctx = Context(http=http, resolver=make_resolver(), addr_resolver=_public)
        try:
            return await CrtshCheck().run(parse_target("example.com"), ctx)
        finally:
            await http.aclose()

    return asyncio.run(go())


def test_crtsh_lists_subdomains():
    body = json.dumps([{"name_value": "www.example.com\nadmin.example.com"},
                       {"name_value": "evil.org"}]).encode()  # fmt: skip
    findings = _crtsh(body)
    assert findings[0].title == "2 subdomain(s) visible in public certificates"
    assert "evil.org" not in findings[0].evidence
    assert findings[1].evidence == "admin.example.com"


def test_crtsh_response_over_5_mb_is_cut_and_not_parsed(monkeypatch):
    parsed = []
    monkeypatch.setattr(extras, "parse_crtsh", lambda *a, **k: parsed.append(1) or (set(), False))
    body = b"[" + b'{"name_value":"a.example.com"},' * 400_000 + b"{}]"  # ~12 Mo
    assert len(body) > extras.MAX_RESPONSE_BYTES
    findings = _crtsh(body)
    assert [f.title for f in findings] == ["crt.sh response too large"]
    assert parsed == []


def test_parse_crtsh_caps_raw_names():
    data = json.dumps([{"name_value": f"h{i}.example.com"} for i in range(50)])
    names, capped = parse_crtsh(data, max_names=10)
    assert len(names) == 10 and capped
    names, capped = parse_crtsh(data, max_names=100)
    assert len(names) == 50 and not capped


def test_crtsh_flags_partial_list_when_capped(monkeypatch):
    monkeypatch.setattr(extras, "MAX_RAW_NAMES", 5)
    body = json.dumps([{"name_value": f"h{i}.example.com"} for i in range(20)]).encode()
    findings = _crtsh(body)
    assert "Partial list" in findings[0].detail
    assert findings[0].title.startswith("5 subdomain")


def test_crtsh_does_not_contact_the_target():
    assert CrtshCheck.contacts_target is False


# ------------------------------------------------------------------ base de données


def _result(findings, lang="en") -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        target=parse_target("example.com"),
        started_at=now,
        ended_at=now,
        findings=findings,
        checks_run=sorted({f.check_id for f in findings}),
        categories=["web", "email"],
        lang=lang,
    )


def _finding(lang: str, days: int) -> Finding:
    title = i18n._("Certificate expires in {n} days", n=days, lang=lang)
    return Finding("web.cert", "web", Severity.WARN, title, i18n._("Fix", lang=lang))


def test_fresh_database_has_only_scans_and_findings(tmp_path):
    path = tmp_path / "fresh.db"
    with Database(path):
        pass
    conn = sqlite3.connect(path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert tables - {"sqlite_sequence"} == {"scans", "findings"}
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 1
    cols = {r[1] for r in conn.execute("PRAGMA table_info(scans)")}
    assert "authorization_id" not in cols and "mode" not in cols and "lang" in cols
    assert (path.stat().st_mode & 0o777) == 0o600


def test_pre_release_database_gets_a_clear_error(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE scans (id INTEGER)")
    conn.execute("PRAGMA user_version = 4")
    conn.commit()
    conn.close()
    with pytest.raises(RuntimeError, match="unknown schema"):
        Database(path)


def test_save_and_reload_round_trip(tmp_path):
    with Database(tmp_path / "a.db") as db:
        result = _result([_finding("fr", 12)], lang="fr")
        scan_id = db.save_scan(result, compute_scores(result.findings, result.categories))
        scan = db.get_scan(scan_id)
    assert scan.lang == "fr"
    assert scan.findings[0].title == "Certificat expire dans 12 jours"
    assert scan.findings[0].title_en == "Certificate expires in 12 days"


def test_diff_matches_issues_across_languages(tmp_path):
    with Database(tmp_path / "d.db") as db:
        for lang, days in (("fr", 20), ("en", 19)):
            r = _result([_finding(lang, days)], lang=lang)
            db.save_scan(r, compute_scores(r.findings, r.categories))
        new, old = db.latest_scans("example.com", 2)
    res = diff_scans(old, new)
    assert res.unchanged == 1 and not res.has_changes


# ------------------------------------------------------------------ rapports


@pytest.fixture
def stored_scan(tmp_path):
    with Database(tmp_path / "r.db") as db:
        r = _result([_finding("en", 12)])
        scan_id = db.save_scan(r, compute_scores(r.findings, r.categories))
        return db.get_scan(scan_id)


def test_html_report_in_english_by_default(stored_scan):
    html = render_html(stored_scan)
    assert '<html lang="en">' in html and "Methodology" in html and "Méthodologie" not in html
    assert "authoriz" not in html.lower()


def test_html_report_in_french(stored_scan):
    html = render_html(stored_scan, lang="fr")
    assert '<html lang="fr">' in html and "Méthodologie" in html and "Limites" in html
    assert "Certificate expires in 12 days" in html  # les constats gardent la langue du scan


def test_json_report_has_no_authorization_or_mode(stored_scan):
    data = json.loads(render_json(stored_scan))
    assert "authorization" not in data and "mode" not in data["scan"]
    assert data["findings"][0]["title_en"] == "Certificate expires in 12 days"


# ------------------------------------------------------------------ lanceur


@pytest.mark.parametrize("answer", ["", "y", "Y", "yes", "YES", "o", "oui", " Yes "])
def test_launcher_accepts_yes_answers(answer):
    assert sonde_passif.is_yes(answer, default=True)


@pytest.mark.parametrize("answer", ["n", "no", "non", "nope", "x"])
def test_launcher_refuses_other_answers(answer):
    assert not sonde_passif.is_yes(answer, default=True)


def test_launcher_default_no_for_confirmation():
    assert not sonde_passif.is_yes("", default=False)
    assert sonde_passif.is_yes("y", default=False)


def test_launcher_prompt_labels_follow_language(monkeypatch):
    prompts = []
    monkeypatch.setattr("builtins.input", lambda p: prompts.append(p) or "yes")
    assert sonde_passif.ask("Go?")
    i18n.set_lang("fr")
    assert sonde_passif.ask("Go?")
    assert prompts == ["Go? [Y/n] ", "Go? [O/n] "]


def test_launcher_installs_from_lock_with_hashes():
    cmd = sonde_passif.install_command(sonde_passif.venv_python())
    assert "--require-hashes" in cmd and cmd[-1].endswith("requirements.lock")


def test_lock_file_pins_and_hashes_every_package():
    lock = sonde_passif.LOCK_FILE.read_text()
    reqs = [line for line in lock.splitlines() if line and line[0].isalpha()]
    assert reqs and all("==" in line for line in reqs)
    assert lock.count("--hash=sha256:") >= len(reqs)
    for line in (sonde_passif.HERE / "requirements.txt").read_text().splitlines():
        if line and not line.startswith("#"):
            assert "==" in line, line


# ------------------------------------------------------------------ CLI


def test_cli_messages_in_english_and_french():
    from sonde.cli import app

    runner = CliRunner()
    res = runner.invoke(app, ["history", "example.com"])
    assert res.exit_code == 1 and "No saved scan for example.com" in res.output
    res = runner.invoke(app, ["--lang", "fr", "history", "example.com"])
    assert "Aucun scan enregistré pour example.com" in res.output
    i18n.set_lang(None)  # --lang reste actif pour la suite du processus
    res = runner.invoke(app, ["scan", "127.0.0.1"])
    assert res.exit_code == 2 and "an IP address is not a domain" in res.output
