"""Configuration commune : langue et base de données isolées pour chaque test."""

from __future__ import annotations

import pytest

from sonde import i18n


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.delenv(i18n.ENV_VAR, raising=False)
    monkeypatch.setenv("SONDE_DB", str(tmp_path / "sonde.db"))
    i18n.set_lang(None)
    yield
    i18n.set_lang(None)
