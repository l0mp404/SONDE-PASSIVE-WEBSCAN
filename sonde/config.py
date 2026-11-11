"""Chemins de données de Sonde (surchargeables par variables d'environnement)."""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    return Path(os.environ.get("SONDE_DATA_DIR") or "~/.local/share/sonde-passif").expanduser()


def db_path() -> Path:
    """SONDE_DB (fichier précis) > SONDE_DATA_DIR/sonde.db > ~/.local/share/sonde-passif/sonde.db."""
    if env := os.environ.get("SONDE_DB"):
        return Path(env).expanduser()
    return data_dir() / "sonde.db"
