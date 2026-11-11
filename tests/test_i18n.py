"""Traductions : catalogue complet, paramètres cohérents, choix de la langue."""

from __future__ import annotations

import ast
import re
import string
from pathlib import Path

import pytest
from sonde.i18n import N_, Msg, _, pop_lang_option
from sonde.i18n.fr import FR

from sonde import i18n

ROOT = Path(__file__).resolve().parent.parent
_TEMPLATE_CALL = re.compile(r'_\(\s*"((?:[^"\\]|\\.)*)"')


def extract_msgids() -> dict[str, str]:
    """Tous les messages passés à _() ou N_() dans le code et les gabarits -> emplacement."""
    found: dict[str, str] = {}
    sources = [*sorted((ROOT / "sonde").rglob("*.py")), ROOT / "sonde_passif.py"]
    for path in sources:
        if path.name == "fr.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("_", "N_")
                and node.args
            ):
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    found.setdefault(arg.value, f"{path.relative_to(ROOT)}:{node.lineno}")
    for path in sorted((ROOT / "sonde" / "report" / "templates").glob("*.j2")):
        for m in _TEMPLATE_CALL.finditer(path.read_text(encoding="utf-8")):
            found.setdefault(m.group(1), str(path.relative_to(ROOT)))
    return found


def _fields(text: str) -> set[str]:
    return {name for _lit, name, _spec, _conv in string.Formatter().parse(text) if name}


def test_every_message_has_a_french_translation():
    missing = {k: where for k, where in extract_msgids().items() if k not in FR}
    assert not missing, "\n".join(f"{where}: {k!r}" for k, where in missing.items())


def test_catalog_has_no_orphan_entry():
    orphans = set(FR) - set(extract_msgids())
    assert not orphans, sorted(orphans)


@pytest.mark.parametrize("msgid", sorted(FR))
def test_translation_keeps_the_same_placeholders(msgid):
    assert _fields(FR[msgid]) == _fields(msgid)


def test_extractor_sees_a_reasonable_number_of_messages():
    assert len(extract_msgids()) > 300


def test_english_is_the_default():
    assert i18n.get_lang() == "en"
    assert _("SPF missing") == "SPF missing"


def test_french_with_set_lang_and_env(monkeypatch):
    i18n.set_lang("fr")
    assert _("SPF missing") == "SPF absent"
    i18n.set_lang(None)
    monkeypatch.setenv(i18n.ENV_VAR, "fr_FR.UTF-8")
    assert i18n.get_lang() == "fr"
    assert _("SPF missing") == "SPF absent"


def test_unsupported_language_is_rejected():
    with pytest.raises(ValueError):
        i18n.set_lang("de")


def test_msg_keeps_english_rendering_even_with_translated_params():
    i18n.set_lang("fr")
    msg = _("Check not completed: {name}", name=_(N_("TLS certificate")))
    assert isinstance(msg, Msg)
    assert msg == "Contrôle non réalisé : Certificat TLS"
    assert msg.en == "Check not completed: TLS certificate"


def test_explicit_lang_argument_wins():
    assert _("Fixed", lang="fr") == "Corrigés"
    i18n.set_lang("fr")
    assert _("Fixed", lang="en") == "Fixed"


@pytest.mark.parametrize(
    ("argv", "rest", "lang"),
    [
        (["scan", "a.fr", "--lang", "fr"], ["scan", "a.fr"], "fr"),
        (["--lang=en", "history", "a.fr"], ["history", "a.fr"], "en"),
        (["scan", "a.fr"], ["scan", "a.fr"], None),
    ],
)
def test_pop_lang_option(argv, rest, lang):
    assert pop_lang_option(argv) == (rest, lang)


def test_pop_lang_option_requires_a_value():
    with pytest.raises(ValueError):
        pop_lang_option(["scan", "a.fr", "--lang"])


def test_no_code_rebinds_the_translation_function():
    """`for _ in …` ou `x, _ = …` dans une fonction masque _() et casse la traduction."""
    offenders = []
    for path in [*sorted((ROOT / "sonde").rglob("*.py")), ROOT / "sonde_passif.py"]:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Name) and node.id == "_" and isinstance(node.ctx, ast.Store):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert not offenders, offenders
