"""Translations (standard library only: the launcher imports this before dependencies exist).

Messages are written in English in the code and wrapped in `_()`. The French catalog
(`sonde/i18n/fr.py`) maps each English message to its translation.

    _("Certificate expires in {days} days", days=12)

`_()` returns a `Msg`: a `str` in the active language that also remembers its English
rendering (`.en`). Findings store that English title so that `diff` can match the same issue
across scans made in different languages.

`N_()` only marks a string for translation (module constants, check names); translate it
where it is displayed with `_()`.

Language: `set_lang()` (CLI `--lang`), otherwise the SONDE_LANG environment variable,
otherwise English.
"""

from __future__ import annotations

import os

from sonde.i18n.fr import FR

LANGS = ("en", "fr")
DEFAULT_LANG = "en"
ENV_VAR = "SONDE_LANG"

_CATALOGS: dict[str, dict[str, str]] = {"fr": FR}
_current: str | None = None


class Msg(str):
    """Translated text that keeps its English version in `.en`."""

    en: str

    def __new__(cls, text: str, en: str) -> Msg:
        obj = super().__new__(cls, text)
        obj.en = en
        return obj


def normalize(lang: str | None) -> str | None:
    """'fr', 'FR', 'fr_FR.UTF-8', 'fr-CA' -> 'fr' ; unsupported or empty -> None."""
    if not lang:
        return None
    code = lang.strip().lower().replace("-", "_").split("_")[0].split(".")[0]
    return code if code in LANGS else None


def set_lang(lang: str | None) -> str:
    """Selects the language for the rest of the process. ValueError if unsupported."""
    global _current
    if lang is None:
        _current = None
        return get_lang()
    code = normalize(lang)
    if code is None:
        raise ValueError(f"unsupported language: {lang!r} (choose: {', '.join(LANGS)})")
    _current = code
    return code


def explicit_lang() -> str | None:
    """Language explicitly requested (--lang or SONDE_LANG), None if left to the default."""
    return _current or normalize(os.environ.get(ENV_VAR))


def get_lang() -> str:
    return explicit_lang() or DEFAULT_LANG


def _(msgid: str, /, *, lang: str | None = None, **params: object) -> Msg:
    """Translates `msgid` then substitutes `params` (str.format), in `lang` or the active one."""
    code = lang or get_lang()
    template = _CATALOGS.get(code, {}).get(msgid, msgid)
    if params:
        en_params = {k: getattr(v, "en", v) for k, v in params.items()}
        return Msg(template.format(**params), msgid.format(**en_params))
    return Msg(template, msgid)


def N_(msgid: str, /) -> str:  # noqa: N802 — convention gettext
    """Marks a string for translation without translating it (translated later with `_`)."""
    return msgid


def pop_lang_option(argv: list[str]) -> tuple[list[str], str | None]:
    """Removes `--lang X` / `--lang=X` from anywhere in `argv`. -> (remaining args, value).

    ValueError if `--lang` has no value."""
    rest: list[str] = []
    value: str | None = None
    it = iter(argv)
    for arg in it:
        if arg == "--lang":
            value = next(it, None)
            if value is None or value.startswith("-"):
                raise ValueError("--lang requires a value (en or fr)")
        elif arg.startswith("--lang="):
            value = arg.split("=", 1)[1]
        else:
            rest.append(arg)
    return rest, value
