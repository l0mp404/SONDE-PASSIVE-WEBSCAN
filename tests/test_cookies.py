"""Check cookies : classification par nom et gravité (hors ligne, aucune requête)."""

from __future__ import annotations

import pytest
from sonde.checks.passive.cookies import CookiesCheck, Kind, classify, parse_set_cookie
from sonde.core.finding import Severity

CHECK = CookiesCheck()


def _sev(header: str) -> Severity:
    return CHECK._cookie_finding(parse_set_cookie(header)).severity


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("PHPSESSID", Kind.SESSION),
        ("JSESSIONID", Kind.SESSION),
        ("laravel_session", Kind.SESSION),
        ("wordpress_logged_in_abc123", Kind.SESSION),
        ("auth_token", Kind.SESSION),
        ("XSRF-TOKEN", Kind.CSRF),
        ("csrftoken", Kind.CSRF),
        ("_ga", Kind.THIRD_PARTY),
        ("_ga_ABC123", Kind.THIRD_PARTY),
        ("__cf_bm", Kind.THIRD_PARTY),
        ("pll_language", Kind.PREFERENCE),
        ("cookielawinfo-checkbox-necessary", Kind.PREFERENCE),
        ("foo", Kind.UNKNOWN),
    ],
)
def test_classify(name, kind):
    assert classify(name) is kind


def test_bare_session_cookie_is_critical():
    assert _sev("PHPSESSID=abc; path=/") is Severity.CRIT


def test_session_cookie_missing_one_flag_is_warn():
    assert _sev("PHPSESSID=abc; path=/; Secure") is Severity.WARN


def test_well_protected_session_cookie_is_ok():
    assert _sev("PHPSESSID=abc; Secure; HttpOnly; SameSite=Lax") is Severity.OK


def test_third_party_and_preference_cookies_never_cost_points():
    assert _sev("_ga=GA1.2.3; path=/") is Severity.INFO
    assert _sev("pll_language=fr; path=/") is Severity.INFO


def test_csrf_token_without_httponly_is_fine():
    f = CHECK._cookie_finding(parse_set_cookie("XSRF-TOKEN=x; Secure; SameSite=Lax"))
    assert f.severity is Severity.OK
    assert "HttpOnly" not in f.fix


def test_unknown_cookie_keeps_previous_behaviour():
    assert _sev("foo=bar") is Severity.WARN


def test_host_prefix_without_secure_is_flagged():
    f = CHECK._cookie_finding(parse_set_cookie("__Host-id=1; Path=/; HttpOnly; SameSite=Lax"))
    assert f.severity is Severity.WARN
    assert "__Host-" in f.title


def test_fix_ignores_flag_words_in_cookie_value():
    # L'ancien code cherchait "secure" dans toute la ligne, valeur comprise.
    f = CHECK._cookie_finding(parse_set_cookie("pref=secure_mode; HttpOnly; SameSite=Lax"))
    assert "Secure" in f.fix


# ------------------------------------------------------------ heuristique sur la valeur

HEX32 = "9f86d081884c7d659a2feaa0c55ad015"
B64 = "Zm9vYmFyQmF6UXV4LTEyMzQ1Njc4OTBhYmNkZWY"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"


@pytest.mark.parametrize("value", [HEX32, B64, JWT])
def test_unknown_name_with_secret_value_is_guessed_session(value):
    c = parse_set_cookie(f"x7f={value}; path=/")
    assert c.kind is Kind.SESSION and c.guessed


@pytest.mark.parametrize(
    "value",
    ["fr", "1700000000000000000000", "aaaaaaaaaaaaaaaaaaaaaaaa", "dark-mode", "a b c d e f g h i j k"],
)
def test_ordinary_values_stay_unknown(value):
    assert parse_set_cookie(f"x7f={value}").kind is Kind.UNKNOWN


def test_guessed_session_is_capped_at_warn():
    f = CHECK._cookie_finding(parse_set_cookie(f"x7f={HEX32}; path=/"))
    assert f.severity is Severity.WARN
    assert "32" in f.detail


def test_known_name_wins_over_value():
    c = parse_set_cookie(f"_ga={HEX32}")
    assert c.kind is Kind.THIRD_PARTY and not c.guessed


def test_evidence_never_contains_the_cookie_value():
    f = CHECK._cookie_finding(parse_set_cookie(f"PHPSESSID={HEX32}; path=/"))
    assert HEX32 not in f.evidence
    assert "PHPSESSID=9f86…; path=/" in f.evidence


@pytest.mark.parametrize(
    "value",
    [
        "%7B%22theme%22%3A%22dark%22%7D",
        "necessary%2Canalytics%2Cmarketing",
        "product_ids%3D12%2C45%2C78",
    ],
)
def test_url_encoded_structured_values_are_not_secrets(value):
    assert parse_set_cookie(f"x7f={value}").kind is Kind.UNKNOWN
