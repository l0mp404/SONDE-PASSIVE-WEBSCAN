#!/usr/bin/env python3
"""Sonde (passif) : lanceur. Bannière à chaque ouverture, vérification des modules à la première.

N'utilise que la bibliothèque standard tant que les dépendances ne sont pas vérifiées
(`sonde.i18n` est en bibliothèque standard). Les dépendances sont installées depuis
requirements.lock, versions exactes vérifiées par hash (pip --require-hashes).
"""

import contextlib
import importlib.util
import os
import shutil
import subprocess  # noqa: S404 — uniquement des listes d'arguments, jamais de shell
import sys
import time
from pathlib import Path

from sonde.i18n import ENV_VAR, _, pop_lang_option, set_lang

HERE = Path(__file__).resolve().parent
VENV = HERE / ".venv"
MARKER = (
    Path(os.environ.get("SONDE_CONFIG_DIR") or "~/.config/sonde-passif").expanduser() / ".setup_ok"
)
TOOL, VERSION = "Sonde Passif", "0.1.0"
MIN_PYTHON = (3, 12)

LOCK_FILE = HERE / "requirements.lock"

# (nom du module à importer, paquet pip)
REQUIRED = [
    ("typer", "typer"), ("rich", "rich"), ("httpx", "httpx"), ("httpcore", "httpcore"),
    ("dns", "dnspython"), ("cryptography", "cryptography"), ("idna", "idna"),
    ("certifi", "certifi"), ("jinja2", "jinja2"),
]  # fmt: skip
YES = ("o", "oui", "y", "yes")

RED, GREEN, GREY, RESET, BOLD = "\033[91m", "\033[92m", "\033[90m", "\033[0m", "\033[1m"

BANNER = r"""
██╗      ██████╗ ███╗   ███╗██████╗         ██╗  ██╗ ██████╗ ██╗  ██╗
██║     ██╔═══██╗████╗ ████║██╔══██╗        ██║  ██║██╔═████╗██║  ██║
██║     ██║   ██║██╔████╔██║██████╔╝        ███████║██║██╔██║███████║
██║     ██║   ██║██║╚██╔╝██║██╔═══╝         ╚════██║████╔╝██║╚════██║
███████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗     ██║╚██████╔╝     ██║
╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝     ╚═╝ ╚═════╝      ╚═╝
"""


def type_line(text, delay=0.01):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def show_banner(tool=TOOL, version=VERSION):
    print(GREEN + BOLD, end="")
    for line in BANNER.splitlines():
        print(line)
        time.sleep(0.08)
    print(RESET, end="")
    type_line(f"  {RED}[>]{RESET} {BOLD}{tool}{RESET} v{version}  {GREY}by Lomp_404{RESET}", 0.02)
    type_line(f"  {GREY}[i] github.com/l0mp404  |  For authorized use only{RESET}", 0.015)
    print()


# ------------------------------------------------------------------ vérification des modules


def missing_modules() -> list[str]:
    return [pip for module, pip in REQUIRED if importlib.util.find_spec(module) is None]


def in_venv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def is_yes(answer: str, *, default: bool) -> bool:
    """Réponse à une question oui/non : y/yes (et o/oui) acceptés, majuscules comprises."""
    answer = answer.strip().lower()
    return default if not answer else answer in YES


def ask(question: str, *, default: bool = True) -> bool:
    choices = _("[Y/n]") if default else _("[y/N]")
    try:
        return is_yes(input(f"{question} {choices} "), default=default)
    except EOFError:
        return False


def run(cmd: list[str]) -> bool:
    return subprocess.run(cmd, check=False).returncode == 0  # noqa: S603


def setup_environment(argv: list[str]) -> None:
    """Crée .venv, installe les dépendances (versions exactes, hash vérifiés), puis s'y relance."""
    print(f"  {GREY}[i] {_('Creating the local environment (.venv)…')}{RESET}")
    if not venv_python().exists() and not run([sys.executable, "-m", "venv", str(VENV)]):
        sys.exit(f"{RED}[!] {_('Cannot create .venv (is python3 -m venv available?)')}{RESET}")
    if not run(install_command(venv_python())):
        sys.exit(
            f"{RED}[!] {_('Installation failed. Check your connection and try again.')}{RESET}"
        )
    print(f"  {GREEN}[+] {_('Modules installed.')}{RESET}\n")
    os.environ["SONDE_PASSIF_REEXEC"] = "1"  # la bannière a déjà été affichée
    os.execv(str(venv_python()), [str(venv_python()), str(Path(__file__).resolve()), *argv])  # noqa: S606


def install_command(python: Path) -> list[str]:
    """pip n'installe que les versions exactes du lock, et refuse tout paquet dont le hash diffère."""
    return [
        str(python), "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
        "--require-hashes", "--no-deps", "-r", str(LOCK_FILE),
    ]  # fmt: skip


def check_setup(argv: list[str], *, force: bool) -> None:  # argv : arguments d'origine
    """Première ouverture (ou --check) : Python, système, modules. Quitte si impossible."""
    print(f"  {GREY}[i] {_('Checking the installation…')}{RESET}")
    if sys.version_info < MIN_PYTHON:
        need = ".".join(map(str, MIN_PYTHON))
        found = sys.version.split()[0]
        sys.exit(
            f"{RED}[!] {_('Python {need}+ required (found {found}).', need=need, found=found)}{RESET}"
        )
    if sys.platform.startswith("win"):
        print(f"  {RED}[!] {_('Native Windows is not supported: use WSL2 (see README).')}{RESET}")
    elif sys.platform not in ("darwin", "linux"):
        print(f"  {RED}[!] {_('Untested system: {platform}.', platform=sys.platform)}{RESET}")
    missing = missing_modules()
    if missing:
        print(f"  {RED}[!] {_('Missing modules: {modules}', modules=', '.join(missing))}{RESET}")
        if ask("  " + _("Create a local environment (.venv) and install them?")):
            setup_environment(argv)  # ne revient pas
        sys.exit("  " + _("Install them with: pip install --require-hashes -r requirements.lock"))
    for module, _pip in REQUIRED:
        print(f"  {GREEN}[+]{RESET} {module}")
    if importlib.util.find_spec("weasyprint") is None:
        print(
            f"  {GREY}[-] {_('weasyprint missing (PDF export unavailable, HTML/JSON OK)')}{RESET}"
        )
    MARKER.parent.mkdir(parents=True, exist_ok=True)
    MARKER.write_text(VERSION)
    print(f"  {GREEN}[+] {_('All set.')}{RESET}\n")
    if force:
        sys.exit(0)


def data_dirs() -> list[Path]:
    data = Path(os.environ.get("SONDE_DATA_DIR") or "~/.local/share/sonde-passif").expanduser()
    return [data, MARKER.parent]


def uninstall(*, purge_data: bool, assume_yes: bool = False) -> bool:
    """Supprime l'environnement local (.venv) et le marqueur de première ouverture.

    Avec purge_data : efface aussi l'historique des scans et la configuration."""
    targets = []
    if VENV.is_dir() and not VENV.is_symlink() and VENV.parent == HERE:
        targets.append(VENV)
    targets.append(MARKER)
    if purge_data:
        # garde-fou : seuls des dossiers nommés exactement « sonde-passif » peuvent être effacés
        targets += [d for d in data_dirs() if d.name == "sonde-passif"]
    existing = [t for t in targets if t.exists()]
    if not existing:
        print(f"  {GREY}[i] {_('Nothing to remove: the local environment does not exist.')}{RESET}")
        return False
    print(f"  {RED}[!] {_('Will be removed:')}{RESET}")
    for t in existing:
        print(f"      {t}")
    if not purge_data:
        print(f"  {GREY}{_('(scan history is kept; add --purge-data to erase it)')}{RESET}")
    if not assume_yes and not ask("  " + _("Confirm?"), default=False):
        print(f"  {GREY}{_('Cancelled.')}{RESET}")
        return False
    for t in existing:
        if t.is_dir():
            shutil.rmtree(t, ignore_errors=True)
        else:
            t.unlink(missing_ok=True)
    print(
        f"  {GREEN}[+] {_('Removed. The program folder itself remains: delete it by hand.')}{RESET}"
    )
    return True


def interactive(app) -> None:
    """Sans argument : invite de commandes. `exemple.fr` seul = `scan exemple.fr`."""
    import shlex  # noqa: PLC0415

    print(
        f"  {GREY}{_('Type a domain (e.g. example.com) or a command: scan, history, diff, report.')}"
    )
    print(
        f"  {_('`help` for help, `uninstall` to remove the local environment, `exit` to quit.')}{RESET}\n"
    )
    while True:
        try:
            line = input(f"{GREEN}sonde-passif{RESET} > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not line:
            continue
        if line.lower() in ("exit", "quit", "q"):
            return
        try:
            args, lang = pop_lang_option(shlex.split(line))
            if lang is not None:
                apply_lang(lang)  # valable pour la suite de la session
        except ValueError as exc:
            print(f"{RED}[!] {exc}{RESET}")
            continue
        if not args:
            continue
        if args[0].lower() == "uninstall":
            if uninstall(purge_data="--purge-data" in args):
                return  # l'environnement n'existe plus : on quitte
            continue
        if args[0].lower() == "help":
            args = ["--help"]
        elif "." in args[0] and len(args) == 1 and args[0] not in ("--help",):
            args = ["scan", args[0]]
        try:
            app(args=args, prog_name="sonde-passif", standalone_mode=False)
        except SystemExit:
            pass
        except Exception as exc:  # noqa: BLE001 — l'invite ne doit jamais se fermer sur une erreur
            print(f"{RED}[!] {exc}{RESET}")
        print()


def apply_lang(lang: str) -> None:
    """Langue choisie par --lang : appliquée ici et transmise au .venv par l'environnement."""
    os.environ[ENV_VAR] = set_lang(lang)


def main() -> None:
    try:
        argv, lang = pop_lang_option(sys.argv[1:])
        if lang is not None:
            apply_lang(lang)
    except ValueError as exc:
        sys.exit(f"{RED}[!] {exc}{RESET}")
    if "--uninstall" in argv:  # avant toute relance dans le .venv qu'on s'apprête à supprimer
        if "--no-banner" not in argv:
            show_banner()
        uninstall(purge_data="--purge-data" in argv, assume_yes="--yes" in argv)
        sys.exit(0)
    # Relance dans l'environnement local s'il existe (créé à la première ouverture).
    if not in_venv() and venv_python().exists() and "--no-venv" not in argv:
        os.execv(str(venv_python()), [str(venv_python()), str(Path(__file__).resolve()), *argv])  # noqa: S606
    raw = list(argv)
    forced = "--check" in argv
    # --json : la sortie doit rester du JSON pur
    quiet = "--no-banner" in argv or "--json" in argv or os.environ.get("SONDE_PASSIF_REEXEC")
    argv = [a for a in argv if a not in ("--no-banner", "--check", "--no-venv")]
    if not quiet:
        show_banner()
    if forced or not MARKER.exists() or missing_modules():
        if "--json" in argv:  # la sortie standard doit rester du JSON pur
            with contextlib.redirect_stdout(sys.stderr):
                check_setup(raw, force=forced)
        else:
            check_setup(raw, force=forced)
    from sonde.cli import app  # noqa: PLC0415 — importé seulement une fois les modules vérifiés

    if not argv:
        interactive(app)
        return
    sys.argv = ["sonde-passif", *argv]
    app(prog_name="sonde-passif")


if __name__ == "__main__":
    main()
