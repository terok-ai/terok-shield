# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Standalone CLI — parses argv, builds a Shield, and dispatches commands.

Constructs ``ShieldConfig`` from ``config.yml``, XDG conventions, and
environment variables, then routes each subcommand through the
``COMMANDS`` registry (``cli.registry``).  Five commands with standalone
CLI logic are handled directly by ``_dispatch`` — ``setup`` and ``logs``
(which bypass Shield entirely) and ``prepare``, ``run``, ``resolve``
(which need Shield but carry extra CLI concerns).  All others delegate
to their registry handler via ``Shield`` (the public API facade).
"""

import argparse
import json
import os
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any

from .. import ExecError, Shield, ShieldConfig, ShieldMode
from ..config import ShieldFileConfig
from ..container import resolve_state_dir as resolve_container_state_dir
from ..validation import validate_container_name
from .registry import COMMANDS, ArgDef, CommandDef

# ── Entry point ──────────────────────────────────────────


def main(argv: list[str] | None = None) -> None:
    """Run the terok-shield CLI."""
    if argv is None:
        argv = sys.argv[1:]

    # The 'run' subcommand uses '--' to separate shield args from podman args.
    # Split before argparse to avoid REMAINDER quirks with optional flags.
    saw_separator = "--" in argv
    run_trailing: list[str] = []
    if saw_separator:
        sep = argv.index("--")
        run_trailing = argv[sep + 1 :]
        argv = argv[:sep]

    parser = _build_parser()
    args = parser.parse_args(argv)

    if saw_separator and args.command != "run":
        parser.error("'--' separator is only supported by the 'run' subcommand")

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "run":
        args.podman_args = run_trailing

    try:
        _dispatch(args)
    except (RuntimeError, ValueError, ExecError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


# ── Command dispatch ─────────────────────────────────────

# Command lookup for dispatch
_CMD_LOOKUP: dict[str, CommandDef] = {cmd.name: cmd for cmd in COMMANDS}


def _dispatch(args: argparse.Namespace) -> None:
    """Dispatch to the appropriate subcommand handler."""
    cmd_name = args.command
    state_dir_override = getattr(args, "state_dir", None)

    # CLI-only: setup doesn't need Shield
    if cmd_name == "setup":
        _cmd_setup(root=getattr(args, "root", False), user=getattr(args, "user", False))
        return

    # CLI-only: logs with aggregated mode (no container -> scan all)
    if cmd_name == "logs":
        _cmd_logs_cli(
            state_dir_override=state_dir_override,
            container=getattr(args, "container", None),
            n=args.n,
        )
        return

    # All other commands need a per-container config + Shield
    container = getattr(args, "container", None)
    config = _build_config(container, state_dir_override=state_dir_override)
    shield = Shield(config)

    # CLI-only standalone commands with custom logic
    if cmd_name == "prepare":
        _cmd_prepare(shield, args.container, profiles=args.profiles, output_json=args.output_json)
    elif cmd_name == "run":
        _cmd_run(shield, args.container, profiles=args.profiles, podman_args=args.podman_args)
    elif cmd_name == "resolve":
        _cmd_resolve(shield, args.container, force=args.force)
    else:
        # Generic registry dispatch
        cmd_def = _CMD_LOOKUP[cmd_name]
        if cmd_def.handler is None:
            raise RuntimeError(f"Command {cmd_name!r} has no handler (standalone-only)")
        kwargs = _extract_handler_kwargs(args, cmd_def)
        if cmd_def.needs_container:
            cmd_def.handler(shield, container, **kwargs)
        else:
            cmd_def.handler(shield, **kwargs)


def _extract_handler_kwargs(args: argparse.Namespace, cmd: CommandDef) -> dict:
    """Extract keyword arguments for a registry handler from parsed args."""
    kwargs: dict = {}
    for arg in cmd.args:
        key = arg.dest or arg.name.lstrip("-").replace("-", "_")
        if hasattr(args, key):
            kwargs[key] = getattr(args, key)
    return kwargs


# ── Argument parser ──────────────────────────────────────

# Custom descriptions for standalone-only commands
_DESCRIPTIONS: dict[str, str] = {
    "prepare": (
        "Resolve DNS, install hooks, and print the podman flags needed to "
        "launch a shielded container.  Use with eval:\n\n"
        '  eval "podman run $(terok-shield prepare my-ctr) alpine:latest sh"'
    ),
    "run": (
        "Prepare shield and exec into podman run with the correct flags.  "
        "Everything after '--' is passed to podman run as-is:\n\n"
        "  terok-shield run my-container -- alpine:latest sh"
    ),
}


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser from the command registry."""
    parser = argparse.ArgumentParser(
        prog="terok-shield",
        description="nftables-based egress firewalling for Podman containers",
    )

    class _VersionAction(argparse.Action):
        """Lazy version action — only calls podman/nft when --version is used."""

        def __init__(self, **kwargs: Any) -> None:
            """Accept standard argparse Action kwargs."""
            super().__init__(nargs=0, **kwargs)

        def __call__(self, parser: argparse.ArgumentParser, *_args: Any, **_kw: Any) -> None:
            """Print version info and exit."""
            print(_version_string())
            parser.exit()

    parser.add_argument("--version", action=_VersionAction)
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=None,
        help="Override state root directory",
    )
    sub = parser.add_subparsers(dest="command")

    for cmd in COMMANDS:
        kwargs: dict = {"help": cmd.help}
        if cmd.name in _DESCRIPTIONS:
            kwargs["description"] = _DESCRIPTIONS[cmd.name]
        p = sub.add_parser(cmd.name, **kwargs)

        # Container arg: `logs` uses --container (optional) in CLI for aggregated mode
        if cmd.needs_container:
            if cmd.name == "logs":
                p.add_argument("--container", default=None, help="Filter by container name")
            else:
                p.add_argument("container", help="Container name or ID")

        for arg in cmd.args:
            _add_argdef(p, arg)

    # Inject "status CONTAINER" as a visible second line in help output
    _orig_format_help = parser.format_help

    def _format_help() -> str:
        """Return help text with 'status CONTAINER' hint injected."""
        text = _orig_format_help()
        marker = "\n    status "
        idx = text.find(marker)
        if idx == -1:
            return text
        eol = text.index("\n", idx + 1)
        hint = "\n    status CONTAINER    Query container firewall state (up/down/down_all/inactive/error)"
        return text[:eol] + hint + text[eol:]

    parser.format_help = _format_help  # type: ignore[assignment]
    return parser


def _add_argdef(parser: argparse.ArgumentParser, arg: ArgDef) -> None:
    """Add an [`ArgDef`][terok_shield.cli.main.ArgDef] to an argparse parser."""
    kwargs: dict = {}
    if arg.help:
        kwargs["help"] = arg.help
    if arg.type is not None:
        kwargs["type"] = arg.type
    if arg.default is not None:
        kwargs["default"] = arg.default
    if arg.action is not None:
        kwargs["action"] = arg.action
    if arg.dest is not None:
        kwargs["dest"] = arg.dest
    if arg.nargs is not None:
        kwargs["nargs"] = arg.nargs
    parser.add_argument(arg.name, **kwargs)


# ── CLI-only command handlers ────────────────────────────


def _cmd_prepare(
    shield: Shield,
    container: str,
    *,
    profiles: list[str] | None,
    output_json: bool = False,
) -> None:
    """Print podman flags for a shielded container launch."""
    podman_args = shield.pre_start(container, profiles)
    podman_args += ["--name", container]
    if output_json:
        print(json.dumps(podman_args))
    else:
        print(" ".join(shlex.quote(a) for a in podman_args))


def _cmd_run(
    shield: Shield,
    container: str,
    *,
    profiles: list[str] | None,
    podman_args: list[str],
) -> None:
    """Launch a shielded container by exec-ing into podman run."""
    if not podman_args:
        raise ValueError(
            "No image specified. Usage: terok-shield run <container> -- <image> [cmd...]"
        )

    _reject_shield_managed_flags(podman_args)

    podman = _find_podman()
    shield_args = shield.pre_start(container, profiles)
    argv = [podman, "run", "--name", container, *shield_args, *podman_args]
    # Exec replaces the current process; argv is constructed locally and uses
    # an absolute podman path, so shell injection and PATH spoofing do not apply.
    os.execv(podman, argv)  # nosec B606


_SHIELD_MANAGED_FLAGS = frozenset(
    {
        "--name",
        "--network",
        "--hooks-dir",
        "--annotation",
        "--cap-add",
        "--cap-drop",
    }
)

# Podman flag aliases that map to a canonical shield-managed flag.
_FLAG_ALIASES: dict[str, str] = {
    "--net": "--network",
}


def _find_podman() -> str:
    """Locate the podman binary for the ``run`` subcommand."""
    found = shutil.which("podman")
    if found:
        resolved = Path(found).resolve()
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return str(resolved)
    raise OSError("podman binary not found. Install Podman to use 'terok-shield run'.")


def _reject_shield_managed_flags(podman_args: list[str]) -> None:
    """Reject podman flags that conflict with shield-managed configuration."""
    conflicts: set[str] = set()
    for arg in podman_args:
        if arg.startswith("--"):
            flag = arg.split("=", 1)[0]
            flag = _FLAG_ALIASES.get(flag, flag)
            if flag in _SHIELD_MANAGED_FLAGS:
                conflicts.add(flag)
    if conflicts:
        raise ValueError(
            f"Flag(s) managed by terok-shield, cannot override: {', '.join(sorted(conflicts))}"
        )


def _cmd_resolve(shield: Shield, container: str, force: bool) -> None:
    """Resolve DNS profiles and cache results."""
    ips = shield.resolve(force=force)
    label = " (forced)" if force else ""
    print(f"Resolved {len(ips)} IPs for {container}{label}")
    for ip in ips:
        print(f"  {ip}")


def _cmd_logs_cli(
    *,
    state_dir_override: Path | None,
    container: str | None,
    n: int,
) -> None:
    """Show audit log entries — supports aggregated mode without Shield.

    When ``container`` is given, tails that container's audit log directly
    (no Shield needed — avoids requiring nft for a read-only operation).
    Otherwise, collects entries from all containers, sorts by timestamp,
    and prints the most recent ``n`` globally.
    """
    from ..audit import AuditLogger

    state_root = (state_dir_override or _resolve_state_root()).resolve()
    if container:
        validate_container_name(container)
        audit_file = state_root / "containers" / container / "audit.jsonl"
        for entry in AuditLogger(audit_path=audit_file).tail_log(n):
            print(json.dumps(entry))
    else:
        entries = _collect_all_audit_entries(state_root, n)
        if not entries:
            print("No audit logs found.")
            return
        for entry in entries:
            print(json.dumps(entry))


def _collect_all_audit_entries(state_root: Path, n: int) -> list[dict]:
    """Collect audit entries from all containers, sorted by timestamp, trimmed to n."""
    from ..audit import AuditLogger

    containers_dir = state_root / "containers"
    if not containers_dir.is_dir():
        return []
    entries: list[dict] = []
    for ctr_dir in sorted(containers_dir.iterdir()):
        audit_file = ctr_dir / "audit.jsonl"
        if audit_file.is_file():
            entries.extend(AuditLogger(audit_path=audit_file).tail_log(n))
    entries.sort(key=lambda e: e.get("ts", ""))
    return entries[-n:]


def _cmd_setup(*, root: bool, user: bool) -> None:
    """Install global OCI hooks for podman < 5.6.0 restart persistence."""
    from ..hooks.install import setup_global_hooks
    from ..podman_info import (
        USER_HOOKS_DIR,
        _user_containers_conf,
        ensure_containers_conf_hooks_dir,
        system_hooks_dir,
    )

    sys_dir = system_hooks_dir()
    usr_dir = USER_HOOKS_DIR.expanduser()
    conf_path = _user_containers_conf()

    if root and user:
        raise ValueError("--root and --user are mutually exclusive")

    if not root and not user:
        # Interactive: present options
        print("terok-shield setup: install global OCI hooks\n")
        print(f"  [r] System-wide (sudo) -> {sys_dir}")
        print(f"  [u] User-local         -> {usr_dir}")
        print(f"      (+ update {conf_path})")
        print()
        choice = input("Choose [r/u]: ").strip().lower()
        if choice == "r":
            root = True
        elif choice == "u":
            user = True
        else:
            print("Cancelled.")
            return

    if root:
        print(f"Installing hooks to {sys_dir} (sudo)...")
        setup_global_hooks(sys_dir, use_sudo=True)
        print("Done. Global hooks installed.")
    elif user:
        print(f"Installing hooks to {usr_dir}...")
        setup_global_hooks(usr_dir)
        ensure_containers_conf_hooks_dir(usr_dir)
        print("Done. Global hooks installed.")


# ── Config construction ──────────────────────────────────


def _build_config(
    container: str | None = None,
    *,
    state_dir_override: Path | None = None,
) -> ShieldConfig:
    """Build a ShieldConfig from config.yml + env vars.

    Args:
        container: Container name (used for per-container state_dir).
        state_dir_override: Explicit state_dir from --state-dir flag.
    """
    file_cfg = _load_config_file()

    # Resolve mode
    mode = _auto_detect_mode() if file_cfg.mode == "auto" else ShieldMode.HOOK

    if container:
        validate_container_name(container)

    state_dir = _resolve_state_dir(container, state_dir_override)

    # Profiles dir
    profiles_dir = _resolve_config_root() / "profiles"

    return ShieldConfig(
        state_dir=state_dir,
        mode=mode,
        default_profiles=tuple(file_cfg.default_profiles),
        loopback_ports=tuple(file_cfg.loopback_ports),
        audit_enabled=file_cfg.audit.enabled,
        profiles_dir=profiles_dir,
    )


def _resolve_state_dir(container: str | None, state_dir_override: Path | None) -> Path:
    """Return the per-container state directory.

    Resolution order, first hit wins:

    1. ``--state-dir`` flag.  The caller explicitly said where the
       state root lives, so nest under ``containers/<name>`` there.
       Used by tests and anyone driving the CLI by hand with a
       custom layout.
    2. ``podman inspect`` of *container*'s ``terok.shield.state_dir``
       annotation.  This is the path shield's own ``pre_start()``
       writes and the OCI hook reads — the single source of truth for
       any shielded container.  If the annotation is missing the
       container simply wasn't launched through shield, so we fail
       loudly rather than guess a layout that won't match anything.
    3. No container given (commands like ``install-hooks`` that aren't
       per-container): use the default root + ``_default`` slot.
    """
    if state_dir_override is not None:
        state_root = state_dir_override.resolve()
        return state_root / "containers" / (container or "_default")
    if container:
        annotated = resolve_container_state_dir(container)
        if annotated is None:
            raise SystemExit(
                f"container {container!r} has no 'terok.shield.state_dir' annotation — "
                "was it launched through shield.pre_start()? "
                "Pass --state-dir=<root> if you know where its state lives."
            )
        return annotated
    state_root = _resolve_state_root().resolve()
    return state_root / "containers" / "_default"


def _load_config_file() -> ShieldFileConfig:
    """Load and validate ``config.yml`` via [`ShieldFileConfig`][terok_shield.cli.main.ShieldFileConfig].

    Returns defaults when the file is missing or contains invalid YAML.
    Validation errors (typos, wrong types) abort with a clear message.
    """
    import yaml
    from pydantic import ValidationError

    config_file = _resolve_config_root() / "config.yml"
    if not config_file.is_file():
        return ShieldFileConfig()

    try:
        raw = yaml.safe_load(config_file.read_text()) or {}
    except yaml.YAMLError as e:
        print(f"Warning [shield]: failed to parse {config_file}: {e}", file=sys.stderr)
        return ShieldFileConfig()
    except OSError as e:
        print(f"Warning [shield]: failed to read {config_file}: {e}", file=sys.stderr)
        return ShieldFileConfig()

    if not isinstance(raw, dict):
        print(
            f"Warning [shield]: {config_file}: expected mapping, got {type(raw).__name__}",
            file=sys.stderr,
        )
        return ShieldFileConfig()

    try:
        return ShieldFileConfig(**raw)
    except ValidationError as e:
        print(f"Error [shield]: invalid {config_file}:\n{e}", file=sys.stderr)
        sys.exit(1)


def _resolve_state_root() -> Path:
    """Resolve the state root from env / XDG / default."""
    env = os.environ.get("TEROK_SHIELD_STATE_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "terok" / "shield"


def _resolve_config_root() -> Path:
    """Resolve the config root from env / XDG / default."""
    env = os.environ.get("TEROK_SHIELD_CONFIG_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "terok" / "shield"


def _auto_detect_mode() -> ShieldMode:
    """Auto-detect the best available shield mode.

    Currently only hook mode is supported.

    Raises:
        NftNotFoundError: If nft is not installed.
    """
    from ..run import NftNotFoundError, find_nft

    if find_nft():
        return ShieldMode.HOOK

    raise NftNotFoundError("No supported shield mode available. Install nft for hook mode.")


# ── Version display ──────────────────────────────────────


def _version_string() -> str:
    """Return version string with terok-shield and podman versions."""
    from ..run import find_nft

    version = _get_version()
    lines = [f"terok-shield {version}"]
    # Best-effort podman version (don't fail if podman is missing)
    try:
        import subprocess

        r = subprocess.run(  # noqa: S603, S607
            ["podman", "version", "--format", "{{.Client.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        podman_v = r.stdout.strip() if r.returncode == 0 else "not found"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        podman_v = "not found"
    lines.append(f"podman {podman_v}")
    nft = find_nft()
    lines.append(f"nft {'found' if nft else 'not found'}")
    return "\n".join(lines)


def _get_version() -> str:
    """Return the package version."""
    from .. import __version__

    return __version__
