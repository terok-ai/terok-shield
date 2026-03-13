# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""CLI entry point for terok-shield."""

import argparse
import json
import os
import shlex
import sys
from pathlib import Path

from . import ExecError, Shield, ShieldConfig, ShieldMode
from .registry import COMMANDS, ArgDef, CommandDef
from .validation import validate_container_name

# ── Config construction (formerly in config.py) ──────────


def _resolve_state_root() -> Path:
    """Resolve the state root from env / XDG / default."""
    env = os.environ.get("TEROK_SHIELD_STATE_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    return base / "terok-shield"


def _resolve_config_root() -> Path:
    """Resolve the config root from env / XDG / default."""
    env = os.environ.get("TEROK_SHIELD_CONFIG_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "terok-shield"


def _parse_loopback_ports(raw: object) -> tuple[int, ...]:
    """Parse and validate loopback_ports from config YAML.

    Accepts a list of ints or a single int.  Invalid entries are silently
    dropped.
    """
    if isinstance(raw, bool):
        return ()
    if isinstance(raw, int):
        raw = [raw]
    if not isinstance(raw, list):
        return ()
    ports: list[int] = []
    for v in raw:
        if isinstance(v, bool) or not isinstance(v, int):
            continue
        if 1 <= v <= 65535:
            ports.append(v)
    return tuple(ports)


def _auto_detect_mode() -> ShieldMode:
    """Auto-detect the best available shield mode.

    Currently only hook mode is supported.

    Raises:
        RuntimeError: If no supported shield mode is available.
    """
    from .run import find_nft

    if find_nft():
        return ShieldMode.HOOK

    raise RuntimeError("No supported shield mode available. Install nft for hook mode.")


def _load_config_file() -> dict:
    """Load config.yml from the config root, returning a dict (or empty)."""
    import yaml

    config_file = _resolve_config_root() / "config.yml"
    if not config_file.is_file():
        return {}

    try:
        section = yaml.safe_load(config_file.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return {}

    return section if isinstance(section, dict) else {}


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
    section = _load_config_file()

    # Resolve mode
    mode_str = section.get("mode", "auto")
    if mode_str == "auto":
        mode = _auto_detect_mode()
    elif mode_str == "hook":
        mode = ShieldMode.HOOK
    else:
        raise ValueError(f"Unknown shield mode: {mode_str!r}")

    # Profiles
    raw_profiles = section.get("default_profiles", ["dev-standard"])
    if not isinstance(raw_profiles, list) or not all(
        isinstance(p, str) and p for p in raw_profiles
    ):
        raw_profiles = ["dev-standard"]
    profiles = tuple(raw_profiles)

    # Loopback ports
    loopback_ports = _parse_loopback_ports(section.get("loopback_ports", []))

    # Audit
    audit_section = section.get("audit", {})
    if not isinstance(audit_section, dict):
        audit_section = {}
    audit_enabled = audit_section.get("enabled", True)
    if not isinstance(audit_enabled, bool):
        audit_enabled = True

    # State dir
    if state_dir_override:
        state_root = state_dir_override.resolve()
    else:
        state_root = _resolve_state_root().resolve()

    if container:
        validate_container_name(container)
        state_dir = state_root / "containers" / container
    else:
        state_dir = state_root / "containers" / "_default"

    # Profiles dir
    profiles_dir = _resolve_config_root() / "profiles"

    return ShieldConfig(
        state_dir=state_dir,
        mode=mode,
        default_profiles=profiles,
        loopback_ports=loopback_ports,
        audit_enabled=audit_enabled,
        profiles_dir=profiles_dir,
    )


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

# Command lookup for dispatch
_CMD_LOOKUP: dict[str, CommandDef] = {cmd.name: cmd for cmd in COMMANDS}


def _add_argdef(parser: argparse.ArgumentParser, arg: ArgDef) -> None:
    """Add an :class:`ArgDef` to an argparse parser."""
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


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser from the command registry."""
    parser = argparse.ArgumentParser(
        prog="terok-shield",
        description="nftables-based egress firewalling for Podman containers",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_get_version()}",
    )
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


def _extract_handler_kwargs(args: argparse.Namespace, cmd: CommandDef) -> dict:
    """Extract keyword arguments for a registry handler from parsed args."""
    kwargs: dict = {}
    for arg in cmd.args:
        key = arg.dest or arg.name.lstrip("-").replace("-", "_")
        if hasattr(args, key):
            kwargs[key] = getattr(args, key)
    return kwargs


def _dispatch(args: argparse.Namespace) -> None:
    """Dispatch to the appropriate subcommand handler."""
    cmd_name = args.command
    state_dir_override = getattr(args, "state_dir", None)

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


# ── CLI-only command handlers ─────────────────────────────


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


_SHIELD_MANAGED_FLAGS = frozenset(
    {
        "--name",
        "--network",
        "--hooks-dir",
        "--annotation",
        "--cap-add",
        "--cap-drop",
        "--security-opt",
    }
)


def _reject_shield_managed_flags(podman_args: list[str]) -> None:
    """Reject podman flags that conflict with shield-managed configuration."""
    conflicts: set[str] = set()
    for arg in podman_args:
        if arg.startswith("--"):
            flag = arg.split("=", 1)[0]
            if flag in _SHIELD_MANAGED_FLAGS:
                conflicts.add(flag)
    if conflicts:
        raise ValueError(
            f"Flag(s) managed by terok-shield, cannot override: {', '.join(sorted(conflicts))}"
        )


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

    shield_args = shield.pre_start(container, profiles)
    argv = ["podman", "run", "--name", container, *shield_args, *podman_args]
    os.execvp("podman", argv)


def _cmd_resolve(shield: Shield, container: str, force: bool) -> None:
    """Resolve DNS profiles and cache results."""
    ips = shield.resolve(force=force)
    label = " (forced)" if force else ""
    print(f"Resolved {len(ips)} IPs for {container}{label}")
    for ip in ips:
        print(f"  {ip}")


# ── CLI-only logs with aggregation ────────────────────────


def _collect_all_audit_entries(state_root: Path, n: int) -> list[dict]:
    """Collect audit entries from all containers, sorted by timestamp, trimmed to n."""
    from .audit import AuditLogger

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


def _cmd_logs_cli(
    *,
    state_dir_override: Path | None,
    container: str | None,
    n: int,
) -> None:
    """Show audit log entries (CLI-only: supports aggregated mode).

    When ``container`` is given, tails that container's audit log directly
    (no Shield needed — avoids requiring nft for a read-only operation).
    Otherwise, collects entries from all containers, sorts by timestamp,
    and prints the most recent ``n`` globally.
    """
    from .audit import AuditLogger

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


def _get_version() -> str:
    """Return the package version."""
    from . import __version__

    return __version__
