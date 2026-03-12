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
    import shutil

    if shutil.which("nft"):
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


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
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

    sub.add_parser("status", help="Show shield status")

    p_prepare = sub.add_parser(
        "prepare",
        help="Prepare shield and print podman flags",
        description=(
            "Resolve DNS, install hooks, and print the podman flags needed to "
            "launch a shielded container.  Use with eval:\n\n"
            '  eval "podman run $(terok-shield prepare my-ctr) alpine:latest sh"'
        ),
    )
    p_prepare.add_argument("container", help="Container name")
    p_prepare.add_argument(
        "--profiles",
        nargs="+",
        default=None,
        help="Override default profiles",
    )
    p_prepare.add_argument(
        "--json",
        action="store_true",
        default=False,
        dest="output_json",
        help="Output podman args as a JSON array (machine-readable)",
    )

    p_run = sub.add_parser(
        "run",
        help="Launch a shielded container via podman",
        description=(
            "Prepare shield and exec into podman run with the correct flags.  "
            "Everything after '--' is passed to podman run as-is:\n\n"
            "  terok-shield run my-container -- alpine:latest sh"
        ),
    )
    p_run.add_argument("container", help="Container name")
    p_run.add_argument(
        "--profiles",
        nargs="+",
        default=None,
        help="Override default profiles",
    )
    p_resolve = sub.add_parser("resolve", help="Resolve DNS profiles and cache IPs")
    p_resolve.add_argument("container", help="Container name (cache key)")
    p_resolve.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Bypass cache freshness and re-resolve",
    )

    p_allow = sub.add_parser("allow", help="Live-allow a domain or IP for a container")
    p_allow.add_argument("container", help="Container name or ID")
    p_allow.add_argument("target", help="Domain name or IP address to allow")

    p_deny = sub.add_parser("deny", help="Live-deny a domain or IP for a container")
    p_deny.add_argument("container", help="Container name or ID")
    p_deny.add_argument("target", help="Domain name or IP address to deny")

    p_down = sub.add_parser("down", help="Switch container to bypass mode (accept-all + log)")
    p_down.add_argument("container", help="Container name or ID")
    p_down.add_argument(
        "--all",
        action="store_true",
        default=False,
        dest="allow_all",
        help="Also allow private-range traffic (RFC 1918 + RFC 4193)",
    )

    p_up = sub.add_parser("up", help="Restore deny-all mode for a container")
    p_up.add_argument("container", help="Container name or ID")

    p_preview = sub.add_parser("preview", help="Show ruleset that would be applied")
    p_preview.add_argument(
        "--down",
        action="store_true",
        default=False,
        help="Show bypass ruleset instead of default deny-all",
    )
    p_preview.add_argument(
        "--all",
        action="store_true",
        default=False,
        dest="allow_all",
        help="Omit private-range reject rules (requires --down)",
    )

    p_rules = sub.add_parser("rules", help="Show current nft rules for a container")
    p_rules.add_argument("container", help="Container name or ID")

    p_logs = sub.add_parser("logs", help="Show audit log entries")
    p_logs.add_argument("--container", default=None, help="Filter by container name")
    p_logs.add_argument("-n", type=int, default=50, help="Number of recent entries")

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


def _dispatch(args: argparse.Namespace) -> None:
    """Dispatch to the appropriate subcommand handler."""
    cmd = args.command
    state_dir_override = getattr(args, "state_dir", None)

    # logs doesn't need a Shield — avoid _auto_detect_mode() / nft check
    if cmd == "logs":
        _cmd_logs(
            state_dir_override=state_dir_override,
            container=getattr(args, "container", None),
            n=args.n,
        )
        return

    # All other commands need a per-container config + Shield
    container = getattr(args, "container", None)
    config = _build_config(container, state_dir_override=state_dir_override)
    shield = Shield(config)

    if cmd == "status":
        _cmd_status(shield)
    elif cmd == "prepare":
        _cmd_prepare(shield, args.container, profiles=args.profiles, output_json=args.output_json)
    elif cmd == "run":
        _cmd_run(shield, args.container, profiles=args.profiles, podman_args=args.podman_args)
    elif cmd == "resolve":
        _cmd_resolve(shield, args.container, force=args.force)
    elif cmd == "allow":
        _cmd_allow(shield, args.container, args.target)
    elif cmd == "deny":
        _cmd_deny(shield, args.container, args.target)
    elif cmd == "down":
        _cmd_down(shield, args.container, allow_all=args.allow_all)
    elif cmd == "up":
        _cmd_up(shield, args.container)
    elif cmd == "preview":
        _cmd_preview(shield, down=args.down, allow_all=args.allow_all)
    elif cmd == "rules":
        _cmd_rules(shield, args.container)


def _cmd_status(shield: Shield) -> None:
    """Show shield status."""
    status = shield.status()
    print(f"Mode:     {status['mode']}")
    print(f"Audit:    {'enabled' if status['audit_enabled'] else 'disabled'}")
    print(f"Profiles: {', '.join(status['profiles']) or '(none)'}")


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


def _cmd_allow(shield: Shield, container: str, target: str) -> None:
    """Live-allow a domain or IP."""
    ips = shield.allow(container, target)
    if ips:
        print(f"Allowed {target} -> {', '.join(ips)} for {container}")
    else:
        print(f"Error: no IPs allowed for {container}", file=sys.stderr)
        sys.exit(1)


def _cmd_deny(shield: Shield, container: str, target: str) -> None:
    """Live-deny a domain or IP."""
    ips = shield.deny(container, target)
    if ips:
        print(f"Denied {target} ({', '.join(ips)}) for {container}")
    else:
        print(f"Error: no IPs denied for {container}", file=sys.stderr)
        sys.exit(1)


def _cmd_down(shield: Shield, container: str, *, allow_all: bool) -> None:
    """Switch container to bypass mode."""
    shield.down(container, allow_all=allow_all)
    label = " (all traffic)" if allow_all else ""
    print(f"Shield down for {container}{label}")


def _cmd_up(shield: Shield, container: str) -> None:
    """Restore deny-all mode."""
    shield.up(container)
    print(f"Shield up for {container}")


def _cmd_preview(shield: Shield, *, down: bool, allow_all: bool) -> None:
    """Show ruleset that would be applied."""
    if allow_all and not down:
        raise ValueError("--all requires --down")
    ruleset = shield.preview(down=down, allow_all=allow_all)
    label = "bypass" if down else "enforce"
    if allow_all:
        label += " (all traffic)"
    print(f"# Ruleset preview ({label}):")
    print(ruleset)


def _cmd_rules(shield: Shield, container: str) -> None:
    """Show nft rules for a container."""
    st = shield.state(container)
    print(f"State: {st.value}")
    rules = shield.rules(container)
    if rules.strip():
        print(rules)
    else:
        print(f"No rules found for {container}")


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


def _cmd_logs(
    *,
    state_dir_override: Path | None,
    container: str | None,
    n: int,
) -> None:
    """Show audit log entries.

    When ``container`` is given, tails that container's audit log.
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
