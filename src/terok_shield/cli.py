# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""CLI entry point for terok-shield."""

import argparse
import json
import sys

from . import ExecError, Shield, ShieldConfig


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
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("setup", help="Install firewall hook")

    sub.add_parser("status", help="Show shield status")

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
        help="Also allow RFC1918/link-local traffic",
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
        help="Omit RFC1918 reject rules (requires --down)",
    )

    p_rules = sub.add_parser("rules", help="Show current nft rules for a container")
    p_rules.add_argument("container", help="Container name or ID")

    p_logs = sub.add_parser("logs", help="Show audit log entries")
    p_logs.add_argument("--container", default=None, help="Filter by container name")
    p_logs.add_argument("-n", type=int, default=50, help="Number of recent entries")

    return parser


def main(argv: list[str] | None = None) -> None:
    """Run the terok-shield CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    try:
        _dispatch(args)
    except (RuntimeError, ValueError, ExecError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def _dispatch(args: argparse.Namespace) -> None:
    """Dispatch to the appropriate subcommand handler."""
    shield = Shield(ShieldConfig())
    cmd = args.command
    if cmd == "setup":
        _cmd_setup(shield)
    elif cmd == "status":
        _cmd_status(shield)
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
    elif cmd == "logs":
        _cmd_logs(shield, container=args.container, n=args.n)


def _cmd_setup(shield: Shield) -> None:
    """Run shield setup."""
    shield.setup()
    print("Shield setup complete (hook mode).")


def _cmd_status(shield: Shield) -> None:
    """Show shield status."""
    status = shield.status()
    print(f"Mode:     {status['mode']}")
    print(f"Audit:    {'enabled' if status['audit_enabled'] else 'disabled'}")
    print(f"Profiles: {', '.join(status['profiles']) or '(none)'}")
    if status["log_files"]:
        print(f"Logs:     {len(status['log_files'])} container(s)")


def _cmd_resolve(shield: Shield, container: str, force: bool) -> None:
    """Resolve DNS profiles and cache results."""
    ips = shield.resolve(container, force=force)
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


def _cmd_logs(shield: Shield, container: str | None, n: int) -> None:
    """Show audit log entries."""
    if container:
        for entry in shield.tail_log(container, n):
            print(json.dumps(entry))
    else:
        files = shield.log_files()
        if not files:
            print("No audit logs found.")
            return
        for ctr in files:
            for entry in shield.tail_log(ctr, n):
                print(json.dumps(entry))


def _get_version() -> str:
    """Return the package version."""
    from . import __version__

    return __version__
