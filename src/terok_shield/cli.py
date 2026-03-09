# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""CLI entry point for terok-shield."""

import argparse
import json
import sys

from . import (
    ExecError,
    ShieldConfig,
    ShieldMode,
    list_log_files,
    shield_allow,
    shield_deny,
    shield_resolve,
    shield_rules,
    shield_setup,
    shield_status,
    tail_log,
)


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

    p_setup = sub.add_parser("setup", help="Install firewall hook or verify bridge")
    p_setup.add_argument(
        "--bridge",
        action="store_true",
        default=False,
        help="Use bridge mode (bridge network + rootless-netns)",
    )

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
    cmd = args.command
    if cmd == "setup":
        _cmd_setup(bridge=args.bridge)
    elif cmd == "status":
        _cmd_status()
    elif cmd == "resolve":
        _cmd_resolve(args.container, force=args.force)
    elif cmd == "allow":
        _cmd_allow(args.container, args.target)
    elif cmd == "deny":
        _cmd_deny(args.container, args.target)
    elif cmd == "rules":
        _cmd_rules(args.container)
    elif cmd == "logs":
        _cmd_logs(container=args.container, n=args.n)


def _cmd_setup(bridge: bool) -> None:
    """Run shield setup."""
    mode = ShieldMode.BRIDGE if bridge else ShieldMode.HOOK
    shield_setup(config=ShieldConfig(mode=mode))
    print(f"Shield setup complete ({mode.value} mode).")


def _cmd_status() -> None:
    """Show shield status."""
    status = shield_status()
    print(f"Mode:     {status['mode']}")
    print(f"Audit:    {'enabled' if status['audit_enabled'] else 'disabled'}")
    print(f"Profiles: {', '.join(status['profiles']) or '(none)'}")
    if status["log_files"]:
        print(f"Logs:     {len(status['log_files'])} container(s)")


def _cmd_resolve(container: str, force: bool) -> None:
    """Resolve DNS profiles and cache results."""
    ips = shield_resolve(container, force=force)
    label = " (forced)" if force else ""
    print(f"Resolved {len(ips)} IPs for {container}{label}")
    for ip in ips:
        print(f"  {ip}")


def _cmd_allow(container: str, target: str) -> None:
    """Live-allow a domain or IP."""
    ips = shield_allow(container, target)
    if ips:
        print(f"Allowed {target} -> {', '.join(ips)} for {container}")
    else:
        print(f"Error: no IPs allowed for {container}", file=sys.stderr)
        sys.exit(1)


def _cmd_deny(container: str, target: str) -> None:
    """Live-deny a domain or IP."""
    ips = shield_deny(container, target)
    if ips:
        print(f"Denied {target} ({', '.join(ips)}) for {container}")
    else:
        print(f"Error: no IPs denied for {container}", file=sys.stderr)
        sys.exit(1)


def _cmd_rules(container: str) -> None:
    """Show nft rules for a container."""
    rules = shield_rules(container)
    if rules.strip():
        print(rules)
    else:
        print(f"No rules found for {container}")


def _cmd_logs(container: str | None, n: int) -> None:
    """Show audit log entries."""
    if container:
        for entry in tail_log(container, n):
            print(json.dumps(entry))
    else:
        files = list_log_files()
        if not files:
            print("No audit logs found.")
            return
        for ctr in files:
            for entry in tail_log(ctr, n):
                print(json.dumps(entry))


def _get_version() -> str:
    """Return the package version."""
    from . import __version__

    return __version__
