# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""CLI entry point for terok-shield."""


import argparse
import sys


def main(argv: list[str] | None = None) -> None:
    """Run the terok-shield CLI."""
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
    sub.add_parser("setup", help="Install firewall hook or verify bridge")
    sub.add_parser("status", help="Show shield status")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "setup":
        print("terok-shield setup: not yet implemented")
    elif args.command == "status":
        print("terok-shield status: not yet implemented")


def _get_version() -> str:
    """Return the package version."""
    from . import __version__

    return __version__
