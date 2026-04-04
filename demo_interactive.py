#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Quick interactive demo of the CLI verdict frontend."""

import sys
import time

from terok_shield.cli.interactive import CliSessionIO

EVENTS = [
    (1, "140.82.121.4", 443, 6, "github.com"),
    (2, "104.16.24.5", 443, 6, "pypi.org"),
    (3, "198.51.100.7", 8080, 6, ""),
]

io = CliSessionIO()
io.emit_banner()

for evt in EVENTS:
    time.sleep(0.3)
    io.emit_pending(*evt)
    while True:
        try:
            line = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        result = io.parse_command(line)
        if result is not None:
            break
    pid, action = result
    io.emit_verdict_applied(pid, evt[1], action, ok=True)

print("\nAll connections resolved.")
