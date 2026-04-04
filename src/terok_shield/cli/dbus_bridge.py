# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""``shield dbus-bridge`` entry point — standalone D-Bus bridge launcher.

Acquires the per-container well-known bus name on the session bus,
creates a :class:`~terok_shield.lib.dbus_bridge.ShieldBridge`, and
runs until SIGINT/SIGTERM.  For orchestrated use (e.g. terok TUI),
import :class:`ShieldBridge` directly and manage the bus externally.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


async def _run_bridge(state_dir: Path, container: str) -> None:
    """Connect to the session bus, acquire the bus name, and run the bridge."""
    from dbus_fast.aio import MessageBus

    from ..lib.dbus_bridge import ShieldBridge, bus_name_for_container

    bus = await MessageBus().connect()
    bridge = ShieldBridge(state_dir=state_dir, container=container, bus=bus)

    name = bus_name_for_container(bridge.container_id)
    reply = await bus.request_name(name)
    from dbus_fast import RequestNameReply

    if reply != RequestNameReply.PRIMARY_OWNER:
        print(
            f"Error: could not acquire bus name {name} (another bridge may be running).",
            file=sys.stderr,
        )
        bus.disconnect()
        raise SystemExit(1)

    stop_event = asyncio.Event()

    def _on_signal() -> None:
        """Set the stop event on SIGINT/SIGTERM."""
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _on_signal)

    await bridge.start()
    logger.info("D-Bus bridge active: %s -> %s", container, name)

    try:
        await stop_event.wait()
    finally:
        await bridge.stop()
        bus.disconnect()


def run_dbus_bridge(state_dir: Path, container: str) -> None:
    """Start the standalone D-Bus bridge for a container.

    Acquires the per-container bus name, spawns the interactive
    subprocess, and relays events until interrupted.

    Args:
        state_dir: Per-container state directory.
        container: Container name.

    Raises:
        SystemExit: If the bus name cannot be acquired.
    """
    try:
        asyncio.run(_run_bridge(state_dir, container))
    except KeyboardInterrupt:
        pass
