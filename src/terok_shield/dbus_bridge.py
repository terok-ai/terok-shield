# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""D-Bus event bridge for interactive NFLOG sessions.

Translates between :class:`InteractiveSession`'s JSON-lines protocol and
D-Bus ``org.terok.Shield1`` signals/methods.  Each bridge serves one
container; MPRIS-style per-container bus names
(``org.terok.Shield1.Container_<short_id>``) allow unlimited coexistence.

The bridge does **not** own the bus name — the caller (standalone CLI or
orchestrator) acquires the name and passes the connected bus.  This lets
a single orchestrator manage multiple bridges on one bus connection.

Requires optional dependencies ``dbus-fast`` and ``terok-dbus``.
Install via ``poetry install --with dbus``.
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

try:
    from dbus_fast.aio import MessageBus
    from dbus_fast.service import ServiceInterface, method, signal
except ImportError as _exc:
    raise ImportError(
        "D-Bus bridge requires dbus-fast and terok-dbus. Install via: poetry install --with dbus"
    ) from _exc

try:
    from terok_dbus._interfaces import SHIELD_INTERFACE_NAME, SHIELD_OBJECT_PATH
except ImportError as _exc:
    raise ImportError(
        "D-Bus bridge requires terok-dbus. Install via: poetry install --with dbus"
    ) from _exc

from .state import container_id_path

logger = logging.getLogger(__name__)

BUS_NAME_PREFIX = "org.terok.Shield1.Container_"
"""Per-container bus name prefix.  Suffixed with the short container ID."""

_NSENTER_ENV = "_TEROK_SHIELD_NFLOG_NSENTER"
_RAW_ENV = "_TEROK_SHIELD_NFLOG_RAW"


def _propagate_pythonpath(env: dict[str, str]) -> None:
    """Ensure ``terok_shield`` is importable in the interactive subprocess.

    Mirrors :func:`terok_shield.cli.interactive._propagate_pythonpath` —
    duplicated because tach layer boundaries prevent support->cli imports.
    """
    # terok_shield/ is one level up from this file; site-packages is two.
    site = str(Path(__file__).resolve().parent.parent)
    existing = env.get("PYTHONPATH", "")
    if site not in existing.split(os.pathsep):
        env["PYTHONPATH"] = f"{site}{os.pathsep}{existing}" if existing else site


def bus_name_for_container(short_id: str) -> str:
    """Derive the per-container well-known bus name.

    D-Bus bus name segments must start with ``[A-Za-z_]``, so hex IDs
    (which may start with a digit) are prefixed with ``Container_``.
    """
    return f"{BUS_NAME_PREFIX}{short_id}"


class _ShieldInterface(ServiceInterface):
    """D-Bus ``org.terok.Shield1`` interface exported by the bridge.

    Signals are emitted when the subprocess produces JSON events.
    The ``Verdict`` method routes operator decisions back to the subprocess.

    Signal decorators use explicit ``name=`` to emit CamelCase member names
    per the D-Bus specification, while keeping Pythonic snake_case in code.
    dbus-fast defaults to the Python method name, which would produce
    non-standard snake_case on the wire and break ``EventSubscriber``'s
    member-name matching (and any other D-Bus client).
    """

    def __init__(self, bridge: "ShieldBridge") -> None:
        """Initialise with a back-reference to the bridge for verdict routing."""
        super().__init__(SHIELD_INTERFACE_NAME)
        self._bridge = bridge

    @signal(name="ConnectionBlocked")
    def connection_blocked(
        self,
        container: "s",
        dest: "s",
        port: "q",
        proto: "q",
        domain: "s",
        request_id: "s",
    ) -> "ssqqss":
        """Emit when a new outbound connection is blocked."""
        return [container, dest, port, proto, domain, request_id]

    @signal(name="VerdictApplied")
    def verdict_applied(
        self,
        container: "s",
        dest: "s",
        request_id: "s",
        action: "s",
        ok: "b",
    ) -> "ssssb":
        """Emit after a verdict has been applied to the nft ruleset."""
        return [container, dest, request_id, action, ok]

    @method(name="Verdict")
    async def verdict(self, request_id: "s", action: "s") -> "b":
        """Route an operator verdict to the subprocess stdin."""
        return await self._bridge.submit_verdict(request_id, action)


class ShieldBridge:
    """D-Bus bridge for one container's interactive NFLOG session.

    Spawns ``InteractiveSession`` (JSON-lines mode) as a subprocess that
    enters the container's network namespace via nsenter.  Translates
    JSON-lines events to D-Bus ``Shield1`` signals and routes verdicts
    from D-Bus method calls back to the subprocess's stdin.

    Args:
        state_dir: Per-container state directory.
        container: Container name (used for nsenter and signal payloads).
        bus: Connected ``MessageBus`` instance (caller-owned).
    """

    def __init__(self, *, state_dir: Path, container: str, bus: MessageBus) -> None:
        """Initialise the bridge with state directory, container name, and bus."""
        self._state_dir = state_dir
        self._container = container
        self._bus = bus
        self._process: asyncio.subprocess.Process | None = None
        self._read_task: asyncio.Task[None] | None = None
        self._interface = _ShieldInterface(self)
        self._container_id: str | None = None

    @property
    def container_id(self) -> str:
        """Short container ID read from ``state_dir/container.id``."""
        if self._container_id is None:
            id_path = container_id_path(self._state_dir)
            if not id_path.is_file():
                raise FileNotFoundError(
                    f"Container ID not found at {id_path}. "
                    "Run 'shield prepare' first to persist the container ID."
                )
            self._container_id = id_path.read_text().strip()
        return self._container_id

    @property
    def bus_name(self) -> str:
        """Per-container well-known bus name."""
        return bus_name_for_container(self.container_id)

    # ── Lifecycle ────────────────────────────────────────

    async def start(self) -> None:
        """Spawn the interactive subprocess and begin the event relay loop.

        Exports the Shield1 interface on the bus at
        ``/org/terok/Shield1``, then reads JSON lines from the subprocess
        stdout and emits D-Bus signals for each event.
        """
        # Preload bus_name (file I/O) before any side effects so a
        # missing container.id raises before we export or spawn.
        name = self.bus_name

        self._bus.export(SHIELD_OBJECT_PATH, self._interface)
        try:
            env = {**os.environ, _RAW_ENV: "1"}
            env.pop(_NSENTER_ENV, None)
            _propagate_pythonpath(env)
            self._process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "terok_shield.cli.interactive",
                str(self._state_dir),
                self._container,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=None,
                env=env,
            )
        except Exception:
            try:
                self._bus.unexport(SHIELD_OBJECT_PATH, self._interface)
            except Exception:
                logger.debug("Unexport failed during start rollback", exc_info=True)
            raise
        self._read_task = asyncio.create_task(self._read_loop())
        logger.info(
            "Bridge started for %s (bus name: %s, pid: %s)",
            self._container,
            name,
            self._process.pid,
        )

    # ── Event relay ──────────────────────────────────────

    async def submit_verdict(self, request_id: str, action: str) -> bool:
        """Write a verdict command to the subprocess stdin.

        Args:
            request_id: Compound ID ``"{container}:{packet_id}"``.
            action: ``"accept"`` or ``"deny"``.

        Returns:
            ``True`` if the verdict was written successfully.
        """
        if not self._process or self._process.stdin is None:
            logger.warning("Cannot submit verdict — subprocess not running")
            return False

        if action not in ("accept", "deny"):
            logger.warning("Invalid verdict action: %s", action)
            return False

        container, sep, packet_raw = request_id.partition(":")
        if not sep or not container:
            logger.warning("Invalid request_id format: %s", request_id)
            return False
        if container != self._container:
            logger.warning(
                "request_id container mismatch: expected=%s got=%s",
                self._container,
                container,
            )
            return False
        try:
            packet_id = int(packet_raw)
        except ValueError:
            logger.warning("Non-integer packet ID in request_id: %s", request_id)
            return False

        verdict = {"type": "verdict", "id": packet_id, "action": action}
        line = json.dumps(verdict, separators=(",", ":")) + "\n"
        try:
            self._process.stdin.write(line.encode())
            await self._process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            logger.warning("Subprocess stdin closed while writing verdict")
            return False
        return True

    async def _read_loop(self) -> None:
        """Read JSON lines from the subprocess stdout and emit D-Bus signals."""
        if self._process is None or self._process.stdout is None:
            logger.error("Read loop called without a running subprocess")
            return
        try:
            async for raw_line in self._process.stdout:
                line = raw_line.decode().strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("Non-JSON line from subprocess: %s", line)
                    continue
                self._dispatch_event(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Read loop error for %s", self._container)
        finally:
            logger.debug("Read loop exited for %s", self._container)

    def _dispatch_event(self, event: dict) -> None:
        """Route a parsed JSON event to the appropriate D-Bus signal."""
        event_type = event.get("type")
        if event_type == "pending":
            request_id = f"{self._container}:{event['id']}"
            self._interface.connection_blocked(
                self._container,
                event.get("dest", ""),
                event.get("port", 0),
                event.get("proto", 0),
                event.get("domain", ""),
                request_id,
            )
        elif event_type == "verdict_applied":
            request_id = f"{self._container}:{event['id']}"
            self._interface.verdict_applied(
                self._container,
                event.get("dest", ""),
                request_id,
                event.get("action", ""),
                event.get("ok", False),
            )
        else:
            logger.debug("Ignoring unknown event type: %s", event_type)

    # ── Shutdown ─────────────────────────────────────────

    async def stop(self) -> None:
        """Terminate the subprocess and clean up resources.

        Runs cleanup to completion even if the caller's task is
        cancelled, then re-raises ``CancelledError``.
        """
        await self._cancel_read_task()
        cancelled = await self._terminate_process()
        self._unexport_bus()
        logger.info("Bridge stopped for %s", self._container)
        if cancelled:
            raise asyncio.CancelledError

    async def _cancel_read_task(self) -> None:
        """Cancel the read-loop task and await its completion."""
        if not self._read_task or self._read_task.done():
            return
        self._read_task.cancel()
        try:
            await self._read_task
        except asyncio.CancelledError:  # NOSONAR(S5754) expected from cancel() above
            pass

    async def _terminate_process(self) -> bool:
        """Terminate the subprocess, escalating to kill on timeout.

        Returns ``True`` if a ``CancelledError`` was caught during
        the wait (external cancellation of ``stop()``).
        """
        if not self._process or self._process.returncode is not None:
            return False
        try:
            self._process.terminate()
        except ProcessLookupError:
            logger.debug("Subprocess already exited before terminate")
            return False
        try:
            await asyncio.wait_for(self._process.wait(), timeout=5.0)
        except asyncio.CancelledError:  # NOSONAR(S5754) re-raised by stop() via flag
            return True
        except TimeoutError:
            try:
                self._process.kill()
            except ProcessLookupError:
                logger.debug("Subprocess already exited before kill")
            else:
                try:
                    await self._process.wait()
                except asyncio.CancelledError:  # NOSONAR(S5754) re-raised by stop()
                    return True
        return False

    def _unexport_bus(self) -> None:
        """Remove the Shield1 interface from the bus."""
        try:
            self._bus.unexport(SHIELD_OBJECT_PATH, self._interface)
        except Exception:
            logger.debug("Unexport failed during stop", exc_info=True)
