# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Hook mode: OCI hooks + per-container netns.

Uses OCI hooks to apply per-container nftables rules inside each
container's network namespace.  No root required — only podman and nft.
The OCI hook (``oci_hook.py``) applies the ruleset at container creation;
this module handles setup, DNS pre-resolution, and live allow/deny.
"""

import json
import os
import shlex
import stat
import sys

from .config import (
    ANNOTATION_KEY,
    ANNOTATION_NAME_KEY,
    ShieldConfig,
    ShieldState,
    ensure_shield_dirs,
    shield_hook_entrypoint,
    shield_hooks_dir,
    shield_resolved_dir,
)
from .dns import resolve_and_cache
from .nft import (
    NFT_TABLE,
    add_elements_dual,
    bypass_ruleset,
    hook_ruleset,
    safe_ip,
    verify_bypass_ruleset,
    verify_ruleset,
)
from .profiles import compose_profiles
from .run import ExecError, nft_via_nsenter, podman_inspect, run as run_cmd
from .util import is_ipv4


def _resolve_container_name(container: str) -> str:
    """Resolve the canonical container name from the shield annotation.

    Falls back to the raw *container* argument if the annotation is
    missing or podman inspect fails (e.g. container not running).
    """
    try:
        name = podman_inspect(
            container,
            '{{index .Config.Annotations "' + ANNOTATION_NAME_KEY + '"}}',
        )
        if name and name != "<no value>":
            return name
    except (OSError, RuntimeError):
        pass
    return container


def _detect_rootless_network_mode() -> str:
    """Detect the rootless network mode (pasta or slirp4netns).

    Runs ``podman info -f json`` and reads ``host.rootlessNetworkCmd``.
    Returns ``"pasta"`` if detection fails (modern podman default).
    """
    output = run_cmd(["podman", "info", "-f", "json"], check=False)
    if not output:
        return "pasta"
    try:
        info = json.loads(output)
    except json.JSONDecodeError:
        return "pasta"
    cmd = info.get("host", {}).get("rootlessNetworkCmd", "")
    return cmd if cmd in ("pasta", "slirp4netns") else "pasta"


def _generate_entrypoint() -> str:
    """Generate the OCI hook entrypoint shell script.

    Uses the current Python interpreter so the hook runs in the
    same environment where terok-shield is installed.
    """
    return f'#!/bin/sh\nexec {shlex.quote(sys.executable)} -m terok_shield.oci_hook "$@"\n'


def _generate_hook_json(entrypoint: str, stage: str) -> str:
    """Generate an OCI hook JSON descriptor for a given stage.

    Args:
        entrypoint: Absolute path to the hook entrypoint script.
        stage: OCI hook stage (``createRuntime`` or ``poststop``).
    """
    hook = {
        "version": "1.0.0",
        "hook": {"path": entrypoint, "args": ["terok-shield-hook", stage]},
        "when": {"annotations": {ANNOTATION_KEY: ".*"}},
        "stages": [stage],
    }
    return json.dumps(hook, indent=2) + "\n"


def install_hooks() -> None:
    """Install OCI hook entrypoint and hook JSON files.

    Installs hooks for the ``createRuntime`` and ``poststop`` stages.
    """
    ensure_shield_dirs()

    ep = shield_hook_entrypoint()
    ep.write_text(_generate_entrypoint())
    ep.chmod(ep.stat().st_mode | stat.S_IEXEC)

    hooks_dir = shield_hooks_dir()
    for stage in ("createRuntime", "poststop"):
        hook_json = _generate_hook_json(str(ep), stage)
        (hooks_dir / f"terok-shield-{stage}.json").write_text(hook_json)


def setup(_config: ShieldConfig) -> None:
    """Install OCI hook JSON and entrypoint script.

    Args:
        _config: Shield configuration (unused, kept for API consistency).
    """
    install_hooks()


def pre_start(
    config: ShieldConfig,
    container: str,
    profiles: list[str],
) -> list[str]:
    """Prepare for container start in hook mode.

    Composes profiles, resolves DNS domains, caches results, and
    returns the podman CLI arguments needed for shield protection.

    Args:
        config: Shield configuration.
        container: Container name (used as DNS cache key).
        profiles: Profile names to compose and resolve.

    Returns:
        Extra arguments for ``podman run``.

    Raises:
        RuntimeError: If the OCI hook is not installed.
        FileNotFoundError: If a named profile does not exist.
    """
    hook_json = shield_hooks_dir() / "terok-shield-createRuntime.json"
    if not hook_json.is_file():
        raise RuntimeError("Shield hook not installed. Run 'terok-shield setup' first.")

    ep = shield_hook_entrypoint()
    if not ep.is_file() or not os.access(ep, os.X_OK):
        raise RuntimeError(
            "Shield hook entrypoint missing or not executable. Run 'terok-shield setup' first."
        )

    entries = compose_profiles(profiles)
    resolve_and_cache(entries, container)

    args: list[str] = []

    if os.geteuid() != 0:
        mode = _detect_rootless_network_mode()
        if mode == "slirp4netns":
            args += [
                "--network",
                "slirp4netns:allow_host_loopback=true",
                "--add-host",
                "host.containers.internal:10.0.2.2",
            ]
        else:
            tcp_flags = ",".join(f"-T,{p}" for p in config.loopback_ports)
            pasta_arg = f"pasta:{tcp_flags}" if tcp_flags else "pasta:"
            args += [
                "--network",
                pasta_arg,
                "--add-host",
                "host.containers.internal:127.0.0.1",
            ]

    args += [
        "--annotation",
        f"{ANNOTATION_KEY}={','.join(profiles)}",
        "--annotation",
        f"{ANNOTATION_NAME_KEY}={container}",
        "--hooks-dir",
        str(shield_hooks_dir()),
        "--cap-drop",
        "NET_ADMIN",
        "--cap-drop",
        "NET_RAW",
        "--security-opt",
        "no-new-privileges",
    ]
    return args


def _set_for_ip(ip: str) -> str:
    """Return the nft set name for an IP address (allow_v4 or allow_v6)."""
    return "allow_v4" if is_ipv4(ip) else "allow_v6"


def allow_ip(container: str, ip: str) -> None:
    """Live-allow an IP for a running container via nsenter.

    Args:
        container: Container name or ID.
        ip: IPv4/IPv6 address or CIDR to allow.
    """
    ip = safe_ip(ip)
    nft_via_nsenter(
        container,
        "add",
        "element",
        "inet",
        "terok_shield",
        _set_for_ip(ip),
        f"{{ {ip} }}",
    )


def deny_ip(container: str, ip: str) -> None:
    """Live-deny an IP for a running container via nsenter.

    Args:
        container: Container name or ID.
        ip: IPv4/IPv6 address or CIDR to deny.
    """
    ip = safe_ip(ip)
    nft_via_nsenter(
        container,
        "delete",
        "element",
        "inet",
        "terok_shield",
        _set_for_ip(ip),
        f"{{ {ip} }}",
    )


def list_rules(container: str) -> str:
    """List current nft rules for a running container.

    Args:
        container: Container name or ID.

    Returns:
        The nft ruleset output, or empty string on failure.
    """
    try:
        return nft_via_nsenter(
            container,
            "list",
            "table",
            "inet",
            "terok_shield",
            check=False,
        )
    except ExecError:
        return ""


def shield_down(config: ShieldConfig, container: str, *, allow_all: bool = False) -> None:
    """Switch a running container to bypass mode (accept-all + log).

    Atomically replaces the nft ruleset with an accept-all ruleset that
    logs every new connection.  RFC1918 reject rules are kept unless
    *allow_all* is True.

    Args:
        config: Shield configuration.
        container: Container name or ID.
        allow_all: If True, also allow RFC1918/link-local traffic.
    """
    ruleset = bypass_ruleset(
        loopback_ports=config.loopback_ports,
        allow_all=allow_all,
    )
    stdin = f"delete table {NFT_TABLE}\n{ruleset}"
    nft_via_nsenter(container, stdin=stdin)
    output = nft_via_nsenter(container, "list", "ruleset")
    errors = verify_bypass_ruleset(output, allow_all=allow_all)
    if errors:
        raise RuntimeError(f"Bypass ruleset verification failed: {'; '.join(errors)}")


def shield_up(config: ShieldConfig, container: str) -> None:
    """Restore normal deny-all mode for a running container.

    Atomically replaces the nft ruleset with the standard hook ruleset,
    then re-adds any cached resolved IPs from the container's ``.resolved``
    file.  The canonical container name is resolved from the shield
    annotation so that the correct cache file is used regardless of
    whether *container* is a name or ID.

    Args:
        config: Shield configuration.
        container: Container name or ID.
    """
    ruleset = hook_ruleset(loopback_ports=config.loopback_ports)
    stdin = f"delete table {NFT_TABLE}\n{ruleset}"
    nft_via_nsenter(container, stdin=stdin)

    name = _resolve_container_name(container)
    resolved_file = shield_resolved_dir() / f"{name}.resolved"
    if resolved_file.is_file():
        ips = [line.strip() for line in resolved_file.read_text().splitlines() if line.strip()]
        elements_cmd = add_elements_dual(ips)
        if elements_cmd:
            nft_via_nsenter(container, stdin=elements_cmd)

    output = nft_via_nsenter(container, "list", "ruleset")
    errors = verify_ruleset(output)
    if errors:
        raise RuntimeError(f"Ruleset verification failed: {'; '.join(errors)}")


def shield_state(container: str) -> ShieldState:
    """Query the live nft ruleset to determine the container's shield state.

    Uses ``list_rules()`` (scoped to the terok_shield table) and the
    ``verify_*`` functions to classify the state from ground truth
    rather than substring probes on the full netns ruleset.

    Args:
        container: Container name or ID.

    Returns:
        The current ShieldState for the container.
    """
    output = list_rules(container)
    if not output.strip():
        return ShieldState.INACTIVE

    if not verify_bypass_ruleset(output, allow_all=False):
        return ShieldState.DOWN
    if not verify_bypass_ruleset(output, allow_all=True):
        return ShieldState.DOWN_ALL

    if not verify_ruleset(output):
        return ShieldState.UP

    return ShieldState.ERROR


def preview(config: ShieldConfig, *, down: bool = False, allow_all: bool = False) -> str:
    """Generate the ruleset that would be applied to a container.

    Returns the nft ruleset text without applying it.  Useful for
    inspecting what a container would get at startup.

    Args:
        config: Shield configuration.
        down: If True, generate the bypass ruleset instead.
        allow_all: If True (with *down*), omit RFC1918 reject rules.
    """
    if down:
        return bypass_ruleset(loopback_ports=config.loopback_ports, allow_all=allow_all)
    return hook_ruleset(loopback_ports=config.loopback_ports)
