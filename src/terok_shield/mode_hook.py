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
    ShieldConfig,
    ensure_shield_dirs,
    shield_hook_entrypoint,
    shield_hooks_dir,
)
from .dns import resolve_and_cache
from .nft import safe_ip
from .profiles import compose_profiles
from .run import nft_via_nsenter, run as run_cmd


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
    return f"#!/bin/sh\nexec {shlex.quote(sys.executable)} -m terok_shield.oci_hook\n"


def _generate_hook_json(entrypoint: str) -> str:
    """Generate the OCI hook JSON descriptor.

    The hook fires at ``createRuntime`` for containers with the
    ``terok.shield.profiles`` annotation.

    Args:
        entrypoint: Absolute path to the hook entrypoint script.
    """
    hook = {
        "version": "1.0.0",
        "hook": {"path": entrypoint, "args": ["terok-shield-hook"]},
        "when": {"annotations": {ANNOTATION_KEY: ".*"}},
        "stages": ["createRuntime"],
    }
    return json.dumps(hook, indent=2) + "\n"


def setup(_config: ShieldConfig) -> None:
    """Install OCI hook JSON and entrypoint script.

    Args:
        _config: Shield configuration (unused, kept for API consistency).
    """
    ensure_shield_dirs()

    ep = shield_hook_entrypoint()
    ep.write_text(_generate_entrypoint())
    ep.chmod(ep.stat().st_mode | stat.S_IEXEC)

    hook_json = _generate_hook_json(str(ep))
    (shield_hooks_dir() / "terok-shield-hook.json").write_text(hook_json)


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
    hook_json = shield_hooks_dir() / "terok-shield-hook.json"
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
            args += [
                "--network",
                f"pasta:-T,{config.gate_port}",
                "--add-host",
                "host.containers.internal:127.0.0.1",
            ]

    args += [
        "--annotation",
        f"{ANNOTATION_KEY}={','.join(profiles)}",
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


def allow_ip(container: str, ip: str) -> None:
    """Live-allow an IP for a running container via nsenter.

    Args:
        container: Container name or ID.
        ip: IPv4 address or CIDR to allow.
    """
    safe_ip(ip)
    nft_via_nsenter(
        container,
        "add",
        "element",
        "inet",
        "terok_shield",
        "allow_v4",
        f"{{ {ip} }}",
    )


def deny_ip(container: str, ip: str) -> None:
    """Live-deny an IP for a running container via nsenter.

    Args:
        container: Container name or ID.
        ip: IPv4 address or CIDR to deny.
    """
    safe_ip(ip)
    nft_via_nsenter(
        container,
        "delete",
        "element",
        "inet",
        "terok_shield",
        "allow_v4",
        f"{{ {ip} }}",
    )


def list_rules(container: str) -> str:
    """List current nft rules for a running container.

    Args:
        container: Container name or ID.

    Returns:
        The nft ruleset output, or empty string on failure.
    """
    return nft_via_nsenter(
        container,
        "list",
        "table",
        "inet",
        "terok_shield",
        check=False,
    )
