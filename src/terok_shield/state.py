# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Per-container state bundle layout contract.

Defines the canonical directory structure for a container's state
bundle and provides pure path-derivation functions.  Zero dependencies
beyond ``pathlib`` — this module is the single source of truth for
where files live within a state directory.

Bundle layout::

    {state_dir}/
    ├── hooks/
    │   ├── terok-shield-createRuntime.json
    │   └── terok-shield-poststop.json
    ├── terok-shield-hook              # entrypoint script
    ├── profile.allowed                # IPs from DNS resolution
    ├── profile.domains                # domain names for dnsmasq config
    ├── live.allowed                   # IPs from allow/deny
    ├── deny.list                      # persistent deny overrides
    ├── dnsmasq.conf                   # generated dnsmasq configuration
    ├── dnsmasq.pid                    # dnsmasq PID (in container netns)
    └── audit.jsonl                    # per-container audit log
"""

from pathlib import Path

BUNDLE_VERSION = 2
"""Integer version of the state bundle layout.

Bumped whenever the file layout changes in a backwards-incompatible way.
The OCI hook hard-fails if the annotation version does not match.
"""


def hooks_dir(state_dir: Path) -> Path:
    """Return the OCI hooks directory within the state bundle."""
    return state_dir / "hooks"


def hook_entrypoint(state_dir: Path) -> Path:
    """Return the path to the hook entrypoint script."""
    return state_dir / "terok-shield-hook"


def hook_json_path(state_dir: Path, stage: str) -> Path:
    """Return the path to a hook JSON file for a given OCI stage."""
    return hooks_dir(state_dir) / f"terok-shield-{stage}.json"


def profile_allowed_path(state_dir: Path) -> Path:
    """Return the path to the profile-derived allowlist file."""
    return state_dir / "profile.allowed"


def live_allowed_path(state_dir: Path) -> Path:
    """Return the path to the live allow/deny allowlist file."""
    return state_dir / "live.allowed"


def deny_path(state_dir: Path) -> Path:
    """Return the path to the persistent denylist file."""
    return state_dir / "deny.list"


def audit_path(state_dir: Path) -> Path:
    """Return the path to the per-container audit log."""
    return state_dir / "audit.jsonl"


def profile_domains_path(state_dir: Path) -> Path:
    """Return the path to the profile domain names list (for dnsmasq config)."""
    return state_dir / "profile.domains"


def dnsmasq_conf_path(state_dir: Path) -> Path:
    """Return the path to the generated dnsmasq configuration file."""
    return state_dir / "dnsmasq.conf"


def dnsmasq_pid_path(state_dir: Path) -> Path:
    """Return the path to the dnsmasq PID file."""
    return state_dir / "dnsmasq.pid"


def read_allowed_ips(state_dir: Path) -> list[str]:
    """Read IPs from both profile.allowed and live.allowed, merged and deduplicated.

    Returns a stable-order list: profile IPs first, then live IPs, with
    duplicates removed (first occurrence wins).
    """
    ips: list[str] = []
    for path in (profile_allowed_path(state_dir), live_allowed_path(state_dir)):
        if path.is_file():
            ips.extend(line.strip() for line in path.read_text().splitlines() if line.strip())
    seen: set[str] = set()
    unique: list[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique


def read_denied_ips(state_dir: Path) -> set[str]:
    """Read IPs from deny.list.

    Returns an empty set if the file does not exist.
    """
    path = deny_path(state_dir)
    if not path.is_file():
        return set()
    return {line.strip() for line in path.read_text().splitlines() if line.strip()}


def read_effective_ips(state_dir: Path) -> list[str]:
    """Compute effective allowed IPs: (profile ∪ live) - deny.

    Returns a stable-order list with denied IPs subtracted.
    """
    allowed = read_allowed_ips(state_dir)
    denied = read_denied_ips(state_dir)
    return [ip for ip in allowed if ip not in denied]


def ensure_state_dirs(state_dir: Path) -> None:
    """Create the state directory and its required subdirectories."""
    state_dir.mkdir(parents=True, exist_ok=True)
    hooks_dir(state_dir).mkdir(parents=True, exist_ok=True)
