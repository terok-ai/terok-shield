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
    ├── terok-shield-hook              # entrypoint script (stdlib-only Python)
    ├── ruleset.nft                    # pre-generated nft ruleset (written by pre_start)
    ├── gateway                        # discovered gateway IP (written by OCI hook)
    ├── profile.allowed                # IPs from DNS resolution
    ├── profile.domains                # domain names for dnsmasq config
    ├── live.allowed                   # IPs from allow/deny
    ├── deny.list                      # persistent deny overrides
    ├── dnsmasq.conf                   # generated dnsmasq configuration
    ├── dnsmasq.pid                    # dnsmasq PID (in container netns)
    ├── dnsmasq.log                    # dnsmasq query log (for shield watch)
    ├── resolv.conf                    # bind-mounted over /etc/resolv.conf (dnsmasq tier)
    ├── interactive                    # interactive tier marker (e.g. "nflog")
    ├── container.id                   # podman container ID (short, 12-char hex)
    └── audit.jsonl                    # per-container audit log
"""

from pathlib import Path

BUNDLE_VERSION = 4
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


def dnsmasq_log_path(state_dir: Path) -> Path:
    """Return the path to the dnsmasq query log (tailed by ``shield watch``)."""
    return state_dir / "dnsmasq.log"


def ruleset_path(state_dir: Path) -> Path:
    """Return the path to the pre-generated nft ruleset file."""
    return state_dir / "ruleset.nft"


def gateway_path(state_dir: Path) -> Path:
    """Return the path to the persisted discovered IPv4 gateway IP."""
    return state_dir / "gateway"


def gateway_v6_path(state_dir: Path) -> Path:
    """Return the path to the persisted discovered IPv6 gateway IP."""
    return state_dir / "gateway_v6"


def upstream_dns_path(state_dir: Path) -> Path:
    """Return the path to the persisted upstream DNS address."""
    return state_dir / "upstream.dns"


def dns_tier_path(state_dir: Path) -> Path:
    """Return the path to the persisted DNS tier value."""
    return state_dir / "dns.tier"


def interactive_path(state_dir: Path) -> Path:
    """Return the path to the interactive tier marker file."""
    return state_dir / "interactive"


def read_interactive_tier(state_dir: Path) -> str | None:
    """Read the interactive tier from the state bundle.

    Returns ``"nflog"`` (or whatever tier string is stored) if the file
    exists and contains a non-empty value, otherwise ``None``.
    """
    path = interactive_path(state_dir)
    if not path.is_file():
        return None
    value = path.read_text().strip()
    return value or None


def live_domains_path(state_dir: Path) -> Path:
    """Return the path to the live domain overrides file (from allow_domain)."""
    return state_dir / "live.domains"


def denied_domains_path(state_dir: Path) -> Path:
    """Return the path to the denied domains file (from deny_domain)."""
    return state_dir / "denied.domains"


def resolv_conf_path(state_dir: Path) -> Path:
    """Return the path to the pre-written ``resolv.conf`` for the dnsmasq tier.

    ``pre_start()`` writes ``nameserver 127.0.0.1`` here and passes
    ``--volume {path}:/etc/resolv.conf:ro`` to podman.  Podman detects the
    user-supplied mount and skips its automatic pasta-generated ``resolv.conf``,
    so the container's DNS is directed to the per-container dnsmasq instance
    at ``127.0.0.1:53``.  The read-only mount prevents the container payload
    from redirecting DNS away from dnsmasq.
    """
    return state_dir / "resolv.conf"


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


def container_id_path(state_dir: Path) -> Path:
    """Return the path to the persisted podman container ID file."""
    return state_dir / "container.id"


def ensure_state_dirs(state_dir: Path) -> None:
    """Create the state directory and its required subdirectories."""
    state_dir.mkdir(parents=True, exist_ok=True)
    hooks_dir(state_dir).mkdir(parents=True, exist_ok=True)
