# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Per-container state bundle layout contract.

Every shielded container gets an isolated state directory.  This module
is the single source of truth for where files live within it — all
paths are derived from a single ``state_dir`` root through
[`StateBundle`][terok_shield.state.StateBundle].  Zero dependencies
beyond ``pathlib``.

Bundle layout::

    {state_dir}/
    ├── hooks/
    │   ├── terok-shield-createRuntime.json
    │   └── terok-shield-poststop.json
    ├── {HOOK_ENTRYPOINT_NAME}         # entrypoint script (stdlib-only Python)
    ├── ruleset.nft                    # pre-generated nft ruleset (gateways baked in)
    ├── upstream.dns                   # upstream DNS address
    ├── dns.tier                       # active DNS tier (dig/getent/dnsmasq)
    ├── loopback.ports                 # per-container host-loopback TCP ports (newline-separated)
    ├── profile.allowed                # IPs from DNS resolution
    ├── profile.domains                # domain names for dnsmasq config
    ├── live.allowed                   # IPs from allow/deny
    ├── live.domains                   # domain overrides from allow_domain
    ├── deny.list                      # persistent deny overrides
    ├── denied.domains                 # denied domains from deny_domain
    ├── dnsmasq.conf                   # generated dnsmasq configuration
    ├── dnsmasq.pid                    # dnsmasq PID (in container netns)
    ├── dnsmasq.log                    # dnsmasq query log (for shield watch)
    ├── resolv.conf                    # bind-mounted over /etc/resolv.conf (dnsmasq tier)
    ├── container.id                   # podman container ID (short, 12-char hex)
    └── audit.jsonl                    # per-container audit log
"""
# WAYPOINT: HookMode (hooks.mode)

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .paths import HOOK_ENTRYPOINT_NAME

BUNDLE_VERSION = 14
"""Integer version of the state bundle layout.

Bumped whenever the file layout changes in a backwards-incompatible way.
The OCI hook hard-fails if the annotation version does not match.  The
same constant is the signal ``check_environment()`` uses to detect a
stale on-disk entrypoint — bump it whenever the entrypoint *protocol*
changes even if the file layout itself is unchanged, so that
``terok setup`` rewrites the script instead of short-circuiting.

Current shape (v14): ``loopback.ports`` carries the per-container
host-loopback TCP ports (the broker / signer ports the supervisor
binds), persisted at pre_start time.  Earlier shapes are recoverable
via ``git log -L /^BUNDLE_VERSION/:src/terok_shield/state.py``.
"""


STATE_DIR_MODE = 0o700
"""Permission mode for ``state_dir`` and its subdirectories.

Owner-only.  The OCI hook in ``_oci_state.py`` rejects ``state_dir`` if
``st_mode & 0o022`` (group- or world-writable), because a loose mode
would let any local peer drop a ``ruleset.nft`` for the hook to apply
with ``CAP_NET_ADMIN``.  ``mkdir(mode=…)`` is masked by ``umask``, so
the writer side has to ``chmod`` after creation to guarantee the bit
pattern the validator demands.
"""


@dataclass(frozen=True)
class StateBundle:
    """File-layout contract for a single shielded container's ``state_dir``.

    Frozen so the per-task instance is safe to pass through hook
    callbacks without anyone smuggling a mutated ``state_dir`` into a
    later stage.  Every property is a pure derivation off ``state_dir``;
    the IO methods ([`read_allowed_ips`][terok_shield.state.StateBundle.read_allowed_ips],
    [`read_denied_ips`][terok_shield.state.StateBundle.read_denied_ips],
    [`read_effective_ips`][terok_shield.state.StateBundle.read_effective_ips],
    [`ensure_dirs`][terok_shield.state.StateBundle.ensure_dirs]) bundle
    the small handful of read-and-merge / setup helpers that previously
    floated as free functions taking ``state_dir`` repeatedly.
    """

    state_dir: Path

    # ── OCI hook paths ──────────────────────────────────────

    @property
    def hooks_dir(self) -> Path:
        """OCI hooks directory within the state bundle."""
        return self.state_dir / "hooks"

    @property
    def hook_entrypoint(self) -> Path:
        """Path to the hook entrypoint script."""
        return self.state_dir / HOOK_ENTRYPOINT_NAME

    def hook_json(self, stage: str) -> Path:
        """Hook JSON file for a given OCI stage (``createRuntime`` / ``poststop``)."""
        return self.hooks_dir / f"terok-shield-{stage}.json"

    @property
    def ruleset(self) -> Path:
        """Path to the pre-generated nft ruleset file."""
        return self.state_dir / "ruleset.nft"

    # ── Network configuration ──────────────────────────────

    @property
    def upstream_dns(self) -> Path:
        """Path to the persisted upstream DNS address."""
        return self.state_dir / "upstream.dns"

    @property
    def dns_tier(self) -> Path:
        """Path to the persisted DNS tier value."""
        return self.state_dir / "dns.tier"

    @property
    def loopback_ports(self) -> Path:
        """Path to the per-container host-loopback TCP ports list.

        Written by ``HookMode.pre_start`` from the caller-supplied
        ``ShieldConfig.loopback_ports`` (the per-container triple of
        gate / token-broker / ssh-signer ports the supervisor binds).
        Read back by ``shield_up`` / ``shield_down`` when they rebuild
        the nft ruleset — so a fresh ``Shield`` constructed without
        the override still emits the correct
        ``tcp dport <p> ip daddr 10.0.2.2 accept`` rules.
        """
        return self.state_dir / "loopback.ports"

    def read_loopback_ports(self) -> tuple[int, ...]:
        """Read persisted loopback ports; empty tuple when the file is absent."""
        if not self.loopback_ports.is_file():
            return ()
        return tuple(
            int(line.strip())
            for line in self.loopback_ports.read_text().splitlines()
            if line.strip()
        )

    # ── Allowlists and denylists ───────────────────────────

    @property
    def profile_allowed(self) -> Path:
        """Path to the profile-derived allowlist file."""
        return self.state_dir / "profile.allowed"

    @property
    def profile_domains(self) -> Path:
        """Path to the profile domain names list (for dnsmasq config)."""
        return self.state_dir / "profile.domains"

    @property
    def live_allowed(self) -> Path:
        """Path to the live allow/deny allowlist file."""
        return self.state_dir / "live.allowed"

    @property
    def live_domains(self) -> Path:
        """Path to the live domain overrides file (from allow_domain)."""
        return self.state_dir / "live.domains"

    @property
    def deny(self) -> Path:
        """Path to the persistent denylist file."""
        return self.state_dir / "deny.list"

    @property
    def denied_domains(self) -> Path:
        """Path to the denied domains list (from deny_domain)."""
        return self.state_dir / "denied.domains"

    # ── dnsmasq runtime ────────────────────────────────────

    @property
    def dnsmasq_conf(self) -> Path:
        """Path to the generated dnsmasq configuration file."""
        return self.state_dir / "dnsmasq.conf"

    @property
    def dnsmasq_pid(self) -> Path:
        """Path to the dnsmasq PID file (PID is in the container netns)."""
        return self.state_dir / "dnsmasq.pid"

    @property
    def dnsmasq_log(self) -> Path:
        """Path to the dnsmasq query log (consumed by ``shield watch``)."""
        return self.state_dir / "dnsmasq.log"

    @property
    def resolv_conf(self) -> Path:
        """Path to the resolv.conf bind-mounted over ``/etc/resolv.conf`` in dnsmasq tier."""
        return self.state_dir / "resolv.conf"

    # ── Container identity and observability ────────────────

    @property
    def container_id(self) -> Path:
        """Path to the persisted podman container ID file."""
        return self.state_dir / "container.id"

    @property
    def reader_pid(self) -> Path:
        """Path where the bridge hook tracks the live NFLOG reader PID."""
        return self.state_dir / "reader.pid"

    @property
    def audit(self) -> Path:
        """Path to the per-container audit log."""
        return self.state_dir / "audit.jsonl"

    @property
    def meta_path(self) -> Path:
        """Persisted-meta-path pointer file under ``state_dir``.

        Mirrors the resource-side ``META_PATH_FILE_NAME`` constant — one
        filename on both sides of the hook boundary so package code that
        reads it (``Shield.up()``/``down()``) and resource code that
        writes it (the bridge ``createRuntime`` hook) can never drift
        on path convention.
        """
        return self.state_dir / "meta_path"

    # ── State readers ──────────────────────────────────────

    def read_allowed_ips(self) -> list[str]:
        """Merge IPs from profile.allowed and live.allowed, deduplicated.

        Returns a stable-order list: profile IPs first, then live IPs,
        with duplicates removed (first occurrence wins).
        """
        ips: list[str] = []
        for path in (self.profile_allowed, self.live_allowed):
            if path.is_file():
                ips.extend(line.strip() for line in path.read_text().splitlines() if line.strip())
        seen: set[str] = set()
        unique: list[str] = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                unique.append(ip)
        return unique

    def read_denied_ips(self) -> set[str]:
        """Read IPs from deny.list (empty set when the file is missing)."""
        if not self.deny.is_file():
            return set()
        return {line.strip() for line in self.deny.read_text().splitlines() if line.strip()}

    def read_effective_ips(self) -> list[str]:
        """Compute effective allowed IPs: ``(profile ∪ live) − deny``.

        Returns a stable-order list with denied IPs subtracted.
        """
        denied = self.read_denied_ips()
        return [ip for ip in self.read_allowed_ips() if ip not in denied]

    # ── Setup ──────────────────────────────────────────────

    def ensure_dirs(self) -> None:
        """Create the state directory and its required subdirectories.

        Both directories are forced to
        [`STATE_DIR_MODE`][terok_shield.state.STATE_DIR_MODE]
        (``0o700``) on every call — the OCI hook rejects anything
        looser, and a prior run under a permissive ``umask`` (Fedora's
        default ``0o002`` is a common offender) would otherwise leave
        the bundle stranded.
        """
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.chmod(STATE_DIR_MODE)
        self.hooks_dir.mkdir(parents=True, exist_ok=True)
        self.hooks_dir.chmod(STATE_DIR_MODE)
