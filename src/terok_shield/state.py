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
    ├── policy/                        # v15 tiered +/- policy (one file per tier set)
    │   ├── 10-override                #   → t10_override
    │   ├── 20-security-deny           #   → t20_security_deny
    │   ├── 30-provider-allow          #   → t30_provider_allow
    │   ├── 40-project-allow           #   → t40_project_allow
    │   └── live                       #   runtime overlay (folded into its tiers)
    ├── resolved.ips                   # derived: resolved allow IPs (t40 set seed)
    ├── override_resolved.ips          # derived: resolved t10 override IPs (above-deny seed)
    ├── deny_resolved.ips              # derived: resolved t20 security-deny IPs (deny seed)
    ├── ruleset.nft                    # pre-generated nft ruleset (gateways baked in)
    ├── upstream.dns                   # upstream DNS address
    ├── dns.tier                       # active DNS tier (dnsmasq/lookup/getent)
    ├── network.mode                   # rootless network mode (pasta/slirp4netns)
    ├── loopback.ports                 # per-container host-loopback TCP ports (newline-separated)
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
from .policy import (
    LOCALHOST,
    Action,
    PolicyEntry,
    domain_targets,
    ip_targets,
    localhost_ports,
    parse_policy,
    render_policy,
)


def _dedup(items: list[str]) -> list[str]:
    """Deduplicate preserving first-seen order."""
    return list(dict.fromkeys(items))


def _read_cached_ips(cache: Path) -> list[str]:
    """Non-blank lines of a derived resolution cache; an absent cache is empty."""
    if not cache.is_file():
        return []
    return [line.strip() for line in cache.read_text().splitlines() if line.strip()]


BUNDLE_VERSION = 16
"""Integer version of the state bundle layout.

Bumped whenever the file layout changes in a backwards-incompatible way.
The OCI hook hard-fails if the annotation version does not match —
deliberately no compatibility window and no migration: containers
prepared by a different generation fail fast at restart with a message
naming the remedy (re-create the task; a running container keeps
running untouched, and the task workspace rides its mounts).  The
same constant is the signal ``check_environment()`` uses to detect a
stale on-disk entrypoint — bump it whenever the entrypoint *protocol*
changes even if the file layout itself is unchanged, so that
``terok setup`` rewrites the script instead of short-circuiting.

Current shape (v16): v15 plus two derived seed caches —
``override_resolved.ips`` (t10 break-glass) and ``deny_resolved.ips``
(t20 security-deny).  Both tiers are now statically resolved, so each is
repopulated *by address* on every ``shield down``/``up`` rebuild instead
of depending on the DNS plane to re-learn it.  (v15
replaced the six v14 split allow/deny files with the tiered ``policy/``
bundle of unified ``+``/``-`` files plus the derived ``resolved.ips``
cache.)  Earlier shapes are recoverable via
``git log -L /^BUNDLE_VERSION/:src/terok_shield/state.py``.
"""


# ── v15 tiered policy bundle ────────────────────────────
# The ``policy/<NN>-<name>`` files replace the v14 split allow/deny files
# (``profile.allowed``/``.domains``, ``live.allowed``/``.domains``,
# ``deny.list``, ``denied.domains``).  Each is a unified ``+``/``-`` list
# whose basename mirrors its nft tier set (``t<NN>_<name>``) 1:1.
POLICY_DIR = "policy"
TIER_FILES: dict[str, str] = {
    "override": "10-override",  # t10 — authored break-glass
    "security_deny": "20-security-deny",  # t20 — vault hosts + operator deny
    "provider_allow": "30-provider-allow",  # t30 — executor roster projection
    "project_allow": "40-project-allow",  # t40 — common sets + git remote + custom
}
LIVE_FILE = "live"  # runtime allow/deny, folded into its owning tiers


@dataclass(frozen=True)
class EffectivePolicy:
    """Per-tier policy entries read from the bundle, in authority order.

    ``live`` is the runtime overlay (``shield allow``/``deny``); the engine
    folds its ``+`` entries into the project-allow set and its ``-`` entries
    into the security-deny set.
    """

    override: list[PolicyEntry]
    security_deny: list[PolicyEntry]
    provider_allow: list[PolicyEntry]
    project_allow: list[PolicyEntry]
    live: list[PolicyEntry]

    def all_entries(self) -> list[PolicyEntry]:
        """Every entry across tiers, top-to-bottom in authority order."""
        return [
            *self.override,
            *self.security_deny,
            *self.provider_allow,
            *self.project_allow,
            *self.live,
        ]

    def localhost_ports(self) -> tuple[int, ...]:
        """Host-service ports granted by ``+localhost:PORT`` across every tier."""
        return localhost_ports(self.all_entries())

    def _allows(self) -> list[PolicyEntry]:
        """Admitting (``+``) entries (provider + project + live) a deny tier does not refuse.

        Subtracting the denied targets keeps a ``-domain`` from being resolved
        into ``resolved.ips`` and re-admitted through the t40 set.  (Tier-10
        break-glass overrides are a *separate* nft set, above the deny tier —
        they are not composed here.)
        """
        denied = {e.target for e in self._denies()}
        pool = [*self.provider_allow, *self.project_allow, *self.live]
        return [e for e in pool if e.action == "+" and e.target not in denied]

    def _denies(self) -> list[PolicyEntry]:
        """Every refusing (``-``) entry: security-deny + live's ``-``."""
        return [e for e in (*self.security_deny, *self.live) if e.action == "-"]

    def allow_domains(self) -> list[str]:
        """Domains to admit — fed to dnsmasq's nftset auto-population."""
        return _dedup(domain_targets(self._allows()))

    def deny_domains(self) -> list[str]:
        """Domains to refuse — withheld from dnsmasq's allow set."""
        return _dedup(domain_targets(self._denies()))

    def dnsmasq_domains(self) -> list[str]:
        """Effective dnsmasq nftset list: admitted domains minus denied."""
        denied = set(self.deny_domains())
        return [d for d in self.allow_domains() if d not in denied]

    def deny_ips(self) -> list[str]:
        """Literal denied IPs — the non-resolved part of the tier-20 set seed."""
        return _dedup(ip_targets(self._denies()))

    def deny_targets(self) -> list[str]:
        """Denied domains + literal IPs to resolve (``localhost`` excluded) — the deny-resolver input.

        The t20 security-deny must hold *addresses* to survive a
        ``shield down`` rebuild and to catch direct-IP access that never
        touches the DNS plane, so its domains are statically resolved into
        [`deny_resolved`][terok_shield.state.StateBundle.deny_resolved]
        (mirroring the t10 override treatment)."""
        return _dedup([e.target for e in self._denies() if e.target != LOCALHOST])

    def effective_ips(self) -> list[str]:
        """Admitted literal IPs minus denied (the non-resolved part of the set seed)."""
        denied = set(self.deny_ips())
        return [ip for ip in _dedup(ip_targets(self._allows())) if ip not in denied]

    def allow_targets(self) -> list[str]:
        """Admitted domains + literal IPs to resolve (``localhost`` excluded) — the resolver input."""
        return _dedup([e.target for e in self._allows() if e.target != LOCALHOST])

    def override_targets(self) -> list[str]:
        """Break-glass override domains + literal IPs to resolve (``localhost`` excluded).

        The t10 override is a *separate* above-deny nft set — not part of the
        ordinary allow tiers
        ([`allow_targets`][terok_shield.state.EffectivePolicy.allow_targets]),
        so it is resolved and seeded independently.
        """
        return _dedup(
            [e.target for e in self.override if e.action == "+" and e.target != LOCALHOST]
        )

    def override_domains(self) -> list[str]:
        """Break-glass override domains — the DNS-plane punch-through set.

        A t10 override host is usually *also* denied by t20 (that is the
        point of an override), so the dnsmasq sinkhole generator must treat
        these names as allowed — otherwise the override host would NXDOMAIN
        and the statically seeded t10 set would never see a connection.
        """
        return _dedup(domain_targets([e for e in self.override if e.action == "+"]))


STATE_DIR_MODE = 0o700
"""Permission mode for ``state_dir`` and its subdirectories.

Owner-only.  The OCI hook in ``_oci_state.py`` rejects ``state_dir`` if
``st_mode & 0o022`` (group- or world-writable), because a loose mode
would let any local peer drop a ``ruleset.nft`` for the hook to apply
with ``CAP_NET_ADMIN``.  ``mkdir(mode=…)`` is masked by ``umask``, so
the writer side has to ``chmod`` after creation to guarantee the bit
pattern the validator demands.
"""


#: Tier names retired by a rename, mapped to what they are called now.  The
#: rename was nominal — same enforcement, a name that stopped privileging one
#: of two interchangeable tools — so a record written under the old name still
#: describes the tier accurately.
_LEGACY_TIER_NAMES = {"dig": "lookup"}


@dataclass(frozen=True)
class StateBundle:
    """File-layout contract for a single shielded container's ``state_dir``.

    Frozen so the per-task instance is safe to pass through hook
    callbacks without anyone smuggling a mutated ``state_dir`` into a
    later stage.  Every property is a pure derivation off ``state_dir``;
    the IO methods ([`read_effective`][terok_shield.state.StateBundle.read_effective],
    [`read_effective_ips`][terok_shield.state.StateBundle.read_effective_ips],
    [`read_denied_ips`][terok_shield.state.StateBundle.read_denied_ips],
    [`ensure_dirs`][terok_shield.state.StateBundle.ensure_dirs]) bundle
    the small handful of read-and-compose / setup helpers that previously
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

    def read_dns_tier(self) -> str | None:
        """The DNS tier this container launched with (``dnsmasq``/``proxy``/``lookup``/``getent``).

        Returns the value the OCI hook recorded at ``pre_start`` — the tier
        actually enforcing this task's egress — or ``None`` when the file is
        absent (the container was never shielded, or predates tier
        recording).  A degraded tier (``lookup``/``getent``) means domain
        allowlisting fell back to static resolution with no IP-rotation
        handling; the operator surfaces that alongside the shield posture.

        A container that recorded ``dig`` reads as ``lookup``.  That rename was
        nominal: the tier enforced static pre-start resolution before it and
        after it, and only stopped being named after one of the two
        interchangeable tools that serve it.  Reading it as the tier it names
        is what lets such a container restart instead of being recreated.
        """
        try:
            tier = self.dns_tier.read_text().strip()
        except (OSError, ValueError):  # absent, or non-UTF-8 content
            return None
        tier = _LEGACY_TIER_NAMES.get(tier, tier)
        # Only the tiers the OCI hook records (mirrors config.DnsTier's
        # values, which this layer may not import); a stray or corrupt file
        # reads as None, never an unsupported tier.  A test holds the two
        # lists together — a tier missing from here reads as "never
        # launched", and its container can never restart.
        return tier if tier in {"dnsmasq", "proxy", "lookup", "getent"} else None

    @property
    def network_mode(self) -> Path:
        """Path to the persisted rootless network mode (``pasta``/``slirp4netns``).

        Detected once at ``pre_start`` and read back by ``HookMode.refresh``,
        which derives the ruleset's gateway addresses from it — a restart
        rebuilds the bundle without paying for a ``podman info`` probe, and
        cannot pick a mode the running container was not launched with.
        """
        return self.state_dir / "network.mode"

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

    # ── v15 tiered policy bundle ────────────────────────────

    @property
    def policy_dir(self) -> Path:
        """Directory holding the per-tier ``+``/``-`` policy files."""
        return self.state_dir / POLICY_DIR

    def tier_path(self, tier: str) -> Path:
        """Path to one tier's policy file (``tier`` is a [`TIER_FILES`][terok_shield.state.TIER_FILES] key)."""
        return self.policy_dir / TIER_FILES[tier]

    @property
    def policy_live(self) -> Path:
        """Path to the runtime overlay (``shield allow``/``deny`` append here)."""
        return self.policy_dir / LIVE_FILE

    @property
    def resolved_cache(self) -> Path:
        """Derived per-container cache of resolved allow IPs (the t40 set seed).

        Separate from the authored ``policy/`` tiers so resolution can be
        reused across task starts and invalidated independently — keyed on
        [`policy_mtime`][terok_shield.state.StateBundle.policy_mtime].
        """
        return self.state_dir / "resolved.ips"

    @property
    def override_resolved(self) -> Path:
        """Derived per-container cache of resolved override IPs (the t10 set seed).

        The t10 override sits *above* the security-deny tier and is a separate
        nft set, so it is resolved and cached apart from the allow tiers.
        Statically resolved at pre_start — break-glass entries are rare and
        specific, and dnsmasq interception would populate t40 (below the deny),
        defeating the override.
        """
        return self.state_dir / "override_resolved.ips"

    @property
    def deny_resolved(self) -> Path:
        """Derived per-container cache of resolved security-deny IPs (the t20 set seed).

        Denied domains must reach the packet filter as addresses: the deny
        set is what survives a ``shield down`` (the down posture keeps enforcing it),
        and an address-level deny also catches direct-IP access that never
        consults the DNS plane.  Statically resolved at pre_start on every
        DNS tier, cached apart from the allow-side ``resolved.ips`` so the
        two invalidate independently.
        """
        return self.state_dir / "deny_resolved.ips"

    def policy_mtime(self) -> float:
        """Newest mtime among the policy files (``0.0`` when none exist yet).

        Feeds the resolver's content-aware freshness check: a resolved cache
        older than this means the authored allowlist changed since we resolved.
        """
        mtimes = [
            p.stat().st_mtime
            for p in (*(self.tier_path(t) for t in TIER_FILES), self.policy_live)
            if p.is_file()
        ]
        return max(mtimes, default=0.0)

    def read_tier(self, path: Path) -> list[PolicyEntry]:
        """Parse one policy file; an absent file is an empty tier."""
        return parse_policy(path.read_text()) if path.is_file() else []

    def write_tier(self, tier: str, content: str) -> None:
        """Write a tier file only when *content* differs.

        Skipping no-op writes preserves the file's mtime, which the resolver's
        content-aware freshness keys on — so an unchanged allowlist stays a
        cache hit across task starts instead of forcing a re-resolution.
        """
        path = self.tier_path(tier)
        if not path.is_file() or path.read_text() != content:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)

    def read_effective(self) -> EffectivePolicy:
        """Read and compose every tier into an [`EffectivePolicy`][terok_shield.state.EffectivePolicy]."""
        return EffectivePolicy(
            override=self.read_tier(self.tier_path("override")),
            security_deny=self.read_tier(self.tier_path("security_deny")),
            provider_allow=self.read_tier(self.tier_path("provider_allow")),
            project_allow=self.read_tier(self.tier_path("project_allow")),
            live=self.read_tier(self.policy_live),
        )

    def overlay_set(self, action: Action, target: str) -> None:
        """Upsert ``{action}{target}`` into the runtime overlay (``policy/live``).

        The target is validated through the parser (a malformed domain/IP
        raises).  Any prior entry for *target* is dropped first, so a later
        ``shield allow`` flips an earlier ``deny`` (and vice-versa) rather
        than stacking.
        """
        (entry,) = parse_policy(f"{action}{target}")
        kept = [e for e in self.read_tier(self.policy_live) if e.target != entry.target]
        kept.append(entry)
        self.policy_live.parent.mkdir(parents=True, exist_ok=True)
        self.policy_live.write_text(render_policy(kept))

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
        """Path to the resolv.conf bind-mounted over ``/etc/resolv.conf`` on every DNS tier."""
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

    def read_denied_ips(self) -> set[str]:
        """The tier-20 security-deny set seed: literal denied IPs + resolved denied domains.

        Unions the current literal ``-`` IPs (security-deny tier + runtime
        overlay) with the statically resolved
        [`deny_resolved`][terok_shield.state.StateBundle.deny_resolved]
        cache.  This is what ``shield down``/``up`` repopulate the deny set
        from — a denied *domain* must keep denying by address across every
        rebuild, or the down posture would silently un-deny it.
        """
        return set(self.read_effective().deny_ips()) | set(_read_cached_ips(self.deny_resolved))

    def read_effective_ips(self) -> list[str]:
        """The tier-40 project-allow set seed: resolved allow IPs minus denied.

        Unions the derived [`resolved_cache`][terok_shield.state.StateBundle.resolved_cache]
        (literal allow IPs plus resolved allow-domains, refreshed at pre_start)
        with the policy tiers' current literal allow IPs — so a runtime
        ``shield allow`` of a raw IP survives a ``shield up`` rebuild even
        before the next resolution — then subtracts the denied IPs.
        """
        eff = self.read_effective()
        denied = set(eff.deny_ips())
        seed = [ip for ip in _read_cached_ips(self.resolved_cache) if ip not in denied]
        return _dedup(seed + eff.effective_ips())

    def read_override_ips(self) -> list[str]:
        """The tier-10 override set seed: literal override IPs + resolved override domains.

        Unions the current literal ``+`` override IPs with the statically
        resolved [`override_resolved`][terok_shield.state.StateBundle.override_resolved]
        cache.  Denies are *not* subtracted — the whole point of an override is
        to sit above the security-deny tier.
        """
        eff = self.read_effective()
        literal = ip_targets([e for e in eff.override if e.action == "+"])
        return _dedup(literal + _read_cached_ips(self.override_resolved))

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
        self.policy_dir.mkdir(parents=True, exist_ok=True)
        self.policy_dir.chmod(STATE_DIR_MODE)


def recorded_dns_tier(state_dir: Path) -> str | None:
    """The DNS tier a shielded container launched with, read from *state_dir*.

    Thin public wrapper over
    [`StateBundle.read_dns_tier`][terok_shield.state.StateBundle.read_dns_tier]
    so callers that only want the tier need not know the bundle layout.
    Returns ``dnsmasq``/``lookup``/``getent``, or ``None`` when no tier was
    recorded.
    """
    return StateBundle(state_dir).read_dns_tier()
