# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Per-container state bundle layout contract.

Every shielded container gets an isolated state directory.  This module
is the single source of truth for where files live within it — all
paths are derived from a single ``state_dir`` root through
[`StateBundle`][terok_shield.state.StateBundle].

Bundle layout::

    {state_dir}/
    ├── policy/                        # v15 tiered +/- policy (one file per tier set)
    │   ├── 10-override                #   → t10_override
    │   ├── 20-security-deny           #   → t20_security_deny
    │   ├── 30-provider-allow          #   → t30_provider_allow
    │   ├── 40-project-allow           #   → t40_project_allow
    │   └── live                       #   runtime overlay (folded into its tiers)
    ├── resolved.ips                   # derived: resolved allow IPs (t40 set seed)
    ├── override_resolved.ips          # derived: t10 override names → their resolved IPs
    ├── deny_resolved.ips              # derived: t20 security-tier names → their resolved IPs (deny seed)
    ├── live_deny_resolved.ips         # derived: policy/live denied names → their resolved IPs (deny seed)
    ├── ruleset.nft                    # pre-generated nft ruleset (gateways baked in)
    ├── override.expiry                # derived: expiring t10 addresses + deadlines (the hook times them)
    ├── override.lock                  # serializes live t10 grants and revokes (flock; empty)
    ├── upstream.dns                   # upstream DNS address
    ├── dns.tier                       # active DNS tier
    ├── dnsmasq.command                # symbolic/operator launch choice
    ├── dnsmasq.bin                    # live executable identity for cleanup
    ├── network.mode                   # rootless network mode (pasta/slirp4netns)
    ├── network.gateways               # slirp4netns: the IPv4 and IPv6 gateways the container launched with
    ├── loopback.ports                 # per-container host-loopback TCP ports (newline-separated)
    ├── audit.enabled                  # creation-time audit flag; the NFLOG reader honours it
    ├── dnsmasq.conf                   # generated dnsmasq configuration
    ├── dnsmasq.pid                    # dnsmasq PID (in container netns)
    ├── dnsmasq.log                    # dnsmasq query log (for shield watch)
    ├── resolv.conf                    # bind-mounted over /etc/resolv.conf on every tier
    ├── container.id                   # podman container ID (short, 12-char hex)
    └── audit.jsonl                    # per-container audit log
"""
# WAYPOINT: HookMode (hooks.mode)

from __future__ import annotations

import contextlib
import fcntl
import ipaddress
import os
import tempfile
import time
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from .config import DnsTier, ShieldState
from .nft.constants import CONTAINER_HOST_ALIAS, CONTAINER_HOST_ALIASES, HARD_DENY_RANGES
from .podman_info.network import host_loopback_addresses
from .policy import (
    EXPIRES_MARKER,
    LOCALHOST,
    REASON_MARKER,
    Action,
    PolicyEntry,
    domain_targets,
    entry_deadline,
    ip_targets,
    is_ip,
    localhost_ports,
    marker_value,
    parse_policy,
    render_policy,
)
from .resources._oci_state import (
    DNSMASQ_BIN_FILE_NAME,
    DNSMASQ_COMMAND_FILE_NAME,
    DNSMASQ_CONF_FILE_NAME,
    DNSMASQ_PID_FILE_NAME,
    OVERRIDE_EXPIRY_FILE_NAME,
)
from .validation import SAFE_CONTAINER_ID

SHORT_ID_LEN = 12
"""Length of the short container id — the prefix of podman's full id every surface keys on."""


def _dedup(items: list[str]) -> list[str]:
    """Deduplicate preserving first-seen order."""
    return list(dict.fromkeys(items))


def _read_cached_ips(cache: Path) -> list[str]:
    """Non-blank lines of a derived resolution cache; an absent cache is empty."""
    if not cache.is_file():
        return []
    return [line.strip() for line in cache.read_text().splitlines() if line.strip()]


def _read_resolved_addresses(cache: Path) -> list[str]:
    """Every address a deny cache holds, in either form it may be written in.

    The deny caches are name-keyed — a name, then its addresses, one line
    each ([`read_name_resolution`][terok_shield.state.read_name_resolution]) —
    and the t20 seed wants their addresses alone.  Whatever parses as an
    address counts and a name never does, so a cache in the flat
    one-address-per-line form, as a running container may still hold, keeps
    denying until its next refresh rewrites it.
    """
    if not cache.is_file():
        return []
    return [
        token
        for line in cache.read_text().splitlines()
        for token in line.split()
        if _canonical_ip(token) is not None
    ]


def _bare_name(name: str) -> str:
    """*name* the way the name matchers compare it: lowercase, no trailing dot, no ``*.``."""
    return name.strip().lower().rstrip(".").removeprefix("*.")


def _nft_spelling(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    """*net* the way nft lists it: one host bare, a range with its prefix."""
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


def _canonical_ip(value: str) -> str | None:
    """The canonical text of an IP or CIDR (as nft lists it), or ``None`` for anything else.

    Every spelling of one network reads the same — ``192.0.2.1/32`` is
    ``192.0.2.1`` — so whatever keys on this text never tells two of them apart.
    """
    try:
        return _nft_spelling(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        return None


def _same_target(recorded: str, wanted: str) -> bool:
    """Whether the policy target *recorded* is *wanted*: the same network, or the same name.

    An IP or CIDR is compared by the network it names, so ``192.0.2.1`` is
    ``192.0.2.1/32`` and an IPv6 address matches however it is spelled.  A
    name matches case-insensitively — the policy grammar takes no trailing
    dot on either side, so there is none to forgive.  A ``*.`` wildcard
    stays apart from its apex, because the two name different hosts.
    """
    try:
        recorded_net = ipaddress.ip_network(recorded.strip(), strict=False)
        wanted_net = ipaddress.ip_network(wanted.strip(), strict=False)
    except ValueError:
        return recorded.strip().lower() == wanted.strip().lower()
    return recorded_net == wanted_net


def _deadline(entry: PolicyEntry) -> float | None:
    """Epoch seconds at which *entry*'s ``%expires`` runs out; ``None`` when it never does.

    Raises:
        ValueError: When the marker holds neither a date nor a timestamp.
    """
    deadline = entry_deadline(entry)
    return None if deadline is None else deadline.timestamp()


def _later(first: float | None, second: float | None) -> float | None:
    """The later of two override deadlines — ``None``, an override that never ends, outlasts any."""
    return None if first is None or second is None else max(first, second)


_HARD_DENY_NETS = tuple(ipaddress.ip_network(net) for net in HARD_DENY_RANGES)


def _never_overridden(address: str, host: Iterable[str]) -> str | None:
    """Why no override opens *address* — the host's own loopback or the hard-deny floor — or ``None``.

    Both sit above t10 in the ruleset, so an element for either would open
    nothing; the seed leaves such an address out, and says why.  Only what
    is wholly unreachable counts: a host-loopback address itself, or an
    address or range inside a hard-deny range.  A wider range that merely
    takes one in stays — the rest of it is what its override opens, and the
    ruleset refuses the part above t10 anyway.
    """
    net = ipaddress.ip_network(address, strict=False)
    if any(net == ipaddress.ip_network(loopback) for loopback in host):
        return f"the host's own loopback ({CONTAINER_HOST_ALIAS})"
    for floor in _HARD_DENY_NETS:
        if net.version == floor.version and net.subnet_of(floor):  # type: ignore[arg-type]
            return f"inside the hard-deny floor {floor}"
    return None


def _valid_at(entry: PolicyEntry, now: float) -> bool:
    """Whether *entry* still holds at *now*.  An unreadable expiry never does.

    Authoring refuses such a marker outright; a read of the bundle — a
    rebuild, a status poll — must not fail on one, and must not let an
    expiry nobody can read keep a break-glass open, so it reads as expired.
    """
    try:
        deadline = _deadline(entry)
    except ValueError:
        return False
    return deadline is None or deadline > now


def read_name_resolution(cache: Path) -> dict[str, list[str]] | None:
    """The addresses each name resolved to, from a name-keyed resolution cache.

    One line per name: the name, then its addresses.  ``None`` when the cache
    is absent or written in the flat one-address-per-line form, which keeps
    no names — a caller treats that as nothing resolved, never as addresses
    it could pin to any name.
    """
    if not cache.is_file():
        return None
    mapping: dict[str, list[str]] = {}
    for line in cache.read_text().splitlines():
        if not line.strip():
            continue
        name, *addresses = line.split()
        if not addresses:
            return None
        mapping.setdefault(name, []).extend(addresses)
    return mapping


def render_name_resolution(mapping: dict[str, list[str]]) -> str:
    """The cache text for *mapping* — the inverse of [`read_name_resolution`][terok_shield.state.read_name_resolution].

    A name that resolved to nothing is left out: it has no line to give.
    """
    return "".join(f"{name} {' '.join(ips)}\n" for name, ips in mapping.items() if ips)


def write_name_resolution(cache: Path, mapping: Mapping[str, Sequence[str]]) -> None:
    """Write *mapping* to the name-keyed resolution *cache*, whole or not at all.

    For answers resolved before they may be kept: a live override grant
    resolves its names, swaps the running t10 set, and only once the kernel
    holds the grant and the tier records it does the cache take the
    addresses it was seeded from.  Written after the tier, the cache
    post-dates it, so the next rebuild trusts it for an hour like any fresh
    cache.  A name with no address gets no line.
    """
    _replace_text(cache, render_name_resolution({name: list(ips) for name, ips in mapping.items()}))


def _replace_text(path: Path, text: str) -> None:
    """Write *path* atomically: a temp file beside it, renamed over it.

    A write that fails part-way — a full disk — leaves the file as it was,
    never torn: a reader sees the old text or the new, and the next rebuild
    never seeds a tier from half a line.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def override_entry(target: str, expires: str, *, reason: str) -> PolicyEntry:
    """The t10 entry a live break-glass grant records: ``+target %expires=… %reason=…``.

    Built through the policy grammar, as every tier line is read, so a grant
    fails on a malformed target or expiry before anything changes.  The
    reason rides along as one marker token
    ([`marker_value`][terok_shield.policy.marker_value] keeps free text
    whole), so the tier says why each hole in the deny exists, not only until
    when.

    Raises:
        ValueError: When the line is no policy line the grammar accepts.
    """
    (entry,) = parse_policy(
        f"+{target} %{EXPIRES_MARKER}={expires} %{REASON_MARKER}={marker_value(reason)}"
    )
    return entry


def _upserted(entries: Iterable[PolicyEntry], entry: PolicyEntry) -> list[PolicyEntry]:
    """*entries* with *entry* last, in place of every earlier entry for its target.

    An entry is for the target however it spells it, the way a revoke finds
    one: ``192.0.2.1/32`` gives way to ``192.0.2.1``, and the other way round.
    """
    return [*(kept for kept in entries if not _same_target(kept.target, entry.target)), entry]


def _disjoint(deadlines: dict[str, float | None]) -> list[OverrideSeed]:
    """Seeds no two of which overlap — what an nft interval set accepts in one transaction.

    nft refuses a batch in which one element lies inside another (a CIDR
    override and a name resolving into it), so the wider element is kept and
    the ones it covers are dropped.  A covered element that would have
    outlived its cover lapses with it, until the next rebuild re-derives the
    tier without the expired cover — never the other way round: stretching
    the cover to the inner element's deadline would open the whole range
    past its own expiry.
    """
    networks = sorted(
        (
            (ipaddress.ip_network(address, strict=False), deadline)
            for address, deadline in deadlines.items()
        ),
        key=lambda item: (item[0].version, item[0].prefixlen),
    )
    kept: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, float | None]] = []
    for net, deadline in networks:
        if any(
            net.version == cover.version and net.subnet_of(cover)  # type: ignore[arg-type]
            for cover, _ in kept
        ):
            continue
        kept.append((net, deadline))
    return [OverrideSeed(address=_nft_spelling(net), deadline=deadline) for net, deadline in kept]


BUNDLE_VERSION = 20
"""Integer version of the state bundle layout.

Bumped whenever the file layout changes in a backwards-incompatible way.
The OCI hook hard-fails if the annotation version does not match —
deliberately no compatibility window and no migration: containers
prepared by a different generation fail fast at restart with a message
naming the remedy (re-create the task; a running container keeps
running untouched, and the task workspace rides its mounts).  The
hook and package must agree on this protocol.

Current shape (v20): ``network.gateways`` records the slirp4netns gateways
the container launched with — the host's own loopback, as the container
reaches it.  Every rebuild, replayed ruleset and override check reads them
from there, never from ``containers.conf``, whose ``cidr=`` may have changed
since.  pasta needs no record: its host-loopback address is a constant.

v19: ``audit.enabled`` records the creation-time audit flag,
which the NFLOG reader honours — no audit lines when it is off.  The reader
records the DOWN posture as a harvest source: the DOWN rulesets accept the
allow tiers (t10/t30/t40) logged ``ALLOWED`` ahead of the ``DOWN`` catch-all,
so a ``DOWN`` line means accepted only because the shield is down.  The
runtime overlay's denied names resolve into ``live_deny_resolved.ips``, apart
from the security tier's ``deny_resolved.ips``; both deny caches keep one line
per name, as ``override_resolved.ips`` does, so a name that answers nothing at
a refresh keeps the addresses it had.  The t10 override sets carry
the ``timeout`` flag, and an override's ``%expires`` becomes its elements'
kernel timeout: ``ruleset.nft`` seeds only the overrides that never expire,
``override.expiry`` lists the rest with their deadlines for the hook to time
at apply, and ``override_resolved.ips`` keeps one line per override name so
each address takes the expiry of the name it came from.  A live override's
tier line carries its ``%reason`` beside its ``%expires``.  Under slirp4netns
``ruleset.nft`` refuses the gateway — the host's own loopback — in t00, above
t10, past the ports its preamble opens, and no t10 seed holds a host-loopback
or hard-deny address.

v18: symbolic dnsmasq launch choice is separate from live process identity.
Global hooks are setup-owned, not per-container files.

v17: ``dnsmasq.bin`` records the dnsmasq binary the OCI hook launches.

v16: v15 plus two derived seed caches —
``override_resolved.ips`` (t10 break-glass) and ``deny_resolved.ips``
(t20 security-deny), so both tiers are repopulated *by address* on every
``shield down``/``up`` rebuild; v15 replaced the six v14 split allow/deny
files with the tiered ``policy/`` bundle of unified ``+``/``-`` files plus
the derived ``resolved.ips`` cache.)  Earlier shapes are recoverable via
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

    def security_deny_targets(self) -> list[str]:
        """The security tier's own domains + literal IPs (``localhost`` excluded).

        The t20 set must hold *addresses* to survive a ``shield down``
        rebuild and to catch direct-IP access that never touches the DNS
        plane, so the tier's domains are statically resolved, name by name,
        into [`deny_resolved`][terok_shield.state.StateBundle.deny_resolved]
        (mirroring the t10 override treatment); its literal IPs reach the set
        as they stand.  The runtime overlay's denies
        resolve into a cache of their own
        ([`live_deny_targets`][terok_shield.state.EffectivePolicy.live_deny_targets]):
        tier authority has to tell a vault host's address from one the
        operator denied, and one shared cache could not.
        """
        return _dedup(
            [e.target for e in self.security_deny if e.action == "-" and e.target != LOCALHOST]
        )

    def live_deny_targets(self) -> list[str]:
        """The domains the runtime overlay denies — resolved into the overlay's own deny cache.

        Only names: a literal ``-`` IP in ``policy/live`` reaches the t20 set
        as it stands.  Their addresses land in
        [`live_deny_resolved`][terok_shield.state.StateBundle.live_deny_resolved],
        apart from the security tier's, so a later live allow can lift the
        operator's own deny without ever lifting the security tier.
        """
        return _dedup(domain_targets([e for e in self.live if e.action == "-"]))

    def effective_ips(self) -> list[str]:
        """Admitted literal IPs minus denied (the non-resolved part of the set seed)."""
        denied = set(self.deny_ips())
        return [ip for ip in _dedup(ip_targets(self._allows())) if ip not in denied]

    def allow_targets(self) -> list[str]:
        """Admitted domains + literal IPs to resolve (``localhost`` excluded) — the resolver input."""
        return _dedup([e.target for e in self._allows() if e.target != LOCALHOST])

    def active_override(self, now: float | None = None) -> list[PolicyEntry]:
        """The t10 ``+`` entries still valid at *now* (epoch seconds; default: the current time).

        An entry's ``%expires`` marker ends it — a date at the end of that day,
        host local time; an entry without one never expires.  Every consumer
        of the override tier reads it through here, so an override that ran
        out is no longer resolved or seeded, and is left out of every dnsmasq
        config written after it ran out — even before the next authoring
        rewrites the tier.  A dnsmasq already running keeps the config it
        loaded, though: the kernel drops the t10 element on time, while the
        name stays punched through the sinkhole until the next ``shield
        up``/``down`` reconciles the config, or a restart rewrites it.
        """
        moment = time.time() if now is None else now
        return [e for e in self.override if e.action == "+" and _valid_at(e, moment)]

    def with_override(self, entry: PolicyEntry) -> EffectivePolicy:
        """This policy with *entry* in its t10 tier, in place of any earlier entry for its target.

        An earlier entry is for its target however it spells it — the same
        network, or the same name in any case — so a grant never leaves its
        host twice in the tier under two deadlines.  The tier as a live grant
        leaves it, held in memory: the grant resolves and seeds the t10 set
        from it, and only once the kernel has taken that does the tier record
        the entry
        ([`upsert_override`][terok_shield.state.StateBundle.upsert_override],
        which replaces an entry the same way).  Every other tier is this
        policy's own.
        """
        return replace(self, override=_upserted(self.override, entry))

    def override_targets(self, now: float | None = None) -> list[str]:
        """Break-glass override domains + literal IPs to resolve (``localhost`` excluded).

        The t10 override is a *separate* above-deny nft set — not part of the
        ordinary allow tiers
        ([`allow_targets`][terok_shield.state.EffectivePolicy.allow_targets]),
        so it is resolved and seeded independently.  Only the overrides still
        valid at *now* count ([`active_override`][terok_shield.state.EffectivePolicy.active_override]).
        """
        return _dedup([e.target for e in self.active_override(now) if e.target != LOCALHOST])

    def wildcard_domains(self) -> list[str]:
        """Admitted ``*.`` entries; only a tier that resolves live can enforce them."""
        return [d for d in self.allow_domains() if d.startswith("*.")]

    def override_domains(self, now: float | None = None) -> list[str]:
        """Break-glass override domains — the DNS-plane punch-through set.

        A t10 override host is usually *also* denied by t20 (that is the
        point of an override), so the dnsmasq sinkhole generator must treat
        these names as allowed — otherwise the override host would NXDOMAIN
        and the statically seeded t10 set would never see a connection.
        Only the overrides still valid at *now* punch through.
        """
        return _dedup(domain_targets(self.active_override(now)))

    def rotation_risk(self, tier: DnsTier, now: float | None = None) -> RotationRisk | None:
        """The names *tier* pins to resolved addresses, by kind; ``None`` when there are none.

        Allowlisted names count on every tier but ``dnsmasq-live``; denied
        names on the tiers without dnsmasq, where nothing sinkholes them —
        less any name a still-valid override opens, which the override line
        speaks for; override names on every tier.
        """
        override = tuple(n for n in self.override_domains(now) if _rotation_prone(n))
        overridden = {_bare_name(n) for n in override}
        allow = () if tier.live else tuple(n for n in self.allow_domains() if _rotation_prone(n))
        deny = (
            ()
            if tier.runs_dnsmasq
            else tuple(
                n
                for n in self.deny_domains()
                if _rotation_prone(n) and _bare_name(n) not in overridden
            )
        )
        if not (allow or deny or override):
            return None
        return RotationRisk(tier=tier, allow=allow, deny=deny, override=override)


@dataclass(frozen=True, slots=True)
class OverrideSeed:
    """One element of the t10 override set: an address, and when its override runs out.

    Attributes:
        address: An IP or CIDR, in nft's canonical text.
        deadline: Epoch seconds at which the override ends — the kernel drops
            the element then — or ``None`` for an override that never expires.
    """

    address: str
    deadline: float | None = None


# ── Rotation risk: names a DNS tier pins to launch-time addresses ──

STABLE_LOCAL_NAMES = frozenset({LOCALHOST, *CONTAINER_HOST_ALIASES})
"""Names that never rotate: the host's own ``localhost`` and the aliases the shield pins to it.

``*.localhost`` names (RFC 6761) count too — they never leave the loopback.
"""

_NAMES_SHOWN = 3
"""How many names a warning line spells out before it just counts the rest."""


def _rotation_prone(name: str) -> bool:
    """Whether *name* resolves to addresses that can rotate — any name but a stable local one."""
    bare = _bare_name(name)
    return bare not in STABLE_LOCAL_NAMES and not bare.endswith(f".{LOCALHOST}")


def _name_list(names: tuple[str, ...]) -> str:
    """The first few *names*, then a count of the rest — a warning line stays one line."""
    shown = ", ".join(names[:_NAMES_SHOWN])
    rest = len(names) - _NAMES_SHOWN
    return f"{shown}, and {rest} more" if rest > 0 else shown


def _grammar(count: int, noun: str) -> tuple[str, str, str]:
    """``(counted noun, pronoun, which one)`` agreeing with *count*: ``1 name`` / ``it`` / ``it``."""
    if count == 1:
        return f"1 {noun}", "it", "it"
    return f"{count} {noun}s", "they", "one of them"


@dataclass(frozen=True)
class RotationRisk:
    """Policy names the container's DNS tier pins to the addresses they resolved to.

    A name the shield resolves itself — once at launch, again at most hourly
    on a posture change — is enforced by those addresses only, and the
    provider behind it can move to another at any time.  What that costs
    depends on the name's tier and on the posture, so the value keeps the
    three kinds apart and words them per posture
    ([`lines`][terok_shield.state.RotationRisk.lines]).

    Computed on read from the bundle — the recorded DNS tier and the
    authored policy ([`recorded_rotation_risk`][terok_shield.state.recorded_rotation_risk])
    — so it never disagrees with what the container runs.  IP and CIDR
    entries cannot rotate and stable local names
    ([`STABLE_LOCAL_NAMES`][terok_shield.state.STABLE_LOCAL_NAMES]) never
    do, so neither is ever listed.

    Attributes:
        tier: The DNS tier the container launched with.
        allow: Allowlisted names (t30, t40, runtime ``+``) on a tier that
            resolves them once — every tier but ``dnsmasq-live``.  While the
            shield is UP, an address they rotate to is refused.
        deny: Denied names (t20, runtime ``-``) on a tier that runs no dnsmasq
            (``lookup``, ``getent``), where nothing sinkholes them: the deny
            holds their resolved addresses only, and an address a vault host
            rotates to escapes it.  A security gap, worded louder.
        override: Break-glass names (t10), resolved once on *every* tier — the
            live tier included, since dnsmasq never populates the override
            set.  An address they rotate to is not reached.
    """

    tier: DnsTier
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    override: tuple[str, ...] = ()

    def lines(self, posture: ShieldState | None = None) -> list[str]:
        """The warning lines that matter in *posture*, worded for it.

        *posture* ``None`` means a launch or restart: the container boots UP
        and may be lowered afterwards, so every line counts and the deny line
        names both ways out.  In UP every line counts; in DOWN only the deny
        line — accept-by-default makes a pinned allow moot, while the security
        tier is still meant to hold; DISENGAGED enforces nothing, so nothing
        is worth a word.
        """
        if posture is ShieldState.DOWN:
            wanted = [self._deny_line(posture)]
        elif posture in (None, ShieldState.UP):
            wanted = [self._allow_line(), self._override_line(), self._deny_line(posture)]
        else:
            wanted = []
        return [line for line in wanted if line]

    def _allow_line(self) -> str:
        """The allow side: false refusals while the shield is UP."""
        if not self.allow:
            return ""
        noun, they, one_of = _grammar(len(self.allow), "allowlisted name")
        return (
            f"DNS tier {self.tier.value} pins {noun} to the addresses {they} resolved to: "
            f"an address {one_of} rotates to is refused until the shield re-resolves it: "
            f"{_name_list(self.allow)}"
        )

    def _override_line(self) -> str:
        """The break-glass side: an override that stops reaching its host."""
        if not self.override:
            return ""
        noun, they, one_of = _grammar(len(self.override), "break-glass override name")
        verb = "is" if len(self.override) == 1 else "are"
        return (
            f"{noun.capitalize()} {verb} pinned to the addresses {they} resolved to — overrides "
            f"never follow DNS, on any tier — so an address {one_of} rotates to is not reached: "
            f"{_name_list(self.override)}"
        )

    def _deny_line(self, posture: ShieldState | None) -> str:
        """The security side: a rotated vault address the deny no longer holds."""
        if not self.deny:
            return ""
        noun, they, one_of = _grammar(len(self.deny), "denied name")
        if posture is ShieldState.DOWN:
            way_out = f"the shield is down, so an address {one_of} rotates to is accepted"
        elif posture is ShieldState.UP:
            way_out = (
                f"an address {one_of} rotates to escapes the deny when an allowlisted name "
                "shares it or a bypass window is open"
            )
        else:
            way_out = (
                f"an address {one_of} rotates to escapes the deny whenever the shield is "
                "down or a bypass window is open"
            )
        return (
            f"Security: DNS tier {self.tier.value} runs no dnsmasq, so nothing sinkholes "
            f"{noun} — the deny holds only the addresses {they} resolved to, and {way_out}: "
            f"{_name_list(self.deny)}"
        )


# ── Tier authority: the t20 security tier ───────────────


class SecurityTierRefusal(RuntimeError):
    """A grant the t20 security tier refuses: only a break-glass override reaches the target.

    The security tier (``policy/20-security-deny``) holds what the
    orchestrator denies direct egress to — the vault-relayed provider hosts,
    above all.  A live allow may lift the operator's own runtime deny, never
    this tier: the one way past it is the t10 override, authored with a
    reason and an expiry and sitting above the deny.  Raised before anything
    changes, so a refused allow leaves the ruleset and the bundle as they were.

    Attributes:
        target: The domain or IP the caller asked to allow.
        entry: The security-tier name, address or range that refuses it.
        address: The address the target shares with the tier, when the
            refusal is by address; empty when the name itself is refused.
    """

    def __init__(self, target: str, *, entry: str, address: str = "") -> None:
        """Record what was refused and by which entry; the message names a shared address."""
        self.target = target
        self.entry = entry
        self.address = address
        super().__init__(f"{self.cause} — break-glass only")

    @property
    def cause(self) -> str:
        """One clause saying why the security tier refuses the target."""
        if not self.address:
            if _bare_name(self.target) == _bare_name(self.entry):
                return f"{self.target} is a security-tier host"
            return f"{self.target} is under the security-tier domain {self.entry}"
        if _canonical_ip(self.target) == self.address:
            if self.entry == self.address:
                return f"{self.target} is a security-tier address"
            return f"{self.target} overlaps the security-tier entry {self.entry}"
        if self.entry == self.address:
            return f"{self.target} shares the address {self.address} with the security tier"
        return (
            f"{self.target} resolves to {self.address}, inside the security-tier range {self.entry}"
        )


@dataclass(frozen=True)
class SecurityTier:
    """The t20 security tier as one matcher — by name, by suffix, by address.

    Read from a bundle by
    [`StateBundle.read_security_tier`][terok_shield.state.StateBundle.read_security_tier].
    The runtime overlay's ``-`` entries are left out on purpose: those are the
    operator's own denies, which a live allow may lift.  Nothing a live allow
    does may lift *this* tier, so it is what a grant is checked against.

    Attributes:
        names: The tier's domains as authored.  A name refuses itself and
            every name under it — the reach of its dnsmasq sinkhole — and a
            ``*.`` entry refuses its apex as well.
        addresses: The tier's literal IPs and CIDRs plus the addresses its
            names resolved to.  Overlap is enough to refuse: a range target
            that would take in one security address is as refused as the
            address itself.
    """

    names: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()

    def refusal(self, target: str, addresses: Iterable[str] = ()) -> SecurityTierRefusal | None:
        """Why the tier refuses *target*, or any of the *addresses* it resolved to; else ``None``.

        The name goes first, so a security host is refused as itself even when
        it resolved to nothing just now.  The addresses follow — an IP or CIDR
        target's own, then the resolved ones — so a name that merely *shares*
        an address with the tier, a CDN front say, is refused naming that
        address: allowing it would hand the agent the vault host's door too.
        """
        candidates = list(addresses)
        if is_ip(target):
            candidates.insert(0, target)
        elif (name := self.name_refusing(target)) is not None:
            return SecurityTierRefusal(target, entry=name)
        for candidate in candidates:
            if (entry := self.address_refusing(candidate)) is not None:
                address = _canonical_ip(candidate) or candidate
                return SecurityTierRefusal(target, entry=entry, address=address)
        return None

    def name_refusing(self, name: str) -> str | None:
        """The tier's name that refuses *name* — that very name, or a domain above it."""
        wanted = _bare_name(name)
        for entry in self.names:
            base = _bare_name(entry)
            if wanted == base or wanted.endswith(f".{base}"):
                return entry
        return None

    def address_refusing(self, address: str) -> str | None:
        """The tier's address or range that *address* overlaps (canonical text), else ``None``.

        The narrowest overlapping entry wins: an exact security address says
        more than the range around it.
        """
        try:
            wanted = ipaddress.ip_network(address.strip(), strict=False)
        except ValueError:
            return None
        narrowest: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
        for entry in self.addresses:
            try:
                denied = ipaddress.ip_network(entry.strip(), strict=False)
            except ValueError:
                continue
            if not isinstance(denied, type(wanted)) or not wanted.overlaps(denied):
                continue
            if narrowest is None or denied.prefixlen > narrowest.prefixlen:
                narrowest = denied
        return None if narrowest is None else _nft_spelling(narrowest)


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

    def read_dns_tier(self) -> DnsTier | None:
        """The tier ``pre_start`` recorded for this container, or ``None`` when there is none.

        ``None`` means the container was never shielded, or the file is not a
        tier name; a retired name reads as the tier it named.
        """
        try:
            return DnsTier.parse(self.dns_tier.read_text().strip())
        except (OSError, ValueError):  # absent, or non-UTF-8 content
            return None

    def read_rotation_risk(self) -> RotationRisk | None:
        """The [`RotationRisk`][terok_shield.state.RotationRisk] of this bundle, computed on read.

        ``None`` when the container was never shielded, when its policy
        names nothing a rotation can hurt, and when the bundle cannot be read
        — a warning must never be what breaks a launch or a status poll.
        """
        tier = self.read_dns_tier()
        if tier is None:
            return None
        try:
            return self.read_effective().rotation_risk(tier)
        except (OSError, ValueError):  # unreadable, or a policy line the grammar rejects
            return None

    @property
    def network_mode(self) -> Path:
        """Path to the persisted rootless network mode (``pasta``/``slirp4netns``).

        Detected once at ``pre_start`` and read back by ``HookMode.refresh``,
        which derives the ruleset's gateway addresses from it — a restart
        rebuilds the bundle without paying for a ``podman info`` probe, and
        cannot pick a mode the running container was not launched with.
        """
        return self.state_dir / "network.mode"

    def read_network_mode(self) -> str:
        """The rootless network mode ``pre_start`` recorded, or ``""`` when there is none.

        A read that must never fail a caller: an absent or unreadable file
        reads as no mode, the way [`read_dns_tier`][terok_shield.state.StateBundle.read_dns_tier]
        treats its own.
        """
        try:
            return self.network_mode.read_text().strip()
        except (OSError, ValueError):  # absent, or non-UTF-8 content
            return ""

    @property
    def network_gateways(self) -> Path:
        """Path to the gateways a slirp4netns container launched with: ``"<IPv4> <IPv6>"``.

        Recorded once at ``pre_start``, from the ``containers.conf`` of that
        moment.  A running container keeps the gateway it started with, so
        every later reader takes it from here — see
        [`read_gateways`][terok_shield.state.StateBundle.read_gateways].
        """
        return self.state_dir / "network.gateways"

    def record_gateways(self, gateway_v4: str, gateway_v6: str) -> None:
        """Record the gateways the container launches with; pasta has none to record."""
        if gateway_v4 or gateway_v6:
            self.network_gateways.write_text(f"{gateway_v4} {gateway_v6}\n")
        else:
            self.network_gateways.unlink(missing_ok=True)

    def read_gateways(self) -> tuple[str, str]:
        """The ``(IPv4, IPv6)`` gateways the container launched with — ``("", "")`` but under slirp4netns.

        Only slirp4netns has gateways, so only a slirp4netns bundle reads the
        record.  The ruleset opens the host-service ports at them and
        refuses the rest of the host's loopback there, above t10.

        Raises:
            RuntimeError: A slirp4netns bundle without the record — prepared
                before the record existed.  Guessing the gateway from
                ``containers.conf`` now could open the wrong address, so the
                task must be re-created.
        """
        if self.read_network_mode() != "slirp4netns":
            return "", ""
        try:
            gateway_v4, gateway_v6 = self.network_gateways.read_text().split()
        except (OSError, ValueError) as exc:  # absent, unreadable or malformed
            raise RuntimeError(
                f"{self.state_dir} records no slirp4netns gateways — the bundle predates "
                "them; re-create the task"
            ) from exc
        return gateway_v4, gateway_v6

    def host_loopback(self) -> frozenset[str]:
        """The addresses that reach the host's own loopback from this container.

        What ``host.containers.internal`` names under the recorded network
        mode: pasta's constant map, or the gateways a slirp4netns container
        launched with ([`host_loopback_addresses`][terok_shield.podman_info.network.host_loopback_addresses]).
        """
        mode = self.read_network_mode()
        return host_loopback_addresses(mode, self.read_gateways())

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

    def read_effective_loopback_ports(self) -> tuple[int, ...]:
        """Every host-loopback port the ruleset preamble opens, from both sources.

        The supervisor's ports persisted in ``loopback.ports`` come first, then
        the ``+localhost:PORT`` grants authored across the policy tiers —
        deduplicated, order preserved.  The ruleset builder reads this, not
        the file alone, so a profile's host-service grant reaches the preamble.
        """
        ports = (*self.read_loopback_ports(), *self.read_effective().localhost_ports())
        return tuple(dict.fromkeys(ports))

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
        """Derived per-container cache of the t10 override names' addresses (part of the t10 seed).

        The t10 override sits *above* the security-deny tier and is a separate
        nft set, so it is resolved and cached apart from the allow tiers.
        Statically resolved at pre_start — break-glass entries are rare and
        specific, and dnsmasq interception would populate t40 (below the deny),
        defeating the override.  Keyed by name, one line each
        ([`read_name_resolution`][terok_shield.state.read_name_resolution]):
        every override carries its own expiry, and an address can only be
        timed to the expiry of the override that resolved to it.
        """
        return self.state_dir / "override_resolved.ips"

    @property
    def override_expiry(self) -> Path:
        """Derived: the expiring t10 addresses and their deadlines, for the OCI hook to time.

        Written beside ``ruleset.nft``, which keeps only the overrides that
        never expire.  The hook turns each deadline into the seconds left when
        it applies the ruleset, so a start that replays an old ruleset never
        re-grants an override past its expiry.
        """
        return self.state_dir / OVERRIDE_EXPIRY_FILE_NAME

    @property
    def override_lock(self) -> Path:
        """The lock file [`override_change`][terok_shield.state.StateBundle.override_change] holds.

        Empty; only its ``flock`` matters.  Created on first use.
        """
        return self.state_dir / "override.lock"

    @contextlib.contextmanager
    def override_change(self) -> Iterator[None]:
        """Hold the t10 lock: one live grant or revoke at a time, across processes.

        A grant and a revoke each read the t10 tier, swap the running t10
        set from it and record the change.  Interleaved, one would swap from
        a tier the other just changed — a revoked address back into the
        kernel, which the tier no longer records, or one grant's element out
        of it.  So each holds this lock from its read of the tier through its
        swap and record.  A grant resolves its names before taking it, so a
        revoke never waits on a resolver.  The lock is an exclusive ``flock``
        on [`override_lock`][terok_shield.state.StateBundle.override_lock],
        released when the block ends, however it ends.

        Raises:
            RuntimeError: When there is no state directory to hold the lock:
                no bundle, so no t10 tier to change.
        """
        try:
            fd = os.open(self.override_lock, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"{self.state_dir} holds no state bundle, so there is no t10 override to change"
            ) from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)  # closing the descriptor drops the lock

    @property
    def deny_resolved(self) -> Path:
        """Derived per-container cache of the security tier's resolved IPs (part of the t20 seed).

        Denied domains must reach the packet filter as addresses: the deny
        set is what survives a ``shield down`` (the down posture keeps enforcing it),
        and an address-level deny also catches direct-IP access that never
        consults the DNS plane.  Statically resolved at pre_start on every
        DNS tier, cached apart from the allow-side ``resolved.ips`` so the
        two invalidate independently — and apart from
        [`live_deny_resolved`][terok_shield.state.StateBundle.live_deny_resolved],
        so these addresses stay attributable to the security tier.

        Keyed by name, one line each
        ([`read_name_resolution`][terok_shield.state.read_name_resolution]): a
        refresh in which one name answers nothing keeps that name's addresses
        while the others take their new ones, so a single timed-out lookup
        never drops a vault host out of the t20 set.
        """
        return self.state_dir / "deny_resolved.ips"

    @property
    def live_deny_resolved(self) -> Path:
        """Derived cache of the addresses the runtime overlay's denied names resolve to.

        The other half of the t20 seed.  Kept apart from
        [`deny_resolved`][terok_shield.state.StateBundle.deny_resolved] so
        each address keeps its provenance: the security tier's are what tier
        authority checks a live allow against, these stem from the
        operator's own runtime denies, which a live allow may lift.  Keyed by
        name like its sibling, with the same rule: a name that answers nothing
        at a refresh keeps the addresses it had.
        """
        return self.state_dir / "live_deny_resolved.ips"

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
        """Write a tier file only when *content* differs, and atomically.

        Skipping no-op writes preserves the file's mtime, which the resolver's
        content-aware freshness keys on — so an unchanged allowlist stays a
        cache hit across task starts instead of forcing a re-resolution.

        The new text goes to a temp file renamed over the tier, so a write
        that fails — a full disk — leaves the tier as it was.  A live grant
        the tier cannot record can then say what the next rebuild seeds in
        its place: the earlier record, whole, never a torn line.
        """
        path = self.tier_path(tier)
        if not path.is_file() or path.read_text() != content:
            _replace_text(path, content)

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

    def upsert_override(self, target: str, expires: str, *, reason: str) -> None:
        """Record ``+target %expires=… %reason=…`` in the t10 tier, replacing any earlier entry for *target*.

        The live break-glass path's record
        ([`override_entry`][terok_shield.state.override_entry] builds the
        line): the tier is what every rebuild re-seeds the override set from,
        so the grant survives a ``shield down``/``up``.  A grant writes it
        once the kernel holds what it seeded, so the tier never records a
        grant the kernel did not take.  The tier as it stands is read afresh
        for the write, and only *target*'s entries change in it — every one
        [`override_entries`][terok_shield.state.StateBundle.override_entries]
        finds for it, however spelled, gives way; a write that fails leaves it
        as it was ([`write_tier`][terok_shield.state.StateBundle.write_tier]).
        The tier stays the orchestrator's to author, though — the next
        ``refresh`` rewrites it from the orchestrator's own policy.
        """
        entry = override_entry(target, expires, reason=reason)
        tier = self.read_tier(self.tier_path("override"))
        self.write_tier("override", render_policy(_upserted(tier, entry)))

    def override_entries(self, target: str) -> list[PolicyEntry]:
        """Every t10 entry recorded for *target*, in force or not.

        *target* matches the way the shield compares targets: an IP or CIDR by
        the network it names, a name case-insensitively.  The entries may come
        from a live grant
        ([`upsert_override`][terok_shield.state.StateBundle.upsert_override])
        or from the orchestrator's authored ``shield.override``.  The tier
        does not tell the two apart, and a revoke ends either.
        """
        return [
            entry
            for entry in self.read_tier(self.tier_path("override"))
            if _same_target(entry.target, target)
        ]

    def remove_override(self, target: str) -> list[PolicyEntry]:
        """Drop every t10 entry for *target* from the tier; return the entries dropped.

        The revoke path's record, and the counterpart of
        [`upsert_override`][terok_shield.state.StateBundle.upsert_override].
        Every rebuild re-seeds the override set from this tier, so once the
        entry is gone no ``shield down``/``up`` re-opens it.  The tier is
        still the orchestrator's to author: the next ``refresh`` rewrites it
        from the orchestrator's own policy, and an override authored there
        comes back.  Matching follows
        [`override_entries`][terok_shield.state.StateBundle.override_entries].
        When nothing matches, the file is not written.
        """
        entries = self.read_tier(self.tier_path("override"))
        kept = [entry for entry in entries if not _same_target(entry.target, target)]
        if len(kept) < len(entries):
            self.write_tier("override", render_policy(kept))
        return [entry for entry in entries if _same_target(entry.target, target)]

    # ── dnsmasq runtime ────────────────────────────────────

    @property
    def dnsmasq_conf(self) -> Path:
        """Path to the generated dnsmasq configuration file."""
        return self.state_dir / DNSMASQ_CONF_FILE_NAME

    @property
    def dnsmasq_pid(self) -> Path:
        """Path to the dnsmasq PID file (PID is in the container netns)."""
        return self.state_dir / DNSMASQ_PID_FILE_NAME

    @property
    def dnsmasq_command(self) -> Path:
        """Path to the symbolic or explicitly configured dnsmasq launch choice."""
        return self.state_dir / DNSMASQ_COMMAND_FILE_NAME

    @property
    def dnsmasq_bin(self) -> Path:
        """Path to the live dnsmasq executable identity, never a launch choice."""
        return self.state_dir / DNSMASQ_BIN_FILE_NAME

    @property
    def dnsmasq_log(self) -> Path:
        """Path to the dnsmasq query log (consumed by ``shield watch``)."""
        return self.state_dir / "dnsmasq.log"

    @property
    def resolv_conf(self) -> Path:
        """Path to the resolv.conf bind-mounted over ``/etc/resolv.conf`` on every tier."""
        return self.state_dir / "resolv.conf"

    # ── Container identity and observability ────────────────

    @property
    def container_id(self) -> Path:
        """Path to the persisted podman container ID file."""
        return self.state_dir / "container.id"

    def read_container_id(self) -> str | None:
        """The short container id the OCI hook recorded, or ``None`` when there is none.

        The hook writes it at ``createRuntime``, cut from the OCI state's full
        id.  ``None`` means the container has not started under the hook yet,
        or the file holds something that is not a podman id.
        """
        try:
            recorded = self.container_id.read_text().strip()
        except (OSError, ValueError):  # absent, or non-UTF-8 content
            return None
        if not SAFE_CONTAINER_ID.fullmatch(recorded):
            return None
        return recorded[:SHORT_ID_LEN].lower()

    @property
    def reader_pid(self) -> Path:
        """Path where the bridge hook tracks the live NFLOG reader PID."""
        return self.state_dir / "reader.pid"

    @property
    def audit(self) -> Path:
        """Path to the per-container audit log."""
        return self.state_dir / "audit.jsonl"

    @property
    def audit_flag(self) -> Path:
        """Path to the creation-time audit flag (``true`` / ``false``).

        Written once, at ``pre_start``, from the config the container was
        created with — the same value its ``audit_enabled`` annotation
        carries.  The NFLOG reader runs inside the container's netns and
        reads no config, so this file is how it learns the operator's
        choice; a harvest reads it back to tell "audit was off" apart from
        "nothing to harvest".
        """
        return self.state_dir / "audit.enabled"

    def read_audit_enabled(self) -> bool:
        """Whether audit was on when this container was created.

        Only an explicit ``false`` says off.  An absent or unreadable flag
        reads as on: the shield's default, and how a bundle that never
        recorded the flag behaved.
        """
        try:
            return self.audit_flag.read_text().strip() != "false"
        except (OSError, ValueError):  # absent, or non-UTF-8 content
            return True

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
        overlay) with both statically resolved caches —
        [`deny_resolved`][terok_shield.state.StateBundle.deny_resolved] and
        [`live_deny_resolved`][terok_shield.state.StateBundle.live_deny_resolved].
        This is what ``shield down``/``up`` repopulate the deny set from — a
        denied *domain* must keep denying by address across every rebuild, or
        the down posture would silently un-deny it.
        """
        return (
            set(self.read_effective().deny_ips())
            | set(_read_resolved_addresses(self.deny_resolved))
            | set(_read_resolved_addresses(self.live_deny_resolved))
        )

    def read_live_denied_ips(self) -> set[str]:
        """The operator's own runtime denies, by address — the part of t20 a live allow may lift.

        The literal ``-`` IPs and CIDRs of ``policy/live`` plus the addresses
        its denied names resolved to.  The security tier's addresses are not
        among them, and nothing a live allow does takes them out of the set.
        """
        denies = [e for e in self.read_tier(self.policy_live) if e.action == "-"]
        return set(ip_targets(denies)) | set(_read_resolved_addresses(self.live_deny_resolved))

    def read_security_tier(self, extra_addresses: Iterable[str] = ()) -> SecurityTier:
        """The t20 security tier this bundle records, as a [`SecurityTier`][terok_shield.state.SecurityTier] matcher.

        Names and literal addresses come from ``policy/20-security-deny``; the
        resolved addresses from
        [`deny_resolved`][terok_shield.state.StateBundle.deny_resolved], plus
        *extra_addresses* — a fresher resolution of the same names, for a
        caller on a tier where a vault host's address can rotate past the
        launch-time cache.  The runtime overlay stays out: its denies are the
        operator's to lift.
        """
        denies = [e for e in self.read_tier(self.tier_path("security_deny")) if e.action == "-"]
        addresses = [
            *ip_targets(denies),
            *_read_resolved_addresses(self.deny_resolved),
            *extra_addresses,
        ]
        return SecurityTier(
            names=tuple(_dedup(domain_targets(denies))),
            addresses=tuple(_dedup(addresses)),
        )

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

    def read_override_ips(self, now: float | None = None) -> list[str]:
        """The tier-10 override set seed's addresses at *now* — see [`read_override_seeds`][terok_shield.state.StateBundle.read_override_seeds]."""
        return [seed.address for seed in self.read_override_seeds(now)]

    def read_override_seeds(
        self,
        now: float | None = None,
        *,
        policy: EffectivePolicy | None = None,
        resolution: Mapping[str, Sequence[str]] | None = None,
    ) -> list[OverrideSeed]:
        """The tier-10 override set seed at *now*: every address a still-valid override may open.

        Literal ``+`` override IPs come from the tier itself, the addresses of
        override names from the name-keyed
        [`override_resolved`][terok_shield.state.StateBundle.override_resolved]
        cache.  Each address carries the deadline of the override that named
        it — the latest one when several did, however each spelled it, none
        at all when any of them never expires.  Overrides that already ran
        out are left out
        ([`active_override`][terok_shield.state.EffectivePolicy.active_override]),
        and so are addresses another seed covers, which an interval set would
        refuse.  Denies are *not* subtracted — the whole point of an override
        is to sit above the security-deny tier.

        What no override may open is left out too, whichever path refreshed
        the cache: the host's own loopback under the recorded network mode,
        and the hard-deny floor
        ([`read_override_refusals`][terok_shield.state.StateBundle.read_override_refusals]
        says which).  A grant checks its own target's fresh answer, yet it
        re-resolves the other names too, and so do a refresh and a rebuild
        over a stale cache — a name rebound onto the slirp4netns gateway must
        not ride into t10 on any of them.

        *policy* stands in for the policy the bundle records, *resolution*
        for its override cache: a live grant seeds the t10 tier as it will
        leave it ([`with_override`][terok_shield.state.EffectivePolicy.with_override]),
        from the answers it resolved, before the tier or the cache records
        anything.  The network mode is the bundle's either way.
        """
        moment = time.time() if now is None else now
        deadlines: dict[str, float | None] = {}
        for entry, address, barred in self._override_addresses(moment, policy, resolution):
            if barred is None:
                deadline = _deadline(entry)
                deadlines[address] = (
                    _later(deadlines[address], deadline) if address in deadlines else deadline
                )
        return _disjoint(deadlines)

    def read_override_refusals(self, now: float | None = None) -> list[str]:
        """One line for each address a still-valid override names that no override may open.

        The other half of
        [`read_override_seeds`][terok_shield.state.StateBundle.read_override_seeds]:
        the host's own loopback and the hard-deny floor sit above t10, so the
        seed leaves them out, and these lines say so.  A name rebound onto one
        of them is worth an operator's attention — that is what a DNS
        rebinding of a break-glass name looks like.
        """
        moment = time.time() if now is None else now
        return [
            f"t10 override {entry.target} reaches {address}, {barred}: no override opens it, "
            "so the t10 set leaves it out"
            for entry, address, barred in self._override_addresses(moment)
            if barred is not None
        ]

    def _override_addresses(
        self,
        now: float,
        policy: EffectivePolicy | None = None,
        resolution: Mapping[str, Sequence[str]] | None = None,
    ) -> Iterator[tuple[PolicyEntry, str, str | None]]:
        """Each still-valid override with every address it names, and why none may open it.

        A literal IP or CIDR names itself, a name the addresses *resolution*
        holds for it — the override cache's, when it is ``None``; a
        ``+localhost:PORT`` grant names none.  The third item is ``None`` for
        an address an override may open.  The overrides are *policy*'s, the
        recorded policy's when it is ``None``.
        """
        if resolution is None:
            resolution = read_name_resolution(self.override_resolved) or {}
        host = self.host_loopback()
        effective = self.read_effective() if policy is None else policy
        for entry in effective.active_override(now):
            if entry.target == LOCALHOST:
                continue
            named = [entry.target] if is_ip(entry.target) else resolution.get(entry.target, [])
            for address in filter(None, map(_canonical_ip, named)):
                yield entry, address, _never_overridden(address, host)

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
        self.policy_dir.mkdir(parents=True, exist_ok=True)
        self.policy_dir.chmod(STATE_DIR_MODE)


def recorded_dns_tier(state_dir: Path) -> DnsTier | None:
    """The DNS tier a shielded container launched with, read from *state_dir*.

    Thin public wrapper over
    [`StateBundle.read_dns_tier`][terok_shield.state.StateBundle.read_dns_tier]
    so callers that only want the tier need not know the bundle layout.
    """
    return StateBundle(state_dir).read_dns_tier()


def recorded_container_id(state_dir: Path) -> str | None:
    """The short id of the container shielded from *state_dir*, as its OCI hook recorded it.

    The 12-character short id is the one key every per-container surface
    shares: the NFLOG reader stamps it on each event, and the clearance hub
    keys its socket and its mute by it.  A caller that holds only the state
    dir — a task's orchestrator — names the container exactly as those
    surfaces do, instead of by a podman name they have never seen.  Thin
    public wrapper over
    [`StateBundle.read_container_id`][terok_shield.state.StateBundle.read_container_id],
    like [`recorded_dns_tier`][terok_shield.state.recorded_dns_tier];
    ``None`` until the container's first start.
    """
    return StateBundle(state_dir).read_container_id()


def recorded_rotation_risk(state_dir: Path) -> RotationRisk | None:
    """What the DNS tier of the container shielded from *state_dir* pins to resolved addresses.

    A file read — the recorded tier and the authored policy — computed on
    read, so an orchestrator shows the same warning the shield logs without
    a ``Shield`` or a container to ask: at launch, in a task pane, after a
    posture change.  Thin public wrapper over
    [`StateBundle.read_rotation_risk`][terok_shield.state.StateBundle.read_rotation_risk],
    like [`recorded_dns_tier`][terok_shield.state.recorded_dns_tier]; ``None``
    when nothing is at risk or nothing was recorded.
    """
    return StateBundle(state_dir).read_rotation_risk()
