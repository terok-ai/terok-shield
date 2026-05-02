# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Per-container state bundle layout contract.

Every shielded container gets an isolated state directory.  This module
is the single source of truth for where files live within it — all paths
are derived from a single ``state_dir`` root.  Zero dependencies beyond
``pathlib``.

Bundle layout::

    {state_dir}/
    ├── hooks/
    │   ├── terok-shield-createRuntime.json
    │   └── terok-shield-poststop.json
    ├── {HOOK_ENTRYPOINT_NAME}         # entrypoint script (stdlib-only Python)
    ├── ruleset.nft                    # pre-generated nft ruleset (gateways baked in)
    ├── upstream.dns                   # upstream DNS address
    ├── dns.tier                       # active DNS tier (dig/getent/dnsmasq)
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

from pathlib import Path

from .paths import HOOK_ENTRYPOINT_NAME

BUNDLE_VERSION = 12
"""Integer version of the state bundle layout.

Bumped whenever the file layout changes in a backwards-incompatible way.
The OCI hook hard-fails if the annotation version does not match.  The
same constant is the signal ``check_environment()`` uses to detect a
stale on-disk entrypoint — bump it whenever the entrypoint *protocol*
changes even if the file layout itself is unchanged, so that
``terok setup`` rewrites the script instead of short-circuiting.

Version history:
    12 — bridge ``createRuntime`` hook persists the OCI-extracted
        dossier under ``state_dir/dossier.json`` so host-side
        ``Shield.up()`` / ``Shield.down()`` can attach the same
        identity bundle to their hub events that block events already
        carry.  Pre-v12 state bundles work fine on a v12 reader; v12
        bundles need a v12 reader (the JSON file is the only new
        file).
    11 — bridge hook extracts ``dossier.*`` OCI annotations and
        forwards them to the reader as a JSON-encoded
        ``--annotations=…`` argv element; reader resolves a per-emit
        dossier (static annotations merged with optional meta-path
        JSON) and ships it on the wire and in the audit log.  Old
        readers reject the new flag; bumping forces ``terok setup``
        to rewrite the on-disk reader script.
    10 — reader appends ``"action": "blocked"`` entries to
        ``audit.jsonl`` before each wire emit, closing the
        block→verdict timeline gap (verdicts were already audited
        by the host-side ``allow``/``deny`` path; blocks were not).
        Same on-disk layout; new action keyword in an existing file.
    9 — pre_start on dnsmasq tier seeds profile.allowed with resolved
        domains so the initial allow set has permanent entries before
        dnsmasq starts.  Reader swaps lifetime-dedup for a 30 s rolling
        window so dismissed notifications can re-surface.
    8 — reader emits JSON over a unix socket to the host-userns hub
        (``--emit=socket``) instead of ``dbus-send`` from NS_ROOTLESS;
        hook spawn line and reader script both need refreshing.
    7 — bridge hook captures reader stdout+stderr into ``reader.log``
        under the state dir; reader splits into host-userns outer and
        container-netns inner.  File layout adds ``reader.log``.
    6 — hook-argv dispatch protocol: bridge hook adds ``--bridge`` flag
        between ``args[0]`` and the stage; file layout unchanged.
    5 — add the optional bridge hook pair and ``reader.pid`` lifecycle file.
    4 — previous stable shape (nft + dnsmasq only).
"""


# ── OCI hook paths ──────────────────────────────────────


def hooks_dir(state_dir: Path) -> Path:
    """Return the OCI hooks directory within the state bundle."""
    return state_dir / "hooks"


def hook_entrypoint(state_dir: Path) -> Path:
    """Return the path to the hook entrypoint script."""
    return state_dir / HOOK_ENTRYPOINT_NAME


def hook_json_path(state_dir: Path, stage: str) -> Path:
    """Return the path to a hook JSON file for a given OCI stage."""
    return hooks_dir(state_dir) / f"terok-shield-{stage}.json"


def ruleset_path(state_dir: Path) -> Path:
    """Return the path to the pre-generated nft ruleset file."""
    return state_dir / "ruleset.nft"


# ── Network configuration ──────────────────────────────


def upstream_dns_path(state_dir: Path) -> Path:
    """Return the path to the persisted upstream DNS address."""
    return state_dir / "upstream.dns"


def dns_tier_path(state_dir: Path) -> Path:
    """Return the path to the persisted DNS tier value."""
    return state_dir / "dns.tier"


# ── Allowlists and denylists ───────────────────────────


def profile_allowed_path(state_dir: Path) -> Path:
    """Return the path to the profile-derived allowlist file."""
    return state_dir / "profile.allowed"


def profile_domains_path(state_dir: Path) -> Path:
    """Return the path to the profile domain names list (for dnsmasq config)."""
    return state_dir / "profile.domains"


def live_allowed_path(state_dir: Path) -> Path:
    """Return the path to the live allow/deny allowlist file."""
    return state_dir / "live.allowed"


def live_domains_path(state_dir: Path) -> Path:
    """Return the path to the live domain overrides file (from allow_domain)."""
    return state_dir / "live.domains"


def deny_path(state_dir: Path) -> Path:
    """Return the path to the persistent denylist file."""
    return state_dir / "deny.list"


def denied_domains_path(state_dir: Path) -> Path:
    """Return the path to the denied domains file (from deny_domain)."""
    return state_dir / "denied.domains"


# ── Dnsmasq tier ────────────────────────────────────────


def dnsmasq_conf_path(state_dir: Path) -> Path:
    """Return the path to the generated dnsmasq configuration file."""
    return state_dir / "dnsmasq.conf"


def dnsmasq_pid_path(state_dir: Path) -> Path:
    """Return the path to the dnsmasq PID file."""
    return state_dir / "dnsmasq.pid"


def dnsmasq_log_path(state_dir: Path) -> Path:
    """Return the path to the dnsmasq query log (tailed by ``shield watch``)."""
    return state_dir / "dnsmasq.log"


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


# ── Container identity and observability ────────────────


def container_id_path(state_dir: Path) -> Path:
    """Return the path to the persisted podman container ID file."""
    return state_dir / "container.id"


def reader_pid_path(state_dir: Path) -> Path:
    """Return the path where the bridge hook tracks the live NFLOG reader PID."""
    return state_dir / "reader.pid"


def audit_path(state_dir: Path) -> Path:
    """Return the path to the per-container audit log."""
    return state_dir / "audit.jsonl"


def meta_path_file(state_dir: Path) -> Path:
    """Return the persisted-meta-path pointer file under *state_dir*.

    Mirrors the resource-side ``META_PATH_FILE_NAME`` constant — one
    filename on both sides of the hook boundary so package code that
    reads it (``Shield.up()``/``down()``) and resource code that
    writes it (the bridge ``createRuntime`` hook) can never drift on
    path convention.
    """
    return state_dir / "meta_path"


# ── State readers ───────────────────────────────────────
#
# The path functions above are pure derivations.  The functions below
# read file contents and compute derived state (merging, deduplication,
# set subtraction).


def read_allowed_ips(state_dir: Path) -> list[str]:
    """Merge IPs from profile.allowed and live.allowed, deduplicated.

    Returns a stable-order list: profile IPs first, then live IPs,
    with duplicates removed (first occurrence wins).
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
    """Compute effective allowed IPs: (profile ∪ live) − deny.

    Returns a stable-order list with denied IPs subtracted.
    """
    allowed = read_allowed_ips(state_dir)
    denied = read_denied_ips(state_dir)
    return [ip for ip in allowed if ip not in denied]


# ── Setup ───────────────────────────────────────────────


STATE_DIR_MODE = 0o700
"""Permission mode for ``state_dir`` and its subdirectories.

Owner-only.  The OCI hook in ``_oci_state.py`` rejects ``state_dir`` if
``st_mode & 0o022`` (group- or world-writable), because a loose mode
would let any local peer drop a ``ruleset.nft`` for the hook to apply
with ``CAP_NET_ADMIN``.  ``mkdir(mode=…)`` is masked by ``umask``, so
the writer side has to ``chmod`` after creation to guarantee the bit
pattern the validator demands.
"""


def ensure_state_dirs(state_dir: Path) -> None:
    """Create the state directory and its required subdirectories.

    Both directories are forced to ``STATE_DIR_MODE`` (``0o700``) on
    every call — the OCI hook rejects anything looser, and a prior
    run under a permissive ``umask`` (Fedora's default ``0o002`` is
    a common offender) would otherwise leave the bundle stranded.
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    state_dir.chmod(STATE_DIR_MODE)
    hd = hooks_dir(state_dir)
    hd.mkdir(parents=True, exist_ok=True)
    hd.chmod(STATE_DIR_MODE)
