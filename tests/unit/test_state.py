# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for per-container state bundle layout (state.py)."""

import fcntl
import ipaddress
import os
import stat
from collections.abc import Iterator
from datetime import date, timedelta
from pathlib import Path
from unittest import mock
from urllib.parse import unquote

import pytest

from terok_shield.config import DnsTier, ShieldState
from terok_shield.nft.constants import PASTA_HOST_LOOPBACK_MAP
from terok_shield.policy import PolicyEntry, expiry_deadline, parse_policy
from terok_shield.state import (
    BUNDLE_VERSION,
    STATE_DIR_MODE,
    OverrideSeed,
    RotationRisk,
    SecurityTier,
    SecurityTierRefusal,
    StateBundle,
    override_entry,
    read_name_resolution,
    recorded_container_id,
    recorded_dns_tier,
    recorded_rotation_risk,
    render_name_resolution,
    write_name_resolution,
)

from ..testfs import FAKE_STATE_DIR, READER_PID_FILENAME
from ..testnet import (
    AWS_IMDS_V4,
    AWS_IMDS_V6,
    CONTAINER_HOSTNAME,
    DEV_PYPI_DOMAIN,
    DOCKER_HOSTNAME,
    IPV6_CLOUDFLARE,
    IPV6_NET1,
    IPV6_VERBOSE,
    IPV6_VERBOSE_CANONICAL,
    LOCALHOST_GRANT,
    LOCALHOST_GRANT_PORT,
    LOCALHOST_SUBDOMAIN,
    RFC1918_CIDR_10,
    SLIRP4NETNS_GATEWAY,
    SLIRP4NETNS_GATEWAY_V6,
    TEST_DOMAIN,
    TEST_DOMAIN2,
    TEST_IP1,
    TEST_IP2,
    TEST_IP3,
    TEST_IP4,
    TEST_IP99,
    TEST_NET1,
    TEST_NET1_HOST,
    VAULT_HOST,
    VAULT_PARENT_DOMAIN,
    VAULT_SUBDOMAIN,
)

# A podman container id as the OCI state carries it, and the short id the
# hook cuts from it — every per-container surface keys on the latter.
_FULL_CONTAINER_ID = "0123456789abcdef" * 4
_SHORT_CONTAINER_ID = _FULL_CONTAINER_ID[:12]


def test_bundle_version_is_positive_int() -> None:
    """BUNDLE_VERSION is a positive integer."""
    assert isinstance(BUNDLE_VERSION, int)
    assert BUNDLE_VERSION > 0


@pytest.mark.parametrize(
    ("attr", "expected"),
    [
        pytest.param("resolved_cache", FAKE_STATE_DIR / "resolved.ips", id="resolved-cache"),
        pytest.param("audit", FAKE_STATE_DIR / "audit.jsonl", id="audit-path"),
        pytest.param("audit_flag", FAKE_STATE_DIR / "audit.enabled", id="audit-flag"),
        pytest.param("dnsmasq_conf", FAKE_STATE_DIR / "dnsmasq.conf", id="dnsmasq-conf"),
        pytest.param("dnsmasq_pid", FAKE_STATE_DIR / "dnsmasq.pid", id="dnsmasq-pid"),
        pytest.param("dns_tier", FAKE_STATE_DIR / "dns.tier", id="dns-tier"),
        pytest.param("container_id", FAKE_STATE_DIR / "container.id", id="container-id"),
        pytest.param("reader_pid", FAKE_STATE_DIR / READER_PID_FILENAME, id="reader-pid"),
        pytest.param("override_lock", FAKE_STATE_DIR / "override.lock", id="override-lock"),
    ],
)
def test_path_property(attr: str, expected: Path) -> None:
    """Pure path properties derive deterministic paths under the state dir."""
    assert getattr(StateBundle(FAKE_STATE_DIR), attr) == expected


@pytest.mark.parametrize(
    "relative_state_dir",
    [
        pytest.param(Path("container-1"), id="single-level"),
        pytest.param(Path("deep") / "nested" / "state", id="nested"),
    ],
)
def test_ensure_dirs_creates_required_directories(
    tmp_path: Path,
    relative_state_dir: Path,
) -> None:
    """``StateBundle.ensure_dirs()`` creates the state dir and hooks subdirectory."""
    bundle = StateBundle(tmp_path / relative_state_dir)
    bundle.ensure_dirs()

    assert bundle.state_dir.is_dir()


def test_ensure_dirs_is_idempotent(tmp_path: Path) -> None:
    """``StateBundle.ensure_dirs()`` is safe to call repeatedly."""
    bundle = StateBundle(tmp_path / "container-1")
    bundle.ensure_dirs()
    bundle.ensure_dirs()
    assert bundle.state_dir.is_dir()


@pytest.fixture
def loose_umask() -> Iterator[None]:
    """Run the test body under ``umask 0o002`` (Fedora's USERGROUPS_ENAB default)."""
    old = os.umask(0o002)
    try:
        yield
    finally:
        os.umask(old)


def _mode(path: Path) -> int:
    """Return permission bits of *path* (``st_mode & 0o7777``)."""
    return stat.S_IMODE(path.stat().st_mode)


def test_ensure_dirs_forces_owner_only_mode(
    tmp_path: Path,
    loose_umask: None,
) -> None:
    """Fresh dirs land at 0o700 even when the caller's umask would relax them.

    Regression test for the v0.6.35 ``_oci_state`` validator rejecting
    bundles created under ``umask 0o002`` (group-writable).  ``mkdir``
    alone is umask-masked, so ``StateBundle.ensure_dirs()`` must ``chmod``.
    """
    bundle = StateBundle(tmp_path / "container-1")
    bundle.ensure_dirs()

    assert _mode(bundle.state_dir) == STATE_DIR_MODE
    # Validator-side invariant: no group/world write bits.
    assert bundle.state_dir.stat().st_mode & 0o022 == 0


def test_ensure_dirs_repairs_loose_existing_mode(tmp_path: Path) -> None:
    """A pre-existing too-permissive bundle is tightened on next call.

    Users hit by v0.6.35 with a 0o775 dir from a prior 0.6.34 run
    should recover automatically — no manual ``chmod`` required.
    """
    bundle = StateBundle(tmp_path / "container-1")
    bundle.state_dir.mkdir()
    bundle.state_dir.chmod(0o775)

    bundle.ensure_dirs()

    assert _mode(bundle.state_dir) == STATE_DIR_MODE


def test_read_denied_ips_empty_when_no_policy(tmp_path: Path) -> None:
    """``StateBundle.read_denied_ips()`` returns an empty set with no policy."""
    assert StateBundle(tmp_path).read_denied_ips() == set()


def test_read_dns_tier_none_when_unset(tmp_path: Path) -> None:
    """No ``dns.tier`` file → ``None`` (never shielded / predates recording)."""
    assert StateBundle(tmp_path).read_dns_tier() is None
    assert recorded_dns_tier(tmp_path) is None


@pytest.mark.parametrize("tier", list(DnsTier))
def test_read_dns_tier_returns_the_recorded_tier(tmp_path: Path, tier: DnsTier) -> None:
    """The recorded name reads back as its tier, trailing newline stripped."""
    bundle = StateBundle(tmp_path)
    bundle.dns_tier.write_text(f"{tier.value}\n")
    assert bundle.read_dns_tier() is tier
    assert recorded_dns_tier(tmp_path) is tier


def test_read_dns_tier_none_for_unsupported_or_corrupt(tmp_path: Path) -> None:
    """An unsupported string, or non-UTF-8 bytes, read as None — never a bad tier."""
    bundle = StateBundle(tmp_path)
    bundle.dns_tier.write_text("bogus\n")
    assert bundle.read_dns_tier() is None
    bundle.dns_tier.write_bytes(b"\xff\xfe not utf-8")
    assert bundle.read_dns_tier() is None


def test_read_dns_tier_carries_the_retired_names_forward(tmp_path: Path) -> None:
    """A container recorded under a retired name reads as the tier it named.

    That is what lets such a container restart rather than be recreated.
    """
    bundle = StateBundle(tmp_path)
    bundle.dns_tier.write_text("dig\n")
    assert bundle.read_dns_tier() is DnsTier.LOOKUP
    bundle.dns_tier.write_text("dnsmasq\n")
    assert recorded_dns_tier(tmp_path) is DnsTier.DNSMASQ_LIVE


def test_wildcard_domains_are_the_admitted_star_entries(tmp_path: Path) -> None:
    """``*.`` entries an allow tier admits count; one a deny refuses does not."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.write_tier("project_allow", f"+*.{TEST_DOMAIN}\n+{TEST_DOMAIN2}\n")
    assert bundle.read_effective().wildcard_domains() == [f"*.{TEST_DOMAIN}"]
    bundle.overlay_set("-", f"*.{TEST_DOMAIN}")
    assert bundle.read_effective().wildcard_domains() == []


def test_read_denied_ips_composes_security_deny_and_live(tmp_path: Path) -> None:
    """``read_denied_ips()`` folds the security-deny tier and the runtime overlay."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("security_deny").write_text(f"-{TEST_IP1}\n")
    bundle.policy_live.write_text(f"-{TEST_IP2}\n")
    assert bundle.read_denied_ips() == {TEST_IP1, TEST_IP2}


def test_read_effective_ips_unions_cache_and_subtracts_denied(tmp_path: Path) -> None:
    """The seed is the resolved cache minus denied IPs."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.resolved_cache.write_text(f"{TEST_IP1}\n{TEST_IP2}\n")
    bundle.tier_path("security_deny").write_text(f"-{TEST_IP1}\n")
    assert bundle.read_effective_ips() == [TEST_IP2]


def test_read_effective_ips_includes_runtime_allow_before_reresolve(tmp_path: Path) -> None:
    """A runtime ``+ip`` in policy/live survives a rebuild even before re-resolution."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.resolved_cache.write_text(f"{TEST_IP1}\n")
    bundle.policy_live.write_text(f"+{TEST_IP3}\n")  # runtime allow, not yet in the cache
    assert bundle.read_effective_ips() == [TEST_IP1, TEST_IP3]


def test_read_override_ips_unions_literal_and_cache_ignoring_denies(tmp_path: Path) -> None:
    """The t10 seed is literal + resolved override IPs; a deny does NOT subtract it."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    # A literal override, and a name the override cache resolved.
    bundle.tier_path("override").write_text(f"+{TEST_IP1}\n+{TEST_DOMAIN}\n")
    bundle.override_resolved.write_text(f"{TEST_DOMAIN} {TEST_IP2}\n")
    bundle.tier_path("security_deny").write_text(f"-{TEST_IP1}\n")  # deny is below the override
    assert bundle.read_override_ips() == [TEST_IP1, TEST_IP2]


def test_override_targets_lists_plus_entries(tmp_path: Path) -> None:
    """override_targets returns the ``+`` override entries (domains + IPs) to resolve."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("override").write_text(f"+{TEST_DOMAIN}\n+{TEST_IP1}\n")
    assert set(bundle.read_effective().override_targets()) == {TEST_DOMAIN, TEST_IP1}


def test_read_denied_ips_unions_resolved_cache(tmp_path: Path) -> None:
    """The t20 seed unions literal ``-`` IPs with the resolved deny cache.

    A denied *domain* only denies by address once resolved — the cache is
    what keeps the deny enforced across ``shield down``/``up`` rebuilds.
    """
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("security_deny").write_text(f"-{TEST_IP1}\n-{TEST_DOMAIN}\n")
    bundle.deny_resolved.write_text(f"{TEST_IP2}\n")  # resolved deny domain
    assert bundle.read_denied_ips() == {TEST_IP1, TEST_IP2}


def test_the_deny_readers_take_every_address_of_a_name_keyed_cache(tmp_path: Path) -> None:
    """The deny caches keep one line per name; the t20 seed and both matchers want the addresses.

    The flat form a running container may still hold reads too (above):
    whatever parses as an address counts, and a name never does.
    """
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("security_deny").write_text(f"-{VAULT_HOST}\n-{TEST_IP1}\n")
    bundle.policy_live.write_text(f"-{TEST_DOMAIN}\n")
    bundle.deny_resolved.write_text(f"{VAULT_HOST} {TEST_IP2} {IPV6_CLOUDFLARE}\n")
    bundle.live_deny_resolved.write_text(f"{TEST_DOMAIN} {TEST_IP4}\n")

    assert bundle.read_denied_ips() == {TEST_IP1, TEST_IP2, IPV6_CLOUDFLARE, TEST_IP4}
    assert bundle.read_live_denied_ips() == {TEST_IP4}
    assert bundle.read_security_tier().addresses == (TEST_IP1, TEST_IP2, IPV6_CLOUDFLARE)


def test_security_deny_targets_lists_only_the_security_tier(tmp_path: Path) -> None:
    """The security tier's domains and IPs feed its own resolver; the overlay's denies do not."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("security_deny").write_text(f"-{TEST_DOMAIN}\n-{TEST_IP1}\n")
    bundle.policy_live.write_text(f"-{TEST_IP2}\n-{TEST_DOMAIN2}\n")
    assert bundle.read_effective().security_deny_targets() == [TEST_DOMAIN, TEST_IP1]


def test_live_deny_targets_lists_the_overlays_denied_names(tmp_path: Path) -> None:
    """The overlay's denied names resolve on their own; its literal IPs need no resolution."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("security_deny").write_text(f"-{TEST_DOMAIN}\n")
    bundle.policy_live.write_text(f"-{TEST_IP2}\n-{TEST_DOMAIN2}\n+{TEST_IP3}\n")
    assert bundle.read_effective().live_deny_targets() == [TEST_DOMAIN2]


def test_override_domains_lists_only_domains(tmp_path: Path) -> None:
    """override_domains returns the ``+`` override domains (no IPs) — the sinkhole punch-through set."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("override").write_text(f"+{TEST_DOMAIN}\n+{TEST_IP1}\n")
    assert bundle.read_effective().override_domains() == [TEST_DOMAIN]


# ── ballast sync contract ────────────────────────────────────────────────────


def test_oci_state_bundle_version_matches_state() -> None:
    """``_oci_state.BUNDLE_VERSION`` must equal ``state.BUNDLE_VERSION``.

    The stdlib-only ballast can't import state.py, so it duplicates the
    constant.  This test is the enforcement mechanism — both role
    scripts read ``BUNDLE_VERSION`` from the same ballast.
    """
    from terok_shield.resources import _oci_state as _ep

    assert _ep.BUNDLE_VERSION == BUNDLE_VERSION, (
        f"_oci_state.BUNDLE_VERSION={_ep.BUNDLE_VERSION!r} "
        f"!= state.BUNDLE_VERSION={BUNDLE_VERSION!r}. "
        "Update the duplicate in _oci_state.py."
    )


def test_oci_state_override_literals_match_the_nft_constants() -> None:
    """The hook names the t10 sets and caps their timeouts exactly as the ruleset does.

    The ballast is stdlib-only and cannot import ``nft.constants``; a
    drifted table or set name would make every timed override fail to load
    at a container start, and a drifted cap would hand nft a literal it
    refuses.
    """
    from terok_shield.nft import constants
    from terok_shield.resources import _oci_state as _ep

    assert _ep.OVERRIDE_TABLE == constants.NFT_TABLE
    assert _ep.OVERRIDE_SET == constants.TIER_OVERRIDE
    assert _ep.ELEMENT_TIMEOUT_MAX_SECONDS == constants.ELEMENT_TIMEOUT_MAX_SECONDS


def test_nft_hook_path_strings_match_state_attributes() -> None:
    """Path-name literals in ``nft_hook.py`` must match ``StateBundle`` properties.

    The stdlib-only script uses an inline string literal for the ruleset
    filename that ``StateBundle`` derives via a property (the dnsmasq
    filenames both sides import from the ballast).  This test parses the
    script with ``ast`` to collect only *code* string constants (not
    comment text), so a rename in ``state.py`` triggers a failure here
    rather than a silent mismatch at runtime.
    """
    import ast

    from terok_shield.resources import nft_hook as _ep

    source = Path(_ep.__file__).read_text()
    tree = ast.parse(source)

    # Collect the AST nodes that are docstrings (Expr wrapping a Constant string
    # at the start of a module/class/function body) so we can exclude them.
    docstring_nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstring_nodes.add(id(body[0].value))

    literals: set[str] = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstring_nodes
    }
    bundle = StateBundle(Path("x"))

    for attr in ("ruleset",):
        filename = getattr(bundle, attr).name
        assert filename in literals, (
            f"nft_hook.py has no code string literal {filename!r} but "
            f"StateBundle.{attr} returns that filename. "
            "Update nft_hook.py to match."
        )


# ── v15 tiered policy bundle ─────────────────────────────────────────────────


def test_policy_tier_paths_live_under_policy_dir(tmp_path: Path) -> None:
    """Tier files and the runtime overlay resolve under ``policy/``."""
    bundle = StateBundle(tmp_path)
    assert bundle.policy_dir == tmp_path / "policy"
    assert bundle.tier_path("project_allow") == tmp_path / "policy" / "40-project-allow"
    assert bundle.tier_path("security_deny") == tmp_path / "policy" / "20-security-deny"
    assert bundle.policy_live == tmp_path / "policy" / "live"


def test_read_tier_parses_present_and_empties_absent(tmp_path: Path) -> None:
    """``read_tier`` parses a written file and treats an absent one as empty."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("project_allow").write_text(f"+{TEST_DOMAIN}\n+{TEST_IP1}\n")
    entries = bundle.read_tier(bundle.tier_path("project_allow"))
    assert [(e.action, e.target) for e in entries] == [("+", TEST_DOMAIN), ("+", TEST_IP1)]
    assert bundle.read_tier(bundle.tier_path("override")) == []


def test_read_effective_composes_tiers_in_authority_order(tmp_path: Path) -> None:
    """``read_effective`` reads every tier; ``all_entries`` is override→live order."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("security_deny").write_text(f"-{TEST_IP2}\n")
    bundle.tier_path("project_allow").write_text(f"+{TEST_IP1}\n")
    bundle.policy_live.write_text(f"+{TEST_IP3}\n")

    eff = bundle.read_effective()
    assert [e.target for e in eff.security_deny] == [TEST_IP2]
    assert [e.target for e in eff.project_allow] == [TEST_IP1]
    assert [e.target for e in eff.live] == [TEST_IP3]
    # authority order: override, security_deny, provider_allow, project_allow, live
    assert [(e.action, e.target) for e in eff.all_entries()] == [
        ("-", TEST_IP2),
        ("+", TEST_IP1),
        ("+", TEST_IP3),
    ]


def test_effective_policy_localhost_ports_span_every_tier(tmp_path: Path) -> None:
    """``+localhost:PORT`` grants are collected from all tiers via the overlay."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("project_allow").write_text("+localhost:8000\n")
    bundle.policy_live.write_text("+localhost:9090\n")
    assert bundle.read_effective().localhost_ports() == (8000, 9090)


def test_read_effective_loopback_ports_unions_supervisor_ports_with_policy_grants(
    tmp_path: Path,
) -> None:
    """The preamble ports are ``loopback.ports`` plus every ``+localhost:PORT`` grant, deduplicated."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.loopback_ports.write_text("8000\n8001\n")
    bundle.tier_path("project_allow").write_text(f"+{LOCALHOST_GRANT}\n+localhost:8000\n")
    assert bundle.read_effective_loopback_ports() == (8000, 8001, LOCALHOST_GRANT_PORT)


def test_read_effective_loopback_ports_is_empty_without_either_source(tmp_path: Path) -> None:
    """No ``loopback.ports`` file and no policy tiers yield no preamble ports."""
    assert StateBundle(tmp_path).read_effective_loopback_ports() == ()


def test_effective_policy_composes_ips_and_domains_by_action(tmp_path: Path) -> None:
    """Compose folds live into its tiers and splits IPs/domains, allow minus deny."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("project_allow").write_text(f"+{TEST_DOMAIN}\n+{TEST_IP1}\n+{TEST_IP2}\n")
    bundle.tier_path("security_deny").write_text(f"-{TEST_IP2}\n-{TEST_DOMAIN2}\n")
    bundle.policy_live.write_text(f"+{TEST_IP3}\n")

    eff = bundle.read_effective()
    assert eff.effective_ips() == [TEST_IP1, TEST_IP3]  # TEST_IP2 subtracted by the deny
    assert eff.deny_ips() == [TEST_IP2]
    assert eff.allow_domains() == [TEST_DOMAIN]
    assert eff.deny_domains() == [TEST_DOMAIN2]


def test_deny_target_is_withheld_from_allow_views(tmp_path: Path) -> None:
    """A ``-target`` refuses an otherwise-allowed one, so it never reaches the resolver."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("project_allow").write_text(f"+{TEST_DOMAIN}\n+{TEST_IP1}\n")
    bundle.policy_live.write_text(f"-{TEST_DOMAIN}\n")  # deny the allowed domain

    eff = bundle.read_effective()
    assert TEST_DOMAIN not in eff.allow_targets()
    assert TEST_DOMAIN not in eff.allow_domains()
    assert TEST_DOMAIN not in eff.dnsmasq_domains()
    assert TEST_IP1 in eff.allow_targets()  # the untouched allow survives


def test_allow_targets_lists_domains_and_ips_excluding_localhost(tmp_path: Path) -> None:
    """``allow_targets`` is the resolver input: admitted domains + IPs, no localhost."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("project_allow").write_text(f"+{TEST_DOMAIN}\n+{TEST_IP1}\n+localhost:8000\n")
    assert bundle.read_effective().allow_targets() == [TEST_DOMAIN, TEST_IP1]


def test_policy_mtime_is_zero_without_files_and_tracks_writes(tmp_path: Path) -> None:
    """``policy_mtime`` is 0.0 with no policy files and the file mtime once written."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    assert bundle.policy_mtime() == 0.0
    bundle.tier_path("project_allow").write_text(f"+{TEST_DOMAIN}\n")
    assert bundle.policy_mtime() == bundle.tier_path("project_allow").stat().st_mtime


def test_resolved_cache_is_a_derived_top_level_file(tmp_path: Path) -> None:
    """The resolved-IP cache lives outside ``policy/`` (it is derived, not authored)."""
    bundle = StateBundle(tmp_path)
    assert bundle.resolved_cache == tmp_path / "resolved.ips"
    assert bundle.policy_dir not in bundle.resolved_cache.parents


def test_ensure_dirs_creates_policy_dir_owner_only(tmp_path: Path) -> None:
    """``ensure_dirs`` creates ``policy/`` at the owner-only bundle mode."""
    bundle = StateBundle(tmp_path / "sd")
    bundle.ensure_dirs()
    assert bundle.policy_dir.is_dir()
    assert stat.S_IMODE(bundle.policy_dir.stat().st_mode) == STATE_DIR_MODE


# ── tier authority: the t20 security tier as a matcher ───────────────────


def _security_bundle(tmp_path: Path) -> StateBundle:
    """A bundle whose security tier denies VAULT_HOST (resolved to TEST_IP1) and TEST_NET1's range."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("security_deny").write_text(f"-{VAULT_HOST}\n-{TEST_NET1}\n")
    bundle.deny_resolved.write_text(f"{TEST_IP1}\n")
    return bundle


def test_read_security_tier_takes_the_tier_and_its_resolution(tmp_path: Path) -> None:
    """Names and literals come from the tier file, addresses also from its resolution cache."""
    tier = _security_bundle(tmp_path).read_security_tier(extra_addresses=[TEST_IP3])
    assert tier == SecurityTier(names=(VAULT_HOST,), addresses=(TEST_NET1, TEST_IP1, TEST_IP3))


def test_read_security_tier_leaves_the_operators_overlay_out(tmp_path: Path) -> None:
    """A runtime deny is the operator's to lift, so the security matcher never sees it."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.policy_live.write_text(f"-{TEST_DOMAIN}\n-{TEST_IP3}\n")
    bundle.live_deny_resolved.write_text(f"{TEST_IP4}\n")
    assert bundle.read_security_tier() == SecurityTier()


@pytest.mark.parametrize(
    ("target", "addresses", "entry", "address", "cause"),
    [
        pytest.param(VAULT_HOST, [], VAULT_HOST, "", "is a security-tier host", id="name"),
        pytest.param(
            VAULT_HOST.upper() + ".", [], VAULT_HOST, "", "security-tier host", id="name-spelling"
        ),
        pytest.param(
            VAULT_SUBDOMAIN, [], VAULT_HOST, "", "under the security-tier domain", id="suffix"
        ),
        pytest.param(
            f"*.{VAULT_HOST}", [], VAULT_HOST, "", "security-tier host", id="wildcard-target"
        ),
        pytest.param(
            TEST_DOMAIN,
            [TEST_IP3, TEST_IP1],
            TEST_IP1,
            TEST_IP1,
            f"shares the address {TEST_IP1}",
            id="shared-address",
        ),
        pytest.param(
            TEST_DOMAIN,
            [TEST_IP99],
            TEST_NET1,
            TEST_IP99,
            f"inside the security-tier range {TEST_NET1}",
            id="address-in-range",
        ),
        pytest.param(TEST_IP1, [], TEST_IP1, TEST_IP1, "is a security-tier address", id="ip"),
        pytest.param(
            TEST_NET1,
            [],
            TEST_IP1,
            TEST_NET1,
            f"overlaps the security-tier entry {TEST_IP1}",
            id="range-names-the-narrowest-entry",
        ),
    ],
)
def test_security_tier_refuses_by_name_suffix_and_address(
    tmp_path: Path,
    target: str,
    addresses: list[str],
    entry: str,
    address: str,
    cause: str,
) -> None:
    """Each way a target can fall in the security tier refuses it, naming the entry and address."""
    refusal = _security_bundle(tmp_path).read_security_tier().refusal(target, addresses)
    assert isinstance(refusal, SecurityTierRefusal)
    assert (refusal.target, refusal.entry, refusal.address) == (target, entry, address)
    assert cause in str(refusal)
    assert str(refusal).endswith("break-glass only")


def test_a_range_target_overlapping_a_security_address_is_refused(tmp_path: Path) -> None:
    """Allowing a range that takes in one security address would allow that address too."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("security_deny").write_text(f"-{TEST_IP1}\n")
    refusal = bundle.read_security_tier().refusal(TEST_NET1)
    assert refusal is not None
    assert refusal.entry == TEST_IP1
    assert f"overlaps the security-tier entry {TEST_IP1}" in str(refusal)


def test_a_one_host_prefix_target_is_refused_as_the_security_address_itself(
    tmp_path: Path,
) -> None:
    """``/32`` names the host alone, so the refusal names it bare, as the tier and nft do."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("security_deny").write_text(f"-{TEST_IP1}\n")
    refusal = bundle.read_security_tier().refusal(f"{TEST_IP1}/32")
    assert refusal is not None
    assert (refusal.entry, refusal.address) == (TEST_IP1, TEST_IP1)
    assert f"{TEST_IP1}/32 is a security-tier address" in str(refusal)


@pytest.mark.parametrize(
    ("target", "addresses"),
    [
        pytest.param(VAULT_PARENT_DOMAIN, [], id="the-domain-above"),
        pytest.param(f"x{VAULT_HOST}", [], id="a-longer-label-is-no-suffix"),
        pytest.param(TEST_DOMAIN, [TEST_IP3, IPV6_CLOUDFLARE], id="unrelated-addresses"),
        pytest.param(TEST_IP3, [], id="unrelated-ip"),
        pytest.param(TEST_DOMAIN, ["not-an-address"], id="unparsable-address"),
    ],
)
def test_security_tier_lets_everything_else_through(
    tmp_path: Path, target: str, addresses: list[str]
) -> None:
    """Neither a parent domain nor an unrelated or unparsable address is refused."""
    assert _security_bundle(tmp_path).read_security_tier().refusal(target, addresses) is None


def test_security_tier_matches_ipv6_canonically_and_never_across_families() -> None:
    """A verbose v6 spelling still matches; a v4 range never swallows a v6 address."""
    tier = SecurityTier(addresses=(IPV6_NET1, TEST_NET1))
    refusal = tier.refusal(IPV6_VERBOSE)
    assert refusal is not None
    assert refusal.address == IPV6_VERBOSE_CANONICAL
    assert SecurityTier(addresses=(TEST_NET1,)).refusal(IPV6_CLOUDFLARE) is None


@pytest.mark.parametrize(
    "addresses",
    [
        pytest.param((TEST_NET1, TEST_IP1), id="range-first"),
        pytest.param((TEST_IP1, TEST_NET1), id="address-first"),
    ],
)
def test_security_tier_names_the_narrowest_entry_whatever_the_order(
    addresses: tuple[str, ...],
) -> None:
    """An exact security address says more than the range around it, in either order."""
    assert SecurityTier(addresses=addresses).address_refusing(TEST_IP1) == TEST_IP1


def test_security_tier_skips_an_unparsable_cached_address() -> None:
    """A corrupt cache line is skipped, never matched and never a crash."""
    assert SecurityTier(addresses=("garbage", TEST_IP1)).address_refusing(TEST_IP1) == TEST_IP1


def test_security_tier_refusal_is_a_runtime_error() -> None:
    """Callers that treat runtime failures alike (both CLIs) report it without special-casing."""
    assert isinstance(SecurityTierRefusal(VAULT_HOST, entry=VAULT_HOST), RuntimeError)


# ── provenance of the t20 seed ────────────────────────────────────────────


def test_read_denied_ips_unions_both_resolution_caches(tmp_path: Path) -> None:
    """The t20 seed keeps the security tier's and the overlay's resolved addresses alike."""
    bundle = _security_bundle(tmp_path)
    bundle.live_deny_resolved.write_text(f"{TEST_IP3}\n")
    assert {TEST_IP1, TEST_IP3, TEST_NET1} <= bundle.read_denied_ips()


def test_read_live_denied_ips_is_only_the_operators_own(tmp_path: Path) -> None:
    """Literal overlay denies plus their resolved names — never the security tier's addresses."""
    bundle = _security_bundle(tmp_path)
    bundle.policy_live.write_text(f"-{TEST_IP3}\n-{TEST_DOMAIN}\n+{TEST_IP99}\n")
    bundle.live_deny_resolved.write_text(f"{TEST_IP4}\n")
    assert bundle.read_live_denied_ips() == {TEST_IP3, TEST_IP4}


def test_live_deny_resolved_is_a_derived_top_level_file(tmp_path: Path) -> None:
    """The overlay's deny cache sits beside the security tier's, outside ``policy/``."""
    bundle = StateBundle(tmp_path)
    assert bundle.live_deny_resolved == tmp_path / "live_deny_resolved.ips"
    assert bundle.live_deny_resolved != bundle.deny_resolved


# ── the recorded container id ─────────────────────────────────────────────


@pytest.mark.parametrize(
    ("recorded", "expected"),
    [
        pytest.param(f"{_SHORT_CONTAINER_ID}\n", _SHORT_CONTAINER_ID, id="as-the-hook-writes-it"),
        pytest.param(_FULL_CONTAINER_ID, _SHORT_CONTAINER_ID, id="full-id-is-cut-short"),
        pytest.param(_SHORT_CONTAINER_ID.upper(), _SHORT_CONTAINER_ID, id="upper-case"),
        pytest.param("../not-an-id\n", None, id="not-hex"),
        pytest.param("abc\n", None, id="too-short"),
        pytest.param("", None, id="empty"),
    ],
)
def test_recorded_container_id_reads_the_hooks_short_id(
    tmp_path: Path, recorded: str, expected: str | None
) -> None:
    """The short id the OCI hook recorded comes back as the 12-char key; anything else is None."""
    StateBundle(tmp_path).container_id.write_text(recorded)
    assert recorded_container_id(tmp_path) == expected


def test_recorded_container_id_is_none_before_the_first_start(tmp_path: Path) -> None:
    """No hook has run, so there is no id to name the container by."""
    assert recorded_container_id(tmp_path) is None


def test_recorded_container_id_survives_a_non_utf8_file(tmp_path: Path) -> None:
    """Undecodable content reads as no id, like an absent file."""
    StateBundle(tmp_path).container_id.write_bytes(b"\xff\xfe")
    assert recorded_container_id(tmp_path) is None


# ── the creation-time audit flag ──────────────────────────────────────────


@pytest.mark.parametrize(
    ("recorded", "expected"),
    [
        pytest.param(b"false\n", False, id="off"),
        pytest.param(b"true\n", True, id="on"),
        pytest.param(None, True, id="never-recorded"),
        pytest.param(b"maybe\n", True, id="not-a-flag"),
        pytest.param(b"\xff\xfe", True, id="non-utf8"),
    ],
)
def test_read_audit_enabled_is_off_only_when_the_flag_says_false(
    tmp_path: Path, recorded: bytes | None, expected: bool
) -> None:
    """Only an explicit ``false`` turns audit off; anything else keeps the shield's default."""
    bundle = StateBundle(tmp_path)
    if recorded is not None:
        bundle.audit_flag.write_bytes(recorded)
    assert bundle.read_audit_enabled() is expected


# ── t10 override expiry ───────────────────────────────────

_TODAY = date.today()
_SOON = _TODAY + timedelta(days=1)
_LATER = _TODAY + timedelta(days=30)
_PAST = _TODAY - timedelta(days=1)


def _override_bundle(state_dir: Path, lines: str) -> StateBundle:
    """A bundle whose t10 tier holds *lines*."""
    bundle = StateBundle(state_dir)
    bundle.ensure_dirs()
    bundle.tier_path("override").write_text(lines)
    return bundle


def _deadline(day: date) -> float:
    """Epoch seconds at which an override expiring on *day* runs out."""
    return expiry_deadline(day.isoformat()).timestamp()


def test_an_expired_override_drops_out_of_every_override_reading(tmp_path: Path) -> None:
    """Past its day an override is no resolver target, no punch-through and no seed."""
    bundle = _override_bundle(
        tmp_path,
        f"+{TEST_IP1} %expires={_PAST}\n+{TEST_DOMAIN} %expires={_PAST}\n+{TEST_IP2}\n",
    )
    effective = bundle.read_effective()
    assert effective.override_targets() == [TEST_IP2]
    assert effective.override_domains() == []
    assert bundle.read_override_ips() == [TEST_IP2]


def test_an_override_holds_through_its_expiry_day(tmp_path: Path) -> None:
    """``expires`` set to today still holds until tonight's midnight, and not a second past it."""
    bundle = _override_bundle(tmp_path, f"+{TEST_IP1} %expires={_TODAY}\n")
    deadline = _deadline(_TODAY)
    assert bundle.read_override_seeds(now=deadline - 1) == [OverrideSeed(TEST_IP1, deadline)]
    assert bundle.read_override_seeds(now=deadline) == []


def test_an_unreadable_expiry_never_keeps_an_override_open(tmp_path: Path) -> None:
    """A read must not fail on a bad marker, nor let an expiry nobody can read hold a door."""
    bundle = _override_bundle(tmp_path, f"+{TEST_IP1} %expires=someday\n+{TEST_IP2}\n")
    assert bundle.read_override_ips() == [TEST_IP2]


def test_override_seeds_time_each_address_by_the_override_that_named_it(tmp_path: Path) -> None:
    """Every override carries its own expiry, so its addresses do — a name's through the cache."""
    bundle = _override_bundle(
        tmp_path,
        f"+{TEST_DOMAIN} %expires={_SOON}\n+{TEST_DOMAIN2} %expires={_LATER}\n+{TEST_IP3}\n",
    )
    bundle.override_resolved.write_text(f"{TEST_DOMAIN} {TEST_IP1}\n{TEST_DOMAIN2} {TEST_IP2}\n")
    assert bundle.read_override_seeds() == [
        OverrideSeed(TEST_IP1, _deadline(_SOON)),
        OverrideSeed(TEST_IP2, _deadline(_LATER)),
        OverrideSeed(TEST_IP3, None),
    ]


def test_a_shared_override_address_lives_as_long_as_its_longest_override(tmp_path: Path) -> None:
    """Two overrides on one address: the later deadline holds it, and no deadline outlives both."""
    bundle = _override_bundle(
        tmp_path, f"+{TEST_DOMAIN} %expires={_SOON}\n+{TEST_DOMAIN2} %expires={_LATER}\n"
    )
    bundle.override_resolved.write_text(f"{TEST_DOMAIN} {TEST_IP1}\n{TEST_DOMAIN2} {TEST_IP1}\n")
    assert bundle.read_override_seeds() == [OverrideSeed(TEST_IP1, _deadline(_LATER))]

    bundle.tier_path("override").write_text(f"+{TEST_DOMAIN} %expires={_SOON}\n+{TEST_DOMAIN2}\n")
    assert bundle.read_override_seeds() == [OverrideSeed(TEST_IP1, None)]


def test_an_override_range_covers_the_hosts_inside_it(tmp_path: Path) -> None:
    """nft refuses overlapping intervals in one batch: the range stays, a host inside it goes."""
    bundle = _override_bundle(tmp_path, f"+{TEST_NET1}\n+{TEST_NET1_HOST}\n+{TEST_IP3}\n")
    assert bundle.read_override_ips() == [TEST_NET1, TEST_IP3]


def test_a_covered_host_that_outlives_its_range_lapses_with_it_until_reseeded(
    tmp_path: Path,
) -> None:
    """The range is never stretched to the host's deadline; once it runs out, the host stands alone."""
    bundle = _override_bundle(tmp_path, f"+{TEST_NET1} %expires={_SOON}\n+{TEST_NET1_HOST}\n")
    assert bundle.read_override_seeds() == [OverrideSeed(TEST_NET1, _deadline(_SOON))]
    assert bundle.read_override_seeds(now=_deadline(_SOON)) == [OverrideSeed(TEST_NET1_HOST, None)]


def test_an_address_a_never_ending_override_names_first_never_ends(tmp_path: Path) -> None:
    """Whichever order the two overrides come in, the one that never expires holds the address."""
    bundle = _override_bundle(tmp_path, f"+{TEST_DOMAIN2}\n+{TEST_DOMAIN} %expires={_SOON}\n")
    bundle.override_resolved.write_text(f"{TEST_DOMAIN} {TEST_IP1}\n{TEST_DOMAIN2} {TEST_IP1}\n")
    assert bundle.read_override_seeds() == [OverrideSeed(TEST_IP1, None)]


# One host, spelled bare (as nft lists it) and as a full-length prefix.
_HOST_SPELLINGS = [
    pytest.param(TEST_IP1, f"{TEST_IP1}/32", id="v4-32"),
    pytest.param(IPV6_VERBOSE_CANONICAL, f"{IPV6_VERBOSE}/128", id="v6-128"),
]


@pytest.mark.parametrize(("host", "prefixed"), _HOST_SPELLINGS)
@pytest.mark.parametrize(
    "prefixed_outlasts", [True, False], ids=["prefix-outlasts", "bare-outlasts"]
)
@pytest.mark.parametrize("sooner_first", [True, False], ids=["sooner-first", "later-first"])
def test_one_host_spelled_two_ways_seeds_one_element_with_the_later_deadline(
    tmp_path: Path, host: str, prefixed: str, prefixed_outlasts: bool, sooner_first: bool
) -> None:
    """``/32`` and ``/128`` name the host itself: the two overrides are one, the later holds it."""
    sooner, later = (host, prefixed) if prefixed_outlasts else (prefixed, host)
    lines = [f"+{sooner} %expires={_SOON}\n", f"+{later} %expires={_LATER}\n"]
    bundle = _override_bundle(tmp_path, "".join(lines if sooner_first else reversed(lines)))
    assert bundle.read_override_seeds() == [OverrideSeed(host, _deadline(_LATER))]


@pytest.mark.parametrize(
    ("host", "pair"),
    [
        pytest.param(TEST_IP1, f"{TEST_IP1}/31", id="v4-31"),
        pytest.param(IPV6_VERBOSE_CANONICAL, f"{IPV6_VERBOSE_CANONICAL}/127", id="v6-127"),
    ],
)
def test_a_two_host_prefix_stays_a_range(tmp_path: Path, host: str, pair: str) -> None:
    """A ``/31`` or ``/127`` is two hosts: it keeps its prefix, and a grant for one host leaves it."""
    range_text = str(ipaddress.ip_network(pair, strict=False))
    bundle = _override_bundle(tmp_path, f"+{pair} %expires={_SOON}\n+{host} %expires={_LATER}\n")
    assert bundle.read_override_seeds() == [OverrideSeed(range_text, _deadline(_SOON))]

    bundle.upsert_override(host, _LATER.isoformat(), reason="outage")
    assert [entry.target for entry in bundle.read_tier(bundle.tier_path("override"))] == [
        pair,
        host,
    ]


def test_a_host_service_grant_in_the_override_tier_seeds_nothing(tmp_path: Path) -> None:
    """``+localhost:PORT`` opens a preamble port, never a t10 element."""
    bundle = _override_bundle(tmp_path, f"+{LOCALHOST_GRANT}\n")
    assert bundle.read_override_seeds() == []


def test_a_flat_override_cache_attributes_nothing(tmp_path: Path) -> None:
    """A cache that kept no names cannot time an address to any override, so it seeds none."""
    bundle = _override_bundle(tmp_path, f"+{TEST_DOMAIN} %expires={_SOON}\n")
    bundle.override_resolved.write_text(f"{TEST_IP1}\n")
    assert bundle.read_override_seeds() == []


@pytest.fixture
def slirp4netns_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> StateBundle:
    """A bundle launched under slirp4netns at its default CIDR, gateways recorded as pre_start does."""
    monkeypatch.setattr("terok_shield.podman_info.network._SYSTEM_CONF_PATHS", ())
    bundle = _override_bundle(tmp_path, "")
    bundle.network_mode.write_text("slirp4netns\n")
    bundle.record_gateways(SLIRP4NETNS_GATEWAY, SLIRP4NETNS_GATEWAY_V6)
    return bundle


def test_a_name_rebound_onto_the_host_gateway_seeds_none_of_it(
    slirp4netns_bundle: StateBundle,
) -> None:
    """Whichever path refreshed the cache, the gateway — the host's loopback — never reaches t10.

    A grant checks only its own target's fresh answer; every rebuild and every
    later grant re-resolves the other names, and the seed is where all of them
    meet.  The name keeps the addresses it may open, and the line says why
    the rest stayed out.
    """
    bundle = slirp4netns_bundle
    bundle.tier_path("override").write_text(f"+{TEST_DOMAIN} %expires={_SOON}\n")
    bundle.override_resolved.write_text(f"{TEST_DOMAIN} {SLIRP4NETNS_GATEWAY} {TEST_IP1}\n")

    assert bundle.read_override_seeds() == [OverrideSeed(TEST_IP1, _deadline(_SOON))]
    (line,) = bundle.read_override_refusals()
    assert f"{TEST_DOMAIN} reaches {SLIRP4NETNS_GATEWAY}" in line
    assert f"the host's own loopback ({CONTAINER_HOSTNAME})" in line


@pytest.mark.parametrize(
    "target",
    [
        pytest.param(SLIRP4NETNS_GATEWAY, id="gateway-v4"),
        pytest.param(SLIRP4NETNS_GATEWAY_V6, id="gateway-v6"),
        pytest.param(AWS_IMDS_V4, id="imds-v4"),
        pytest.param(AWS_IMDS_V6, id="imds-v6"),
    ],
)
def test_an_override_naming_the_host_or_the_floor_outright_seeds_nothing(
    slirp4netns_bundle: StateBundle, target: str
) -> None:
    """An authored literal is held to the same bar as a resolved answer — nothing gets past it."""
    slirp4netns_bundle.tier_path("override").write_text(f"+{target}\n+{TEST_IP2}\n")

    assert slirp4netns_bundle.read_override_ips() == [TEST_IP2]
    (line,) = slirp4netns_bundle.read_override_refusals()
    assert f"t10 override {target} reaches {target}" in line


def test_a_range_around_the_host_gateway_keeps_the_rest_of_the_range(
    slirp4netns_bundle: StateBundle,
) -> None:
    """A range is no host-loopback address: it stays, and the ruleset refuses the gateway above it."""
    slirp4netns_bundle.tier_path("override").write_text(f"+{RFC1918_CIDR_10}\n")

    assert slirp4netns_bundle.read_override_ips() == [RFC1918_CIDR_10]
    assert slirp4netns_bundle.read_override_refusals() == []


def test_the_host_gateway_bar_follows_the_recorded_network_mode(tmp_path: Path) -> None:
    """Under pasta the slirp4netns gateway address is an ordinary private host an override opens."""
    bundle = _override_bundle(tmp_path, f"+{SLIRP4NETNS_GATEWAY}\n")
    bundle.network_mode.write_text("pasta\n")

    assert bundle.read_override_ips() == [SLIRP4NETNS_GATEWAY]
    assert bundle.read_override_refusals() == []


def test_name_resolution_round_trips_and_leaves_out_unresolved_names(tmp_path: Path) -> None:
    """One line per name with its addresses; a name with none has no line to give."""
    cache = tmp_path / "names.ips"
    cache.write_text(
        render_name_resolution({TEST_DOMAIN: [TEST_IP1, IPV6_CLOUDFLARE], TEST_DOMAIN2: []})
    )
    assert read_name_resolution(cache) == {TEST_DOMAIN: [TEST_IP1, IPV6_CLOUDFLARE]}


def test_name_resolution_skips_blank_lines(tmp_path: Path) -> None:
    """A blank line between names is no name of its own."""
    cache = tmp_path / "names.ips"
    cache.write_text(f"{TEST_DOMAIN} {TEST_IP1}\n\n{TEST_DOMAIN2} {TEST_IP2}\n")
    assert read_name_resolution(cache) == {TEST_DOMAIN: [TEST_IP1], TEST_DOMAIN2: [TEST_IP2]}


def test_a_flat_or_absent_cache_reads_as_no_name_resolution(tmp_path: Path) -> None:
    """Without names there is nothing to attribute — absent and flat read the same."""
    cache = tmp_path / "flat.ips"
    cache.write_text(f"{TEST_IP1}\n")
    assert read_name_resolution(cache) is None
    assert read_name_resolution(tmp_path / "absent.ips") is None


def test_upsert_override_replaces_an_earlier_entry_for_the_target(tmp_path: Path) -> None:
    """A live break-glass re-records the target with its expiry and reason; the rest of the tier stays."""
    bundle = _override_bundle(tmp_path, f"+{TEST_DOMAIN}\n+{TEST_IP1}\n")
    bundle.upsert_override(TEST_DOMAIN, _LATER.isoformat(), reason="outage")
    assert parse_policy(bundle.tier_path("override").read_text()) == [
        PolicyEntry("+", TEST_IP1),
        PolicyEntry("+", TEST_DOMAIN, meta={"expires": _LATER.isoformat(), "reason": "outage"}),
    ]


@pytest.mark.parametrize(("host", "prefixed"), _HOST_SPELLINGS)
@pytest.mark.parametrize("granted_prefixed", [True, False], ids=["grant-prefix", "grant-bare"])
def test_a_grant_replaces_the_hosts_entry_however_either_spells_it(
    tmp_path: Path, host: str, prefixed: str, granted_prefixed: bool
) -> None:
    """An operator extending an authored host in another spelling extends it — one entry, one element."""
    authored, granted = (host, prefixed) if granted_prefixed else (prefixed, host)
    bundle = _override_bundle(tmp_path, f"+{authored} %expires={_SOON}\n+{TEST_IP3}\n")
    planned = bundle.read_effective().with_override(
        override_entry(granted, _LATER.isoformat(), reason="outage")
    )

    bundle.upsert_override(granted, _LATER.isoformat(), reason="outage")

    recorded = bundle.read_effective().override
    assert [entry.target for entry in recorded] == [TEST_IP3, granted]
    assert planned.override == recorded
    assert bundle.read_override_seeds() == [
        OverrideSeed(TEST_IP3, None),
        OverrideSeed(host, _deadline(_LATER)),
    ]


def test_read_network_mode_reads_what_pre_start_recorded(tmp_path: Path) -> None:
    """The recorded mode, trimmed; nothing recorded reads as no mode, never as an error."""
    bundle = StateBundle(tmp_path)
    assert bundle.read_network_mode() == ""
    bundle.ensure_dirs()
    bundle.network_mode.write_text("slirp4netns\n")
    assert bundle.read_network_mode() == "slirp4netns"


def test_pasta_has_no_gateways_and_reads_no_record(tmp_path: Path) -> None:
    """pasta's host loopback is a constant map: no record to write, none to read."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.network_mode.write_text("pasta\n")
    bundle.record_gateways("", "")

    assert not bundle.network_gateways.exists()
    assert bundle.read_gateways() == ("", "")
    assert bundle.host_loopback() == {PASTA_HOST_LOOPBACK_MAP}


def test_slirp4netns_reads_the_gateways_it_launched_with(tmp_path: Path) -> None:
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.network_mode.write_text("slirp4netns\n")
    bundle.record_gateways(SLIRP4NETNS_GATEWAY, SLIRP4NETNS_GATEWAY_V6)

    assert bundle.read_gateways() == (SLIRP4NETNS_GATEWAY, SLIRP4NETNS_GATEWAY_V6)
    assert bundle.host_loopback() == {SLIRP4NETNS_GATEWAY, SLIRP4NETNS_GATEWAY_V6}


def test_a_slirp4netns_bundle_without_the_record_must_be_recreated(tmp_path: Path) -> None:
    """Guessing the gateway from today's containers.conf could open the wrong address."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.network_mode.write_text("slirp4netns\n")

    with pytest.raises(RuntimeError, match="re-create the task"):
        bundle.read_gateways()


def test_upsert_override_keeps_a_free_text_reason_whole(tmp_path: Path) -> None:
    """Spaces, a ``#`` and a ``%`` would split or cut the line; encoded, the reason survives intact."""
    reason = "vendor outage #42, 100% down"
    bundle = _override_bundle(tmp_path, "")
    bundle.upsert_override(TEST_DOMAIN, _LATER.isoformat(), reason=reason)

    (line,) = bundle.tier_path("override").read_text().splitlines()
    (entry,) = parse_policy(line)
    assert unquote(entry.meta["reason"]) == reason
    assert entry.meta["expires"] == _LATER.isoformat()


def test_with_override_plans_in_memory_what_recording_the_grant_writes(tmp_path: Path) -> None:
    """A grant's planned tier is the tier its record leaves — and planning it writes nothing."""
    bundle = _override_bundle(tmp_path, f"+{TEST_DOMAIN}\n+{TEST_IP1}\n")
    recorded = bundle.read_effective()

    planned = recorded.with_override(
        override_entry(TEST_DOMAIN, _LATER.isoformat(), reason="outage")
    )

    assert bundle.tier_path("override").read_text() == f"+{TEST_DOMAIN}\n+{TEST_IP1}\n"
    assert recorded.override == [PolicyEntry("+", TEST_DOMAIN), PolicyEntry("+", TEST_IP1)]
    bundle.upsert_override(TEST_DOMAIN, _LATER.isoformat(), reason="outage")
    assert planned.override == bundle.read_effective().override


def test_override_seeds_of_a_planned_policy_come_from_it_not_the_record(tmp_path: Path) -> None:
    """A grant seeds the t10 tier as it will leave it, before the tier records anything."""
    bundle = _override_bundle(tmp_path, f"+{TEST_IP1}\n")
    grant = override_entry(TEST_IP2, _LATER.isoformat(), reason="outage")

    planned = bundle.read_override_seeds(policy=bundle.read_effective().with_override(grant))

    assert planned == [OverrideSeed(TEST_IP1), OverrideSeed(TEST_IP2, _deadline(_LATER))]
    assert bundle.read_override_seeds() == [OverrideSeed(TEST_IP1)]


def test_override_seeds_take_a_grants_own_answers_in_place_of_the_cache(tmp_path: Path) -> None:
    """A grant seeds from the answers it resolved, before the cache records any of them."""
    bundle = _override_bundle(tmp_path, f"+{TEST_DOMAIN} %expires={_LATER}\n")
    bundle.override_resolved.write_text(f"{TEST_DOMAIN} {TEST_IP1}\n")

    answered = bundle.read_override_seeds(resolution={TEST_DOMAIN: [TEST_IP2]})

    assert answered == [OverrideSeed(TEST_IP2, _deadline(_LATER))]
    assert bundle.read_override_seeds() == [OverrideSeed(TEST_IP1, _deadline(_LATER))]


def test_write_name_resolution_replaces_the_cache_whole(tmp_path: Path) -> None:
    """A name with no address gets no line, and no temp file is left beside the cache."""
    cache = tmp_path / "names.ips"
    cache.write_text(f"{TEST_DOMAIN2} {TEST_IP2}\n")

    write_name_resolution(cache, {TEST_DOMAIN: [TEST_IP1], TEST_DOMAIN2: []})

    assert read_name_resolution(cache) == {TEST_DOMAIN: [TEST_IP1]}
    assert list(tmp_path.iterdir()) == [cache]


def test_a_tier_write_that_fails_leaves_the_tier_whole(tmp_path: Path) -> None:
    """A full disk mid-write never tears the tier: a rebuild still reads every earlier entry.

    The grant that failed to record can then say what the next rebuild
    seeds in its place — the earlier record, whole.
    """
    earlier = f"+{TEST_IP1} %expires={_LATER}\n"
    bundle = _override_bundle(tmp_path, earlier)
    expires = _TODAY.isoformat()

    with (
        mock.patch("terok_shield.state.os.replace", side_effect=OSError("disk full")),
        pytest.raises(OSError, match="disk full"),
    ):
        bundle.upsert_override(TEST_IP1, expires, reason="outage")

    assert bundle.tier_path("override").read_text() == earlier
    assert [path.name for path in bundle.policy_dir.iterdir()] == ["10-override"]


def _lock_taken(lock: Path) -> bool:
    """Whether another descriptor holds *lock*'s ``flock`` — probed without waiting for it."""
    fd = os.open(lock, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(fd)
    return False


def test_override_change_holds_the_t10_lock_for_its_block_alone(tmp_path: Path) -> None:
    """Exclusive while the block runs — against every other descriptor — and free once it ends."""
    bundle = _override_bundle(tmp_path, "")

    with bundle.override_change():
        assert _lock_taken(bundle.override_lock)
    assert not _lock_taken(bundle.override_lock)

    with pytest.raises(LookupError), bundle.override_change():
        raise LookupError  # an exception ends the block too, and the lock with it
    assert not _lock_taken(bundle.override_lock)


def test_override_change_without_a_bundle_creates_none(tmp_path: Path) -> None:
    """No state directory, no tier to change: refused in words, and nothing is created."""
    bundle = StateBundle(tmp_path / "never-launched")

    with pytest.raises(RuntimeError, match="holds no state bundle"), bundle.override_change():
        pytest.fail("the block must not run without the lock")

    assert not bundle.state_dir.exists()


@pytest.mark.parametrize(
    ("recorded", "asked"),
    [
        pytest.param(TEST_DOMAIN, TEST_DOMAIN.upper(), id="name-case"),
        pytest.param(TEST_IP1, f"{TEST_IP1}/32", id="host-as-a-prefix"),
        pytest.param(IPV6_VERBOSE_CANONICAL, IPV6_VERBOSE, id="ipv6-spelling"),
        pytest.param(TEST_NET1, TEST_NET1, id="range"),
    ],
)
def test_override_entries_find_a_target_however_it_is_spelled(
    tmp_path: Path, recorded: str, asked: str
) -> None:
    """A revoke names the target as an operator types it; the record may spell it otherwise.

    Only spellings the target grammar accepts on both sides: it takes no
    trailing dot, so neither a revoke nor a record ever carries one.
    """
    bundle = _override_bundle(tmp_path, f"+{recorded} %expires={_LATER}\n+{TEST_IP3}\n")
    assert [entry.target for entry in bundle.override_entries(asked)] == [recorded]


@pytest.mark.parametrize(
    ("recorded", "asked"),
    [
        pytest.param(f"*.{TEST_DOMAIN}", TEST_DOMAIN, id="wildcard-is-not-its-apex"),
        pytest.param(TEST_NET1, TEST_NET1_HOST, id="range-is-not-a-host-inside-it"),
        pytest.param(TEST_IP1, TEST_DOMAIN, id="address-is-not-a-name"),
    ],
)
def test_override_entries_never_stretch_a_match(tmp_path: Path, recorded: str, asked: str) -> None:
    """Only the target itself matches: a revoke must never end a different override."""
    bundle = _override_bundle(tmp_path, f"+{recorded}\n")
    assert bundle.override_entries(asked) == []


def test_remove_override_drops_every_entry_for_the_target_and_keeps_the_rest(
    tmp_path: Path,
) -> None:
    """A live grant and an authored line for one target both go; every other override stays."""
    bundle = _override_bundle(
        tmp_path,
        f"+{TEST_DOMAIN}\n+{TEST_DOMAIN2} %expires={_LATER} %reason=outage\n"
        f"+{TEST_IP1}\n+{TEST_DOMAIN2}\n",
    )

    removed = bundle.remove_override(TEST_DOMAIN2)

    assert [entry.target for entry in removed] == [TEST_DOMAIN2, TEST_DOMAIN2]
    assert parse_policy(bundle.tier_path("override").read_text()) == [
        PolicyEntry("+", TEST_DOMAIN),
        PolicyEntry("+", TEST_IP1),
    ]


def test_remove_override_of_an_unknown_target_leaves_the_tier_untouched(tmp_path: Path) -> None:
    """No match, no write: the resolver's freshness check keys on the tier's mtime."""
    bundle = _override_bundle(tmp_path, f"+{TEST_IP1}\n")
    tier = bundle.tier_path("override")
    os.utime(tier, ns=(0, 0))

    assert bundle.remove_override(TEST_IP2) == []
    assert tier.stat().st_mtime_ns == 0
    assert tier.read_text() == f"+{TEST_IP1}\n"


def test_override_expiry_lives_in_the_bundle(tmp_path: Path) -> None:
    """The hook's deadline file sits beside the ruleset it completes."""
    assert StateBundle(tmp_path).override_expiry == tmp_path / "override.expiry"


# ── rotation risk ─────────────────────────────────────────


def _rotation_bundle(state_dir: Path, tier: DnsTier) -> StateBundle:
    """A bundle with a rotation-prone name in every kind, plus every entry that cannot rotate."""
    bundle = StateBundle(state_dir)
    bundle.ensure_dirs()
    bundle.dns_tier.write_text(f"{tier.value}\n")
    bundle.write_tier("provider_allow", f"+{TEST_DOMAIN}\n")
    bundle.write_tier(
        "project_allow",
        "".join(
            f"+{target}\n"
            for target in (
                DEV_PYPI_DOMAIN,
                TEST_IP1,
                TEST_NET1,
                LOCALHOST_GRANT,
                CONTAINER_HOSTNAME,
                LOCALHOST_SUBDOMAIN,
            )
        ),
    )
    bundle.write_tier("security_deny", f"-{VAULT_HOST}\n-{TEST_IP2}\n")
    bundle.write_tier("override", f"+{TEST_DOMAIN2} %expires={_LATER}\n+{TEST_IP3}\n")
    return bundle


@pytest.mark.parametrize(
    ("tier", "allow", "deny"),
    [
        pytest.param(DnsTier.DNSMASQ_LIVE, (), (), id="live"),
        pytest.param(DnsTier.DNSMASQ_STATIC, (TEST_DOMAIN, DEV_PYPI_DOMAIN), (), id="static"),
        pytest.param(DnsTier.LOOKUP, (TEST_DOMAIN, DEV_PYPI_DOMAIN), (VAULT_HOST,), id="lookup"),
        pytest.param(DnsTier.GETENT, (TEST_DOMAIN, DEV_PYPI_DOMAIN), (VAULT_HOST,), id="getent"),
    ],
)
def test_rotation_risk_follows_what_each_tier_resolves_itself(
    tmp_path: Path, tier: DnsTier, allow: tuple[str, ...], deny: tuple[str, ...]
) -> None:
    """Allow names pin below the live tier, deny names without dnsmasq, overrides on every tier.

    IPs, CIDRs, the host-service grant, the host alias and ``*.localhost``
    names never rotate, so none of them is ever listed.
    """
    risk = _rotation_bundle(tmp_path, tier).read_rotation_risk()
    assert risk == RotationRisk(tier=tier, allow=allow, deny=deny, override=(TEST_DOMAIN2,))


def test_rotation_risk_is_none_when_nothing_can_rotate(tmp_path: Path) -> None:
    """A policy of addresses and stable local names leaves nothing to warn about."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.dns_tier.write_text(f"{DnsTier.GETENT.value}\n")
    bundle.write_tier(
        "project_allow",
        f"+{TEST_IP1}\n+{LOCALHOST_GRANT}\n+{CONTAINER_HOSTNAME}\n+{DOCKER_HOSTNAME}\n",
    )
    bundle.write_tier("security_deny", f"-{TEST_IP2}\n")
    assert bundle.read_rotation_risk() is None


def test_a_broken_glass_name_is_spoken_for_by_the_override_line(tmp_path: Path) -> None:
    """A vault host with a live override is listed once — as the override it now is."""
    bundle = _rotation_bundle(tmp_path, DnsTier.LOOKUP)
    bundle.write_tier("override", f"+{VAULT_HOST} %expires={_LATER}\n")
    risk = bundle.read_rotation_risk()
    assert risk is not None
    assert risk.deny == ()
    assert risk.override == (VAULT_HOST,)


def test_an_expired_override_is_no_rotation_risk(tmp_path: Path) -> None:
    """An override that ran out opens nothing, so nothing of it can rotate."""
    bundle = _rotation_bundle(tmp_path, DnsTier.DNSMASQ_LIVE)
    bundle.write_tier("override", f"+{TEST_DOMAIN2} %expires={_PAST}\n")
    assert bundle.read_rotation_risk() is None


def test_runtime_overlay_names_count_on_both_sides(tmp_path: Path) -> None:
    """A runtime allow pins like an authored one; a runtime deny escapes like the security tier's."""
    bundle = StateBundle(tmp_path)
    bundle.ensure_dirs()
    bundle.dns_tier.write_text(f"{DnsTier.LOOKUP.value}\n")
    bundle.overlay_set("+", TEST_DOMAIN)
    bundle.overlay_set("-", VAULT_SUBDOMAIN)
    assert bundle.read_rotation_risk() == RotationRisk(
        tier=DnsTier.LOOKUP, allow=(TEST_DOMAIN,), deny=(VAULT_SUBDOMAIN,)
    )


def test_rotation_risk_is_none_without_a_recorded_tier_or_a_readable_policy(
    tmp_path: Path,
) -> None:
    """A warning never breaks a launch or a poll: no tier, or a bad policy line, reads as none."""
    bundle = _rotation_bundle(tmp_path, DnsTier.LOOKUP)
    assert recorded_rotation_risk(tmp_path) == bundle.read_rotation_risk()
    bundle.tier_path("project_allow").write_text("no-action-prefix\n")
    assert bundle.read_rotation_risk() is None
    bundle.dns_tier.unlink()
    assert recorded_rotation_risk(tmp_path) is None


_RISK = RotationRisk(
    tier=DnsTier.LOOKUP, allow=(TEST_DOMAIN,), deny=(VAULT_HOST,), override=(TEST_DOMAIN2,)
)


def test_rotation_lines_at_launch_and_in_up_speak_for_every_kind() -> None:
    """A launch boots UP and may be lowered: every line counts, the deny line names both ways out."""
    launch = _RISK.lines()
    assert [TEST_DOMAIN in launch[0], TEST_DOMAIN2 in launch[1], VAULT_HOST in launch[2]] == [
        True,
        True,
        True,
    ]
    assert "whenever the shield is down or a bypass window is open" in launch[2]
    up = _RISK.lines(ShieldState.UP)
    assert len(up) == 3
    assert "when an allowlisted name shares it or a bypass window is open" in up[2]


def test_rotation_lines_in_down_are_the_deny_line_alone() -> None:
    """Accept-by-default makes a pinned allow moot; the security tier is still meant to hold."""
    (line,) = _RISK.lines(ShieldState.DOWN)
    assert line.startswith("Security:")
    assert "the shield is down, so an address it rotates to is accepted" in line


@pytest.mark.parametrize("posture", [ShieldState.DISENGAGED, ShieldState.QUARANTINE])
def test_rotation_lines_are_silent_where_nothing_is_enforced_by_name(posture: ShieldState) -> None:
    """DISENGAGED enforces nothing and quarantine reaches nothing: no line is worth a word."""
    assert _RISK.lines(posture) == []


def test_rotation_lines_on_the_live_tier_are_the_override_line_alone() -> None:
    """dnsmasq-live follows DNS for every allowed and denied name; only the break-glass stays pinned."""
    (line,) = RotationRisk(tier=DnsTier.DNSMASQ_LIVE, override=(TEST_DOMAIN2,)).lines()
    assert TEST_DOMAIN2 in line
    assert "overrides never follow DNS" in line


def test_rotation_lines_agree_in_number_and_count_past_the_first_names() -> None:
    """One name reads as one; many list the first few, then a count."""
    many = (TEST_DOMAIN, TEST_DOMAIN2, DEV_PYPI_DOMAIN, VAULT_HOST, VAULT_SUBDOMAIN)
    (one,) = RotationRisk(tier=DnsTier.LOOKUP, allow=(TEST_DOMAIN,)).lines()
    assert "pins 1 allowlisted name to the addresses it resolved to" in one
    (line,) = RotationRisk(tier=DnsTier.LOOKUP, allow=many).lines()
    assert "pins 5 allowlisted names to the addresses they resolved to" in line
    assert line.endswith(f"{TEST_DOMAIN}, {TEST_DOMAIN2}, {DEV_PYPI_DOMAIN}, and 2 more")
