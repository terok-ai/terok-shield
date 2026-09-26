# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for per-container state bundle layout (state.py)."""

import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from terok_shield.config import DnsTier
from terok_shield.state import (
    BUNDLE_VERSION,
    STATE_DIR_MODE,
    StateBundle,
    recorded_dns_tier,
)

from ..testfs import FAKE_STATE_DIR, READER_PID_FILENAME
from ..testnet import TEST_DOMAIN, TEST_DOMAIN2, TEST_IP1, TEST_IP2, TEST_IP3


def test_bundle_version_is_positive_int() -> None:
    """BUNDLE_VERSION is a positive integer."""
    assert isinstance(BUNDLE_VERSION, int)
    assert BUNDLE_VERSION > 0


@pytest.mark.parametrize(
    ("attr", "expected"),
    [
        pytest.param("resolved_cache", FAKE_STATE_DIR / "resolved.ips", id="resolved-cache"),
        pytest.param("audit", FAKE_STATE_DIR / "audit.jsonl", id="audit-path"),
        pytest.param("dnsmasq_conf", FAKE_STATE_DIR / "dnsmasq.conf", id="dnsmasq-conf"),
        pytest.param("dnsmasq_pid", FAKE_STATE_DIR / "dnsmasq.pid", id="dnsmasq-pid"),
        pytest.param("dns_tier", FAKE_STATE_DIR / "dns.tier", id="dns-tier"),
        pytest.param("container_id", FAKE_STATE_DIR / "container.id", id="container-id"),
        pytest.param("reader_pid", FAKE_STATE_DIR / READER_PID_FILENAME, id="reader-pid"),
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
    bundle.tier_path("override").write_text(f"+{TEST_IP1}\n")  # literal override
    bundle.override_resolved.write_text(f"{TEST_IP2}\n")  # resolved override domain
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


def test_deny_targets_lists_domains_and_ips(tmp_path: Path) -> None:
    """deny_targets returns every ``-`` entry (security-deny + live) — the deny-resolver input."""
    bundle = StateBundle(tmp_path)
    bundle.policy_dir.mkdir()
    bundle.tier_path("security_deny").write_text(f"-{TEST_DOMAIN}\n")
    bundle.policy_live.write_text(f"-{TEST_IP2}\n")
    assert set(bundle.read_effective().deny_targets()) == {TEST_DOMAIN, TEST_IP2}


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
