# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Assembly tests: real class interactions without external dependencies.

These tests exercise real constructor signatures, collaborator wiring,
and cross-module data flow — catching API contract regressions that
integration tests would find only with podman/nft. No subprocess calls,
no mocks (unless strictly needed for the runner layer).

Each test class targets a specific contract boundary:
- Constructor signatures (catches missing required args)
- DnsResolver API (catches resolve_and_cache signature drift)
- Allow/deny persistence (catches live.allowed data flow)
- Shield+HookMode wiring (catches broken collaborator assembly)
"""

import tempfile
from pathlib import Path
from unittest import mock

import pytest

from terok_shield import Shield, ShieldConfig, state
from terok_shield.audit import AuditLogger
from terok_shield.dns import DnsResolver
from terok_shield.mode_hook import HookMode
from terok_shield.nft import RulesetBuilder
from terok_shield.profiles import ProfileLoader

from ..testfs import FAKE_RESOLVED_DIR
from ..testnet import TEST_DOMAIN, TEST_IP1, TEST_IP2


class TestConstructorContracts:
    """Verify constructor signatures accept the documented parameters.

    Catches regressions like ShieldConfig() without state_dir or
    DnsResolver(resolved_dir=...) after API changes.
    """

    def test_shield_config_requires_state_dir(self) -> None:
        """ShieldConfig() without state_dir raises TypeError."""
        with pytest.raises(TypeError):
            ShieldConfig()  # type: ignore[call-arg]

    def test_shield_config_accepts_state_dir(self) -> None:
        """ShieldConfig(state_dir=...) constructs successfully."""
        with tempfile.TemporaryDirectory() as tmp:
            config = ShieldConfig(state_dir=Path(tmp))
            assert config.state_dir == Path(tmp)

    def test_dns_resolver_stateless_constructor(self) -> None:
        """DnsResolver takes only runner=, not resolved_dir."""
        runner = mock.MagicMock()
        resolver = DnsResolver(runner=runner)
        assert resolver._runner is runner

    def test_dns_resolver_rejects_resolved_dir(self) -> None:
        """DnsResolver does not accept resolved_dir kwarg."""
        with pytest.raises(TypeError):
            DnsResolver(resolved_dir=FAKE_RESOLVED_DIR, runner=mock.MagicMock())  # type: ignore[call-arg]

    def test_audit_logger_accepts_audit_path(self) -> None:
        """AuditLogger takes audit_path=, not log_dir."""
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(audit_path=Path(tmp) / "audit.jsonl")
            assert logger is not None

    def test_ruleset_builder_constructor(self) -> None:
        """RulesetBuilder accepts loopback_ports."""
        rb = RulesetBuilder(loopback_ports=(8080, 9090))
        assert rb is not None

    def test_profile_loader_constructor(self) -> None:
        """ProfileLoader accepts user_dir."""
        with tempfile.TemporaryDirectory() as tmp:
            loader = ProfileLoader(user_dir=Path(tmp))
            assert loader is not None


class TestDnsResolverCacheContract:
    """Verify resolve_and_cache takes cache_path: Path, not container: str."""

    def test_resolve_and_cache_accepts_path(self) -> None:
        """resolve_and_cache(entries, cache_path) writes to the given path."""
        runner = mock.MagicMock()
        runner.dig_all.return_value = [TEST_IP1]
        resolver = DnsResolver(runner=runner)

        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "profile.allowed"
            ips = resolver.resolve_and_cache([TEST_DOMAIN], cache_path)
            assert TEST_IP1 in ips
            assert cache_path.is_file()
            assert TEST_IP1 in cache_path.read_text()

    def test_resolve_and_cache_reads_from_cache(self) -> None:
        """Second call with fresh cache skips DNS resolution."""
        runner = mock.MagicMock()
        runner.dig_all.return_value = [TEST_IP1]
        resolver = DnsResolver(runner=runner)

        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "profile.allowed"
            resolver.resolve_and_cache([TEST_DOMAIN], cache_path)
            runner.dig_all.reset_mock()

            ips2 = resolver.resolve_and_cache(["example.com"], cache_path, max_age=3600)
            runner.dig_all.assert_not_called()
            assert ips2 == [TEST_IP1]


class TestAllowDenyPersistence:
    """Verify allow_ip() persists to live.allowed and shield_up() reads it back.

    This catches the regression where test_allow_before_and_after_bypass
    expected IPs to be lost after a bypass cycle, but they now survive
    because allow_ip() writes to live.allowed.
    """

    def test_allow_ip_writes_to_live_allowed(self) -> None:
        """allow_ip() appends the IP to live.allowed."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            state.ensure_state_dirs(sd)
            runner = mock.MagicMock()
            runner.nft_via_nsenter.return_value = ""
            ruleset = mock.MagicMock()
            ruleset.safe_ip.return_value = TEST_IP1

            hm = HookMode(
                config=ShieldConfig(state_dir=sd),
                runner=runner,
                audit=mock.MagicMock(),
                dns=mock.MagicMock(),
                profiles=mock.MagicMock(),
                ruleset=ruleset,
            )

            hm.allow_ip("test-ctr", TEST_IP1)

            live_path = state.live_allowed_path(sd)
            assert live_path.is_file()
            assert TEST_IP1 in live_path.read_text()

    def test_deny_ip_removes_from_live_allowed(self) -> None:
        """deny_ip() removes the IP from live.allowed."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            state.ensure_state_dirs(sd)

            # Pre-populate live.allowed
            live_path = state.live_allowed_path(sd)
            live_path.write_text(f"{TEST_IP1}\n{TEST_IP2}\n")

            runner = mock.MagicMock()
            runner.nft_via_nsenter.return_value = ""
            ruleset = mock.MagicMock()
            ruleset.safe_ip.return_value = TEST_IP1

            hm = HookMode(
                config=ShieldConfig(state_dir=sd),
                runner=runner,
                audit=mock.MagicMock(),
                dns=mock.MagicMock(),
                profiles=mock.MagicMock(),
                ruleset=ruleset,
            )

            hm.deny_ip("test-ctr", TEST_IP1)

            content = live_path.read_text()
            assert TEST_IP1 not in content
            assert TEST_IP2 in content

    def test_read_allowed_ips_merges_both_files(self) -> None:
        """state.read_allowed_ips() merges profile.allowed + live.allowed."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            state.ensure_state_dirs(sd)

            state.profile_allowed_path(sd).write_text(f"{TEST_IP1}\n")
            state.live_allowed_path(sd).write_text(f"{TEST_IP2}\n")

            ips = state.read_allowed_ips(sd)
            assert ips == [TEST_IP1, TEST_IP2]

    def test_read_allowed_ips_deduplicates(self) -> None:
        """Duplicate IPs across files are deduplicated (first wins)."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            state.ensure_state_dirs(sd)

            state.profile_allowed_path(sd).write_text(f"{TEST_IP1}\n")
            state.live_allowed_path(sd).write_text(f"{TEST_IP1}\n{TEST_IP2}\n")

            ips = state.read_allowed_ips(sd)
            assert ips == [TEST_IP1, TEST_IP2]

    def test_shield_up_reads_live_allowed(self) -> None:
        """shield_up() re-adds IPs from live.allowed via state.read_allowed_ips().

        This is the exact scenario that broke the integration test:
        allow_ip() writes to live.allowed, shield_up() reads it back.
        """
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            state.ensure_state_dirs(sd)

            # Simulate allow_ip() having written to live.allowed
            state.live_allowed_path(sd).write_text(f"{TEST_IP1}\n{TEST_IP2}\n")

            runner = mock.MagicMock()
            runner.nft_via_nsenter.return_value = ""
            ruleset = mock.MagicMock()
            ruleset.build_hook.return_value = "table inet terok_shield {}"
            ruleset.add_elements_dual.return_value = "add element ..."
            ruleset.verify_hook.return_value = []  # no errors

            hm = HookMode(
                config=ShieldConfig(state_dir=sd),
                runner=runner,
                audit=mock.MagicMock(),
                dns=mock.MagicMock(),
                profiles=mock.MagicMock(),
                ruleset=ruleset,
            )

            hm.shield_up("test-ctr")

            # Verify add_elements_dual was called with the IPs from live.allowed
            ruleset.add_elements_dual.assert_called_once_with([TEST_IP1, TEST_IP2])


class TestShieldAssembly:
    """Verify Shield wires real collaborators from ShieldConfig.

    Catches regressions where Shield.__init__ fails because
    collaborator constructors changed signatures.
    """

    def test_shield_constructs_with_real_collaborators(self) -> None:
        """Shield(ShieldConfig(state_dir=...)) wires all real collaborators."""
        with tempfile.TemporaryDirectory() as tmp:
            config = ShieldConfig(state_dir=Path(tmp))
            shield = Shield(config)

            assert isinstance(shield.audit, AuditLogger)
            assert isinstance(shield.dns, DnsResolver)
            assert isinstance(shield.profiles, ProfileLoader)
            assert isinstance(shield.ruleset, RulesetBuilder)

    def test_shield_audit_path_derived_from_state_dir(self) -> None:
        """Shield's AuditLogger writes to state_dir/audit.jsonl."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            shield = Shield(ShieldConfig(state_dir=sd))
            expected = state.audit_path(sd)
            assert shield.audit._audit_path == expected

    def test_shield_resolve_uses_profile_allowed_path(self) -> None:
        """Shield.resolve() forwards entries and caches to state_dir/profile.allowed."""
        with tempfile.TemporaryDirectory() as tmp:
            sd = Path(tmp)
            dns = mock.MagicMock()
            dns.resolve_and_cache.return_value = [TEST_IP1]
            profiles = mock.MagicMock()
            profiles.compose_profiles.return_value = [TEST_DOMAIN]

            shield = Shield(ShieldConfig(state_dir=sd), dns=dns, profiles=profiles)
            shield.resolve(["dev-standard"])

            dns.resolve_and_cache.assert_called_once()
            call_args = dns.resolve_and_cache.call_args
            # First positional arg: composed entries
            assert call_args[0][0] == [TEST_DOMAIN]
            # Second positional arg: cache path
            assert call_args[0][1] == state.profile_allowed_path(sd)
