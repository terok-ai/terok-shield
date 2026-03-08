# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: end-to-end firewall behavior in real containers.

These tests verify that the nftables ruleset actually blocks and allows
traffic when applied to a real container network namespace. They require
podman, nft, and internet access.

Run via: make test-podman
"""

import json
import subprocess
import tempfile
from pathlib import Path

import pytest

from terok_shield.hook import apply_hook, hook_main
from terok_shield.nft import add_elements, standard_ruleset, verify_ruleset
from terok_shield.nft_constants import RFC1918
from tests.testnet import (
    ALLOWED_TARGET_HTTP,
    ALLOWED_TARGET_HTTPS,
    ALLOWED_TARGET_IPS,
    BLOCKED_TARGET_HTTP,
    BLOCKED_TARGET_IP,
    GOOGLE_DNS_IP,
    IPV6_CLOUDFLARE,
    IPV6_GOOGLE,
    IPV6_HTTP_URL,
    QUAD9_DNS_IP,
    RFC1918_HOST,
    TEST_IP1,
)

from .conftest import nft_missing, nsenter_nft, podman_missing


def _exec(container: str, *cmd: str, timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a command inside a container via podman exec."""
    return subprocess.run(
        ["podman", "exec", container, *cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _wget(container: str, url: str, timeout: int = 5) -> subprocess.CompletedProcess:
    """Attempt an outbound HTTP/HTTPS request from inside a container."""
    return _exec(
        container, "wget", "-q", "--spider", f"--timeout={timeout}", url, timeout=timeout + 5
    )


# ── Firewall enforcement: blocking ──────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestFirewallBlocking:
    """Verify the default-deny ruleset blocks outbound traffic."""

    def test_http_blocked_after_ruleset(self, container: str, container_pid: str) -> None:
        """Outbound HTTP to an external IP is rejected after applying the ruleset."""

        r = nsenter_nft(container_pid, stdin=standard_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"

        post = _wget(container, ALLOWED_TARGET_HTTP, timeout=10)
        assert post.returncode != 0, "HTTP traffic should be blocked"

    def test_https_blocked_after_ruleset(self, container: str, container_pid: str) -> None:
        """Outbound HTTPS is rejected after applying the ruleset."""

        r = nsenter_nft(container_pid, stdin=standard_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"

        post = _wget(container, ALLOWED_TARGET_HTTPS, timeout=10)
        assert post.returncode != 0, "HTTPS traffic should be blocked"

    def test_ipv6_blocked_after_ruleset(self, container: str, container_pid: str) -> None:
        """IPv6 traffic is unconditionally dropped after applying the ruleset."""
        # Pre-firewall IPv6 probe — if IPv6 doesn't work before the firewall,
        # functional checks would pass trivially (false positive)
        pre_ping = _exec(container, "ping", "-6", "-c1", "-W2", IPV6_CLOUDFLARE, timeout=5)
        ipv6_available = pre_ping.returncode == 0

        nsenter_nft(container_pid, stdin=standard_ruleset())

        # Structural check: IPv6 drop is present and before first accept rule
        listed = nsenter_nft(container_pid, "list", "ruleset")
        assert listed.returncode == 0, listed.stderr
        output = listed.stdout
        assert "nfproto ipv6 drop" in output, "IPv6 drop rule must be in applied ruleset"
        ipv6_pos = output.find("nfproto ipv6 drop")
        ct_pos = output.find("ct state established,related accept")
        assert ipv6_pos < ct_pos, "IPv6 drop must precede established accept"

        if not ipv6_available:
            pytest.skip(
                "IPv6 not available pre-firewall — functional checks would be false positives"
            )

        # Functional: ICMP6 ping to Cloudflare DNS
        ping_cf = _exec(container, "ping", "-6", "-c1", "-W2", IPV6_CLOUDFLARE, timeout=5)
        assert ping_cf.returncode != 0, "IPv6 ping to Cloudflare should be blocked"

        # Functional: ICMP6 ping to Google DNS
        ping_g = _exec(container, "ping", "-6", "-c1", "-W2", IPV6_GOOGLE, timeout=5)
        assert ping_g.returncode != 0, "IPv6 ping to Google should be blocked"

        # Functional: HTTP over IPv6 literal (must not force IPv4)
        http6 = _wget(container, IPV6_HTTP_URL, timeout=5)
        assert http6.returncode != 0, "HTTP over IPv6 should be blocked"

    def test_reject_is_fast_not_timeout(self, container: str, container_pid: str) -> None:
        """Blocked traffic fails fast (reject), not via silent timeout (drop).

        A ``reject`` rule sends an ICMP error back immediately, so the
        connection fails in well under the timeout.  A ``drop`` rule
        would silently discard packets, causing the client to hang until
        the full timeout expires.  We verify reject behavior by measuring
        elapsed time rather than parsing tool-specific error messages.
        """
        import time

        r = nsenter_nft(container_pid, stdin=standard_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"

        wget_timeout = 10
        t0 = time.monotonic()
        post = _wget(container, BLOCKED_TARGET_HTTP, timeout=wget_timeout)
        elapsed = time.monotonic() - t0

        assert post.returncode != 0, "Blocked target should be rejected"
        assert elapsed < wget_timeout / 2, (
            f"Connection took {elapsed:.1f}s (timeout={wget_timeout}s) — "
            f"looks like drop (silent timeout), not reject (ICMP error)"
        )

    def test_rfc1918_still_blocked_when_not_whitelisted(
        self, container: str, container_pid: str
    ) -> None:
        """RFC1918 addresses are rejected when not in the allow set."""
        nsenter_nft(container_pid, stdin=standard_ruleset())

        # Structural: all RFC1918 reject rules present
        listed = nsenter_nft(container_pid, "list", "ruleset")
        assert listed.returncode == 0, listed.stderr
        for net in RFC1918:
            assert net in listed.stdout, f"Missing RFC1918 block for {net}"

    def test_rfc1918_allowed_when_whitelisted(self, container: str, container_pid: str) -> None:
        """RFC1918 addresses in the allow set bypass the RFC1918 reject rules."""
        nsenter_nft(container_pid, stdin=standard_ruleset())
        nsenter_nft(container_pid, stdin=add_elements("allow_v4", [RFC1918_HOST]))

        # Structural: allow set evaluates before RFC1918 reject
        listed = nsenter_nft(container_pid, "list", "ruleset")
        assert listed.returncode == 0, listed.stderr
        output = listed.stdout
        allow_pos = output.find("@allow_v4")
        rfc_pos = output.find(RFC1918[0])
        assert allow_pos != -1, "allow_v4 set must be present"
        assert rfc_pos != -1, "RFC1918 reject rules must be present"
        assert allow_pos < rfc_pos, "Allow set must precede RFC1918 reject rules"


# ── ICMP error detection via shield_probe ─────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestShieldProbe:
    """Verify shield_probe detects the exact ICMP admin-prohibited code."""

    def _run_probe(self, container: str, host: str, port: int = 443, timeout: int = 15) -> dict:
        """Run shield_probe.py inside the container and return parsed JSON."""
        r = _exec(
            container, "python3", "/usr/local/bin/shield_probe.py", host, str(port), timeout=timeout
        )
        assert r.returncode == 0, f"shield_probe failed: {r.stderr}"
        return json.loads(r.stdout)

    def test_admin_prohibited_detected(self, probe_container: str) -> None:
        """Blocked traffic reports ICMP type 3, code 13 (admin-prohibited)."""
        # Apply the standard-mode firewall.
        pid = subprocess.run(
            ["podman", "inspect", "--format", "{{.State.Pid}}", probe_container],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        r = nsenter_nft(pid, stdin=standard_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"

        result = self._run_probe(probe_container, BLOCKED_TARGET_IP)
        assert result["result"] == "icmp-error", f"Expected icmp-error, got: {result}"
        assert result["icmp_type"] == 3, f"Expected ICMP type 3, got: {result}"
        assert result["icmp_code"] == 13, f"Expected ICMP code 13, got: {result}"
        assert result["icmp_code_name"] == "admin-prohibited"

    def test_allowed_ip_is_open(self, probe_container: str) -> None:
        """Without a firewall, probe reports open/timeout (not icmp-error)."""
        result = self._run_probe(probe_container, ALLOWED_TARGET_IPS[0], port=53)
        assert result["result"] != "icmp-error", f"Unexpected ICMP error: {result}"


# ── Firewall enforcement: allowing ──────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestFirewallAllowing:
    """Verify that IPs added to the allow set can be reached."""

    def test_allowed_ip_reachable_http(self, container: str, container_pid: str) -> None:
        """HTTP traffic to an allowed IP is permitted."""

        r = nsenter_nft(container_pid, stdin=standard_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"
        r = nsenter_nft(container_pid, stdin=add_elements("allow_v4", ALLOWED_TARGET_IPS))
        assert r.returncode == 0, f"Add elements failed: {r.stderr}"

        post = _wget(container, ALLOWED_TARGET_HTTP, timeout=10)
        assert post.returncode == 0, f"Allowed IP should be reachable via HTTP: {post.stderr}"

    def test_allowed_ip_reachable_https(self, container: str, container_pid: str) -> None:
        """HTTPS traffic to an allowed IP is permitted."""

        r = nsenter_nft(container_pid, stdin=standard_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"
        r = nsenter_nft(container_pid, stdin=add_elements("allow_v4", ALLOWED_TARGET_IPS))
        assert r.returncode == 0, f"Add elements failed: {r.stderr}"

        post = _wget(container, ALLOWED_TARGET_HTTPS, timeout=10)
        assert post.returncode == 0, f"Allowed IP should be reachable via HTTPS: {post.stderr}"

    def test_non_allowed_ip_still_blocked(self, container: str, container_pid: str) -> None:
        """IPs not in the allow set remain blocked after adding others."""

        r = nsenter_nft(container_pid, stdin=standard_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"
        r = nsenter_nft(container_pid, stdin=add_elements("allow_v4", ALLOWED_TARGET_IPS))
        assert r.returncode == 0, f"Add elements failed: {r.stderr}"

        blocked = _wget(container, BLOCKED_TARGET_HTTP, timeout=10)
        assert blocked.returncode != 0, "Non-allowed IP should be blocked"

    def test_allow_then_block_different_targets(self, container: str, container_pid: str) -> None:
        """One IP allowed, another blocked — in the same container."""

        r = nsenter_nft(container_pid, stdin=standard_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"
        r = nsenter_nft(container_pid, stdin=add_elements("allow_v4", ALLOWED_TARGET_IPS))
        assert r.returncode == 0, f"Add elements failed: {r.stderr}"

        allowed = _wget(container, ALLOWED_TARGET_HTTP, timeout=10)
        blocked = _wget(container, BLOCKED_TARGET_HTTP, timeout=10)
        assert allowed.returncode == 0, "Allowed IP should pass"
        assert blocked.returncode != 0, "Non-allowed IP should be rejected"


# ── Add-elements integration ────────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestAddElementsLive:
    """Verify add_elements works with real nft."""

    def test_elements_appear_in_set(self, container: str, container_pid: str) -> None:
        """IPs added via add_elements appear in 'nft list set'."""
        r = nsenter_nft(container_pid, stdin=standard_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"
        r = nsenter_nft(container_pid, stdin=add_elements("allow_v4", [TEST_IP1]))
        assert r.returncode == 0, f"Add elements failed: {r.stderr}"

        listed = nsenter_nft(container_pid, "list", "set", "inet", "terok_shield", "allow_v4")
        assert listed.returncode == 0
        assert TEST_IP1 in listed.stdout

    def test_multiple_elements(self, container: str, container_pid: str) -> None:
        """Multiple IPs can be added to the set."""
        ips = [*ALLOWED_TARGET_IPS, GOOGLE_DNS_IP, QUAD9_DNS_IP]
        r = nsenter_nft(container_pid, stdin=standard_ruleset())
        assert r.returncode == 0, f"Ruleset apply failed: {r.stderr}"
        r = nsenter_nft(container_pid, stdin=add_elements("allow_v4", ips))
        assert r.returncode == 0, f"Add elements failed: {r.stderr}"

        listed = nsenter_nft(container_pid, "list", "set", "inet", "terok_shield", "allow_v4")
        assert listed.returncode == 0
        for ip in ips:
            assert ip in listed.stdout


# ── apply_hook end-to-end ────────────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestApplyHookE2E:
    """End-to-end test of the OCI hook entry point."""

    def test_apply_hook_creates_firewall(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """apply_hook applies the ruleset and passes verification."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            apply_hook(container, container_pid)

            listed = nsenter_nft(container_pid, "list", "ruleset")
            assert listed.returncode == 0
            assert "terok_shield" in listed.stdout
            errors = verify_ruleset(listed.stdout)
            assert errors == [], f"Verification errors: {errors}"

    def test_apply_hook_with_pre_resolved_ips(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """apply_hook loads pre-resolved IPs from the cache file."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)

            resolved_dir = Path(tmp) / "resolved"
            resolved_dir.mkdir(parents=True)
            resolved_ips = [*ALLOWED_TARGET_IPS, GOOGLE_DNS_IP]
            (resolved_dir / f"{container}.resolved").write_text("\n".join(resolved_ips) + "\n")

            apply_hook(container, container_pid)

            listed = nsenter_nft(container_pid, "list", "set", "inet", "terok_shield", "allow_v4")
            assert listed.returncode == 0
            for ip in resolved_ips:
                assert ip in listed.stdout

    def test_apply_hook_blocks_traffic(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After apply_hook, outbound traffic is blocked."""

        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            apply_hook(container, container_pid)

        post = _wget(container, ALLOWED_TARGET_HTTP, timeout=10)
        assert post.returncode != 0, "Traffic should be blocked after apply_hook"

    def test_apply_hook_allows_pre_resolved(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After apply_hook with pre-resolved IPs, those IPs are reachable."""

        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)

            resolved_dir = Path(tmp) / "resolved"
            resolved_dir.mkdir(parents=True)
            (resolved_dir / f"{container}.resolved").write_text(
                "\n".join(ALLOWED_TARGET_IPS) + "\n"
            )

            apply_hook(container, container_pid)

        # Allowed IP should be reachable
        allowed = _wget(container, ALLOWED_TARGET_HTTP, timeout=10)
        assert allowed.returncode == 0, f"Pre-resolved IP should be reachable: {allowed.stderr}"

        # Non-allowed IP should still be blocked
        blocked = _wget(container, BLOCKED_TARGET_HTTP, timeout=10)
        assert blocked.returncode != 0, "Non-allowed IP should be blocked"

    def test_apply_hook_fail_closed_bad_pid(
        self, container: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """apply_hook raises RuntimeError for an invalid PID."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            with pytest.raises(RuntimeError):
                apply_hook(container, "999999")

    def test_reapply_after_flush(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Flushing and re-applying the hook produces a valid ruleset."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)

            # First apply
            apply_hook(container, container_pid)
            listed = nsenter_nft(container_pid, "list", "ruleset")
            assert "terok_shield" in listed.stdout

            # Flush
            nsenter_nft(container_pid, "flush", "ruleset")
            listed = nsenter_nft(container_pid, "list", "ruleset")
            assert "terok_shield" not in listed.stdout

            # Re-apply
            apply_hook(container, container_pid)
            listed = nsenter_nft(container_pid, "list", "ruleset")
            assert "terok_shield" in listed.stdout
            errors = verify_ruleset(listed.stdout)
            assert errors == [], f"Re-apply verification failed: {errors}"


# ── apply_hook audit trail ────────────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestApplyHookAudit:
    """Verify apply_hook produces JSONL audit entries."""

    def test_apply_hook_produces_audit_trail(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """apply_hook writes per-step JSONL audit entries."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            apply_hook(container, container_pid)

            log_file = Path(tmp) / "logs" / f"{container}.jsonl"
            assert log_file.is_file(), "Audit log must be created"
            entries = [json.loads(line) for line in log_file.read_text().splitlines()]
            details = [e.get("detail", "") for e in entries]
            assert any("ruleset applied" in d for d in details)
            assert any("cached IPs" in d for d in details)
            assert any("verification passed" in d for d in details)
            assert any("applied with" in d for d in details)
            # All entries must have required fields
            for entry in entries:
                assert "ts" in entry
                assert "container" in entry
                assert entry["container"] == container

    def test_apply_hook_audit_with_pre_resolved_ips(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Audit entries include actual resolved IPs."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            resolved_dir = Path(tmp) / "resolved"
            resolved_dir.mkdir(parents=True)
            resolved_ips = ALLOWED_TARGET_IPS
            (resolved_dir / f"{container}.resolved").write_text("\n".join(resolved_ips) + "\n")

            apply_hook(container, container_pid)

            log_file = Path(tmp) / "logs" / f"{container}.jsonl"
            entries = [json.loads(line) for line in log_file.read_text().splitlines()]
            details = [e.get("detail", "") for e in entries]
            # IPs must appear in the tagged detail lines
            assert any("[ips] cached:" in d and resolved_ips[0] in d for d in details)
            assert any("[ips] added to allow_v4:" in d and resolved_ips[0] in d for d in details)

    def test_apply_hook_audit_on_failure(
        self, container: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bad PID produces an 'error' audit entry."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            with pytest.raises(RuntimeError):
                apply_hook(container, "999999")

            log_file = Path(tmp) / "logs" / f"{container}.jsonl"
            assert log_file.is_file(), "Audit log must be created even on failure"
            entries = [json.loads(line) for line in log_file.read_text().splitlines()]
            assert any(e.get("action") == "error" for e in entries)


# ── hook_main end-to-end ─────────────────────────────────


@pytest.mark.needs_podman
@pytest.mark.needs_internet
@podman_missing
@nft_missing
@pytest.mark.usefixtures("nft_in_netns")
class TestHookMainE2E:
    """End-to-end test of hook_main (the OCI hook entry point)."""

    def test_hook_main_success(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """hook_main returns 0 on success and applies the firewall."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)

            oci_state = json.dumps({"id": container, "pid": int(container_pid)})
            rc = hook_main(oci_state)
            assert rc == 0

            listed = nsenter_nft(container_pid, "list", "ruleset")
            assert "terok_shield" in listed.stdout

    def test_hook_main_invalid_json(self) -> None:
        """hook_main returns 1 for invalid OCI state."""
        rc = hook_main("not json")
        assert rc == 1

    def test_hook_main_bad_pid(self, container: str, monkeypatch: pytest.MonkeyPatch) -> None:
        """hook_main returns 1 for unreachable PID."""
        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)
            oci_state = json.dumps({"id": container, "pid": 999999})
            rc = hook_main(oci_state)
            assert rc == 1

    def test_hook_main_with_pre_resolved_blocks_and_allows(
        self, container: str, container_pid: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Full lifecycle: OCI state → hook_main → traffic filtered."""

        with tempfile.TemporaryDirectory() as tmp:
            monkeypatch.setenv("TEROK_SHIELD_STATE_DIR", tmp)

            # Pre-resolve: allow Cloudflare anycast pair only
            resolved_dir = Path(tmp) / "resolved"
            resolved_dir.mkdir(parents=True)
            (resolved_dir / f"{container}.resolved").write_text(
                "\n".join(ALLOWED_TARGET_IPS) + "\n"
            )

            oci_state = json.dumps({"id": container, "pid": int(container_pid)})
            rc = hook_main(oci_state)
            assert rc == 0

        # Allowed target reachable
        allowed = _wget(container, ALLOWED_TARGET_HTTP, timeout=10)
        assert allowed.returncode == 0, "Pre-resolved IP should be reachable"

        # Non-allowed target blocked
        blocked = _wget(container, BLOCKED_TARGET_HTTP, timeout=10)
        assert blocked.returncode != 0, "Non-allowed IP should be blocked"
