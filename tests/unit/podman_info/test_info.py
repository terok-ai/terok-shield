# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``terok_shield.podman_info.info`` — version + capability parsing."""

import json

from terok_shield.podman_info.info import _parse_version, parse_podman_info

# ── Real podman info samples (from actual machines) ───────

# Ubuntu 24.04 — podman 4.9.3, slirp4netns default, no rootlessNetworkCmd
UBUNTU_2404_INFO: dict[str, object] = {
    "host": {
        "pasta": {"executable": "/usr/bin/pasta", "package": "passt_0.0~git20240220"},
        "slirp4netns": {
            "executable": "/usr/bin/slirp4netns",
            "package": "slirp4netns_1.2.1-1build2_amd64",
        },
    },
    "version": {"Version": "4.9.3"},
}

# Debian 13 — podman 5.4.2, pasta default, rootlessNetworkCmd present
DEBIAN_13_INFO: dict[str, object] = {
    "host": {
        "rootlessNetworkCmd": "pasta",
        "pasta": {"executable": "/usr/bin/pasta"},
        "slirp4netns": {"executable": "/usr/bin/slirp4netns"},
    },
    "version": {"Version": "5.4.2"},
}

# Debian 12 — podman 4.3.1, slirp4netns only, no pasta at all
DEBIAN_12_INFO: dict[str, object] = {
    "host": {
        "slirp4netns": {
            "executable": "/usr/bin/slirp4netns",
            "package": "slirp4netns_1.2.0-1_amd64",
        },
    },
    "version": {"Version": "4.3.1"},
}

# Fedora 43 — podman 5.8.0, pasta default, slirp4netns not installed
FEDORA_43_INFO: dict[str, object] = {
    "host": {
        "rootlessNetworkCmd": "pasta",
        "pasta": {"executable": "/usr/bin/pasta"},
        "slirp4netns": {"executable": "", "package": "", "version": ""},
    },
    "version": {"Version": "5.8.0"},
}


# ── parse_podman_info tests ──────────────────────────────


class TestParsePodmanInfo:
    """Tests for parse_podman_info()."""

    def test_ubuntu_2404(self) -> None:
        """Ubuntu 24.04 (podman 4.9.3) — no rootlessNetworkCmd."""
        info = parse_podman_info(json.dumps(UBUNTU_2404_INFO))
        assert info.version == (4, 9, 3)
        assert info.rootless_network_cmd == ""
        assert info.pasta_executable == "/usr/bin/pasta"
        assert info.slirp4netns_executable == "/usr/bin/slirp4netns"

    def test_debian_13(self) -> None:
        """Debian 13 (podman 5.4.2) — pasta via rootlessNetworkCmd."""
        info = parse_podman_info(json.dumps(DEBIAN_13_INFO))
        assert info.version == (5, 4, 2)
        assert info.rootless_network_cmd == "pasta"

    def test_fedora_43(self) -> None:
        """Fedora 43 (podman 5.8.0) — pasta, slirp4netns not installed."""
        info = parse_podman_info(json.dumps(FEDORA_43_INFO))
        assert info.version == (5, 8, 0)
        assert info.rootless_network_cmd == "pasta"
        assert info.slirp4netns_executable == ""

    def test_debian_12(self) -> None:
        """Debian 12 (podman 4.3.1) — slirp4netns only, no pasta section."""
        info = parse_podman_info(json.dumps(DEBIAN_12_INFO))
        assert info.version == (4, 3, 1)
        assert info.rootless_network_cmd == ""
        assert info.pasta_executable == ""
        assert info.slirp4netns_executable == "/usr/bin/slirp4netns"

    def test_empty_output(self) -> None:
        """Empty output produces zero-version fallback."""
        info = parse_podman_info("")
        assert info.version == (0,)
        assert info.rootless_network_cmd == ""

    def test_invalid_json(self) -> None:
        """Invalid JSON produces zero-version fallback."""
        info = parse_podman_info("not json")
        assert info.version == (0,)


# ── PodmanInfo.network_mode tests ────────────────────────


class TestNetworkMode:
    """Tests for PodmanInfo.network_mode detection logic."""

    def test_explicit_pasta(self) -> None:
        """rootlessNetworkCmd=pasta → pasta."""
        info = parse_podman_info(json.dumps(DEBIAN_13_INFO))
        assert info.network_mode == "pasta"

    def test_explicit_slirp4netns(self) -> None:
        """rootlessNetworkCmd=slirp4netns → slirp4netns."""
        data = {"host": {"rootlessNetworkCmd": "slirp4netns"}, "version": {"Version": "5.0.0"}}
        info = parse_podman_info(json.dumps(data))
        assert info.network_mode == "slirp4netns"

    def test_absent_field_with_slirp_exe(self) -> None:
        """No rootlessNetworkCmd + slirp4netns exe available → slirp4netns (podman 4.x)."""
        info = parse_podman_info(json.dumps(UBUNTU_2404_INFO))
        assert info.network_mode == "slirp4netns"

    def test_no_pasta_section_at_all(self) -> None:
        """No pasta section in podman info (Debian 12) -> slirp4netns."""
        info = parse_podman_info(json.dumps(DEBIAN_12_INFO))
        assert info.network_mode == "slirp4netns"

    def test_absent_field_without_slirp_exe(self) -> None:
        """No rootlessNetworkCmd + no slirp4netns exe → pasta."""
        data = {
            "host": {"pasta": {"executable": "/usr/bin/pasta"}, "slirp4netns": {"executable": ""}},
            "version": {"Version": "4.0.0"},
        }
        info = parse_podman_info(json.dumps(data))
        assert info.network_mode == "pasta"

    def test_empty_output_defaults_to_pasta(self) -> None:
        """Unparseable output → pasta (last resort fallback)."""
        info = parse_podman_info("")
        assert info.network_mode == "pasta"


# ── PodmanInfo.hooks_dir_persists tests ──────────────────


class TestHooksDirPersists:
    """Tests for hooks-dir persistence version gate."""

    def test_podman_493_not_persistent(self) -> None:
        """podman 4.9.3 → hooks-dir does NOT persist."""
        info = parse_podman_info(json.dumps(UBUNTU_2404_INFO))
        assert not info.hooks_dir_persists

    def test_podman_542_not_persistent(self) -> None:
        """podman 5.4.2 → hooks-dir does NOT persist."""
        info = parse_podman_info(json.dumps(DEBIAN_13_INFO))
        assert not info.hooks_dir_persists

    def test_podman_431_not_persistent(self) -> None:
        """podman 4.3.1 -> hooks-dir does NOT persist."""
        info = parse_podman_info(json.dumps(DEBIAN_12_INFO))
        assert not info.hooks_dir_persists

    def test_podman_560_not_persistent(self) -> None:
        """podman 5.6.0 → hooks-dir does NOT persist (version gate raised, #122)."""
        data = {"host": {}, "version": {"Version": "5.6.0"}}
        info = parse_podman_info(json.dumps(data))
        assert not info.hooks_dir_persists

    def test_podman_580_not_persistent(self) -> None:
        """podman 5.8.0 → hooks-dir does NOT persist (version gate raised, #122)."""
        info = parse_podman_info(json.dumps(FEDORA_43_INFO))
        assert not info.hooks_dir_persists


# ── _parse_version edge cases ────────────────────────────


class TestParseVersion:
    """Tests for version string parsing."""

    def test_normal_version(self) -> None:
        """Standard 3-part version."""
        assert _parse_version("5.4.2") == (5, 4, 2)

    def test_two_part_version(self) -> None:
        """Two-part version."""
        assert _parse_version("5.4") == (5, 4)

    def test_version_with_suffix(self) -> None:
        """Version with prerelease suffix extracts leading digits."""
        # "5.4.2-beta1" → each part's leading digits: 5, 4, 2
        assert _parse_version("5.4.2-beta1") == (5, 4, 2)

    def test_version_rc(self) -> None:
        """Release candidate version preserves all components."""
        assert _parse_version("5.6.0-rc1") == (5, 6, 0)

    def test_empty_string(self) -> None:
        """Empty string returns (0,)."""
        assert _parse_version("") == (0,)

    def test_non_numeric(self) -> None:
        """Completely non-numeric returns (0,)."""
        assert _parse_version("abc") == (0,)
