# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for podman environment detection."""

import json
from pathlib import Path

import pytest

from terok_shield.podman_info import (
    HOOK_JSON_FILENAME,
    find_hooks_dirs,
    has_global_hooks,
    parse_podman_info,
    parse_resolv_conf,
)

# ── Real podman info samples (from actual machines) ───────

# Ubuntu 24.04 — podman 4.9.3, slirp4netns default, no rootlessNetworkCmd
UBUNTU_2404_INFO = {
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
DEBIAN_13_INFO = {
    "host": {
        "rootlessNetworkCmd": "pasta",
        "pasta": {"executable": "/usr/bin/pasta"},
        "slirp4netns": {"executable": "/usr/bin/slirp4netns"},
    },
    "version": {"Version": "5.4.2"},
}

# Fedora 43 — podman 5.8.0, pasta default, slirp4netns not installed
FEDORA_43_INFO = {
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

    def test_podman_560_persistent(self) -> None:
        """podman 5.6.0 → hooks-dir persists."""
        data = {"host": {}, "version": {"Version": "5.6.0"}}
        info = parse_podman_info(json.dumps(data))
        assert info.hooks_dir_persists

    def test_podman_580_persistent(self) -> None:
        """podman 5.8.0 → hooks-dir persists."""
        info = parse_podman_info(json.dumps(FEDORA_43_INFO))
        assert info.hooks_dir_persists


# ── parse_resolv_conf tests ──────────────────────────────


class TestParseResolvConf:
    """Tests for resolv.conf nameserver parsing."""

    def test_standard_resolv_conf(self) -> None:
        """Standard resolv.conf with one nameserver."""
        text = "# Generated by NetworkManager\nnameserver 10.0.2.3\n"
        assert parse_resolv_conf(text) == "10.0.2.3"

    def test_pasta_dns(self) -> None:
        """Pasta-generated resolv.conf with link-local DNS."""
        text = "nameserver 169.254.1.1\n"
        assert parse_resolv_conf(text) == "169.254.1.1"

    def test_multiple_nameservers_returns_first(self) -> None:
        """Multiple nameservers → returns the first one."""
        text = "nameserver 10.0.2.3\nnameserver 8.8.8.8\n"
        assert parse_resolv_conf(text) == "10.0.2.3"

    def test_empty_file(self) -> None:
        """Empty file → empty string."""
        assert parse_resolv_conf("") == ""

    def test_no_nameserver(self) -> None:
        """File with only comments → empty string."""
        text = "# comment\nsearch example.com\n"
        assert parse_resolv_conf(text) == ""

    def test_comments_and_whitespace(self) -> None:
        """Nameserver after comments and whitespace."""
        text = "# DNS\n\n  nameserver 10.0.2.3  \n"
        assert parse_resolv_conf(text) == "10.0.2.3"


# ── find_hooks_dirs tests ────────────────────────────────


class TestFindHooksDirs:
    """Tests for hooks directory detection."""

    def test_user_conf_takes_precedence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """User-level containers.conf hooks_dir overrides system config."""
        user_conf = tmp_path / "user" / "containers" / "containers.conf"
        user_conf.parent.mkdir(parents=True)
        user_conf.write_text('[engine]\nhooks_dir = ["/user/hooks"]\n')
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "user"))

        # Patch system paths to avoid real filesystem interference
        monkeypatch.setattr(
            "terok_shield.podman_info._SYSTEM_CONF_PATHS", (tmp_path / "nonexistent",)
        )
        monkeypatch.setattr("terok_shield.podman_info._SYSTEM_HOOKS_DIRS", ())

        dirs = find_hooks_dirs()
        assert dirs == [Path("/user/hooks")]

    def test_falls_back_to_system_dirs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Falls back to existing system dirs when no config."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no-config"))
        monkeypatch.setattr(
            "terok_shield.podman_info._SYSTEM_CONF_PATHS", (tmp_path / "nonexistent",)
        )
        system_dir = tmp_path / "system-hooks"
        system_dir.mkdir()
        monkeypatch.setattr("terok_shield.podman_info._SYSTEM_HOOKS_DIRS", (system_dir,))

        dirs = find_hooks_dirs()
        assert dirs == [system_dir]


# ── has_global_hooks tests ───────────────────────────────


class TestHasGlobalHooks:
    """Tests for global hooks detection."""

    def test_hook_found(self, tmp_path: Path) -> None:
        """Returns True when hook JSON exists in a hooks dir."""
        hooks_dir = tmp_path / "hooks"
        hooks_dir.mkdir()
        (hooks_dir / HOOK_JSON_FILENAME).write_text("{}")
        assert has_global_hooks([hooks_dir])

    def test_hook_not_found(self, tmp_path: Path) -> None:
        """Returns False when hooks dir is empty."""
        hooks_dir = tmp_path / "hooks"
        hooks_dir.mkdir()
        assert not has_global_hooks([hooks_dir])

    def test_empty_dirs_list(self) -> None:
        """Returns False with no dirs to check."""
        assert not has_global_hooks([])


# ── ensure_containers_conf_hooks_dir tests ───────────────

from terok_shield.podman_info import ensure_containers_conf_hooks_dir


class TestEnsureContainersConf:
    """Tests for containers.conf modification."""

    def test_creates_new_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Creates containers.conf when absent."""
        conf_dir = tmp_path / "containers"
        monkeypatch.setattr(
            "terok_shield.podman_info._user_containers_conf", lambda: conf_dir / "containers.conf"
        )
        ensure_containers_conf_hooks_dir(Path("/my/hooks"))
        text = (conf_dir / "containers.conf").read_text()
        assert 'hooks_dir = ["/my/hooks"]' in text
        assert text.count("[engine]") == 1

    def test_inserts_into_existing_engine_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Inserts hooks_dir into existing [engine] without duplicating the section."""
        conf = tmp_path / "containers.conf"
        conf.write_text('[engine]\nimage_copy_tmp_dir = "/data/tmp"\n')
        monkeypatch.setattr("terok_shield.podman_info._user_containers_conf", lambda: conf)
        ensure_containers_conf_hooks_dir(Path("/my/hooks"))
        text = conf.read_text()
        assert text.count("[engine]") == 1
        assert 'hooks_dir = ["/my/hooks"]' in text
        assert 'image_copy_tmp_dir = "/data/tmp"' in text

    def test_preserves_comments(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Comments in the file are preserved."""
        conf = tmp_path / "containers.conf"
        conf.write_text('# My config\n[engine]\n# temp dir\nimage_copy_tmp_dir = "/data"\n')
        monkeypatch.setattr("terok_shield.podman_info._user_containers_conf", lambda: conf)
        ensure_containers_conf_hooks_dir(Path("/my/hooks"))
        text = conf.read_text()
        assert "# My config" in text
        assert "# temp dir" in text

    def test_ignores_engine_in_comment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Does not match [engine] inside a comment."""
        conf = tmp_path / "containers.conf"
        conf.write_text('# see [engine] docs\n[engine]\nfoo = "bar"\n')
        monkeypatch.setattr("terok_shield.podman_info._user_containers_conf", lambda: conf)
        ensure_containers_conf_hooks_dir(Path("/my/hooks"))
        text = conf.read_text()
        assert text.count("[engine]") == 2  # one in comment, one real
        assert text.count("hooks_dir") == 1

    def test_skips_if_already_configured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No-op when hooks_dir already points to the right path."""
        conf = tmp_path / "containers.conf"
        conf.write_text('[engine]\nhooks_dir = ["/my/hooks"]\n')
        monkeypatch.setattr("terok_shield.podman_info._user_containers_conf", lambda: conf)
        ensure_containers_conf_hooks_dir(Path("/my/hooks"))
        assert conf.read_text().count("hooks_dir") == 1

    def test_appends_engine_when_no_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Appends [engine] section when file exists but has no [engine]."""
        conf = tmp_path / "containers.conf"
        conf.write_text("[containers]\nlabel = false\n")
        monkeypatch.setattr("terok_shield.podman_info._user_containers_conf", lambda: conf)
        ensure_containers_conf_hooks_dir(Path("/my/hooks"))
        text = conf.read_text()
        assert "[containers]" in text
        assert "[engine]" in text
        assert 'hooks_dir = ["/my/hooks"]' in text
