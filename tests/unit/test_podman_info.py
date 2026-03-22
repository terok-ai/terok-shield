# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Tests for podman environment detection."""

import json
from pathlib import Path

import pytest

from terok_shield.podman_info import (
    HOOK_JSON_FILENAME,
    _parse_hooks_dir_from_conf,
    _parse_version,
    ensure_containers_conf_hooks_dir,
    find_hooks_dirs,
    global_hooks_hint,
    has_global_hooks,
    parse_podman_info,
    parse_proc_net_route,
    parse_resolv_conf,
    system_hooks_dir,
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

# Debian 12 — podman 4.3.1, slirp4netns only, no pasta at all
DEBIAN_12_INFO = {
    "host": {
        "slirp4netns": {
            "executable": "/usr/bin/slirp4netns",
            "package": "slirp4netns_1.2.0-1_amd64",
        },
    },
    "version": {"Version": "4.3.1"},
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


# ── parse_resolv_conf tests ──────────────────────────────


class TestParseProcNetRoute:
    """Tests for /proc/net/route gateway parsing."""

    def test_slirp4netns_default(self) -> None:
        """Standard slirp4netns default route (10.0.2.2)."""
        text = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "tap0\t00000000\t0202000A\t0003\t0\t0\t0\t00000000\n"
            "tap0\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
        )
        assert parse_proc_net_route(text) == "10.0.2.2"

    def test_custom_cidr(self) -> None:
        """Custom CIDR (192.168.42.0/24) gateway is 192.168.42.2."""
        # 192.168.42.2 = 0xC0A82A02, in little-endian hex: 022AA8C0
        text = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "tap0\t00000000\t022AA8C0\t0003\t0\t0\t0\t00000000\n"
        )
        assert parse_proc_net_route(text) == "192.168.42.2"

    def test_no_default_route(self) -> None:
        """No default route returns empty string (e.g. pasta mode)."""
        text = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "eth0\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
        )
        assert parse_proc_net_route(text) == ""

    def test_empty_input(self) -> None:
        """Empty input returns empty string."""
        assert parse_proc_net_route("") == ""

    def test_header_only(self) -> None:
        """Header-only input returns empty string."""
        text = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
        assert parse_proc_net_route(text) == ""


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

    def test_warns_when_different_hooks_dir_configured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Warns and does not modify when hooks_dir is already set differently."""
        conf = tmp_path / "containers.conf"
        conf.write_text('[engine]\nhooks_dir = ["/other/hooks"]\n')
        monkeypatch.setattr("terok_shield.podman_info._user_containers_conf", lambda: conf)
        ensure_containers_conf_hooks_dir(Path("/my/hooks"))
        assert "Warning" in capsys.readouterr().out
        assert conf.read_text().count("hooks_dir") == 1  # unchanged


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


# ── _parse_hooks_dir_from_conf edge cases ────────────────


class TestParseHooksDirFromConf:
    """Tests for containers.conf hooks_dir parsing."""

    def test_hooks_dir_as_string(self, tmp_path: Path) -> None:
        """hooks_dir as a bare string (not list)."""
        conf = tmp_path / "containers.conf"
        conf.write_text('[engine]\nhooks_dir = "/single/path"\n')
        assert _parse_hooks_dir_from_conf(conf) == ["/single/path"]

    def test_hooks_dir_missing(self, tmp_path: Path) -> None:
        """No hooks_dir key returns empty."""
        conf = tmp_path / "containers.conf"
        conf.write_text('[engine]\nfoo = "bar"\n')
        assert _parse_hooks_dir_from_conf(conf) == []

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        """Nonexistent file returns empty."""
        assert _parse_hooks_dir_from_conf(tmp_path / "nope.conf") == []

    def test_invalid_toml(self, tmp_path: Path) -> None:
        """Invalid TOML returns empty."""
        conf = tmp_path / "containers.conf"
        conf.write_text("not valid toml {{{\n")
        assert _parse_hooks_dir_from_conf(conf) == []

    def test_hooks_dir_empty_list(self, tmp_path: Path) -> None:
        """Empty hooks_dir list returns empty."""
        conf = tmp_path / "containers.conf"
        conf.write_text("[engine]\nhooks_dir = []\n")
        assert _parse_hooks_dir_from_conf(conf) == []


# ── system_hooks_dir tests ───────────────────────────────


class TestSystemHooksDir:
    """Tests for system hooks directory detection."""

    def test_returns_existing_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returns an existing system dir when available."""
        d = tmp_path / "hooks.d"
        d.mkdir()
        monkeypatch.setattr("terok_shield.podman_info._SYSTEM_HOOKS_DIRS", (d,))
        assert system_hooks_dir() == d

    def test_fallback_when_none_exist(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Falls back to last entry when no system dir exists."""
        monkeypatch.setattr(
            "terok_shield.podman_info._SYSTEM_HOOKS_DIRS",
            (Path("/nonexistent/a"), Path("/nonexistent/b")),
        )
        assert system_hooks_dir() == Path("/nonexistent/b")


# ── global_hooks_hint tests ──────────────────────────────


class TestGlobalHooksHint:
    """Tests for the setup hint message."""

    def test_contains_setup_command(self) -> None:
        """Hint mentions terok-shield setup."""
        assert "terok-shield setup" in global_hooks_hint()

    def test_contains_reference(self) -> None:
        """Hint includes the podman issue reference."""
        assert "17935" in global_hooks_hint()


# ── find_hooks_dirs system conf path ─────────────────────


class TestFindHooksDirsSystemConf:
    """Test system-level containers.conf parsing in find_hooks_dirs."""

    def test_system_conf_used_when_no_user_conf(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """System containers.conf is used when user config absent."""
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no-user"))
        sys_conf = tmp_path / "system.conf"
        sys_conf.write_text('[engine]\nhooks_dir = ["/sys/hooks"]\n')
        monkeypatch.setattr("terok_shield.podman_info._SYSTEM_CONF_PATHS", (sys_conf,))
        monkeypatch.setattr("terok_shield.podman_info._SYSTEM_HOOKS_DIRS", ())
        dirs = find_hooks_dirs()
        assert dirs == [Path("/sys/hooks")]
