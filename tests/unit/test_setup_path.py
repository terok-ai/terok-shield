# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Owned setup and actual standalone hook bootstrap, without container execution."""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest
from terok_util import SetupDowngradeError, SetupRequiredError, SetupStatus, setup_status

from terok_shield.hooks.install import HooksInstaller
from terok_shield.paths import reader_script_path
from terok_shield.resources._oci_state import BUNDLE_VERSION


def _tools(directory: Path) -> None:
    """Write harmless executable stand-ins for every required host tool."""
    directory.mkdir()
    scripts = {
        "nft": "",
        "nsenter": "import json, os, sys\nfrom pathlib import Path\nPath(os.environ['TRACE']).write_text(json.dumps(sys.argv))\n",
        "podman": "import os, sys\nos.execv(sys.argv[2], sys.argv[2:])\n",
    }
    for name, source in scripts.items():
        binary = directory / name
        binary.write_text(f"#!{sys.executable}\n{source}")
        binary.chmod(0o755)


@pytest.fixture
def installer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HooksInstaller:
    """Provide a real installation isolated from the user's files and tools."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
    monkeypatch.setattr(
        "terok_shield.hooks.install._user_containers_conf", lambda: tmp_path / "containers.conf"
    )
    binaries = tmp_path / "first-bin"
    _tools(binaries)
    monkeypatch.setenv("PATH", str(binaries))
    return HooksInstaller(target_dir=tmp_path / "shield" / "hooks")


def test_receipt_is_owned_and_outside_scanned_directory(installer: HooksInstaller) -> None:
    """Setup certifies only Shield, with a receipt outside Podman's hook scan."""
    assert setup_status(installer.check_setup()) != SetupStatus.READY
    installer.install()
    assert setup_status(installer.check_setup(live=True)) == SetupStatus.READY
    receipt = installer.target_dir.parent / "setup.json"
    assert json.loads(receipt.read_text())["owner"] == "terok-shield"
    assert not (installer.target_dir / "setup.json").exists()


@pytest.mark.parametrize("damage", ["descriptor", "helper", "reader", "python"])
def test_changed_artifacts_require_setup(
    installer: HooksInstaller, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    """Missing resources and changed interpreter identity cannot reuse a receipt."""
    installer.install()
    if damage == "descriptor":
        (installer.target_dir / "terok-shield-createRuntime.json").write_text("{}")
    elif damage == "helper":
        (installer.target_dir / "_host_tools.py").unlink()
    elif damage == "reader":
        reader_script_path().unlink()
    else:
        monkeypatch.setattr("terok_shield.hooks.install.python_identity", lambda: "changed")
    assert setup_status(installer.check_setup()) == SetupStatus.STALE


def test_live_missing_tools_do_not_invalidate_good_setup(
    installer: HooksInstaller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PATH changes are launch inputs, not reason to silently reinstall hooks."""
    installer.install()
    receipt = (installer.target_dir.parent / "setup.json").read_bytes()
    monkeypatch.setenv("PATH", "")
    assert setup_status(installer.check_setup()) == SetupStatus.READY
    assert setup_status(installer.check_setup(live=True)) == SetupStatus.MISSING
    with pytest.raises(SetupRequiredError, match="PATH"):
        installer.install()
    assert (installer.target_dir.parent / "setup.json").read_bytes() == receipt


def test_downgrade_preflight_writes_nothing(installer: HooksInstaller) -> None:
    """Newer receipts stop even bootstrap rewrites before the first mutation."""
    installer.install()
    receipt = installer.target_dir.parent / "setup.json"
    stored = json.loads(receipt.read_text())
    stored["version"] = "999.0"
    receipt.write_text(json.dumps(stored))
    with mock.patch("terok_shield.hooks.install.install_reader_resource") as write:
        with pytest.raises(SetupDowngradeError):
            installer.install()
        write.assert_not_called()
    assert json.loads(receipt.read_text())["version"] == "999.0"


def test_failed_install_cannot_certify_setup(installer: HooksInstaller) -> None:
    """A previously ready receipt is invalidated before replacement work starts."""
    installer.install()
    with mock.patch("terok_shield.hooks.install._write_role_files", side_effect=OSError("full")):
        with pytest.raises(OSError, match="full"):
            installer.install()
    assert not (installer.target_dir.parent / "setup.json").exists()


@pytest.mark.parametrize("path_mode", ["inherited", "absent", "empty"])
def test_bare_hook_resolves_fresh_path_without_installed_packages(
    installer: HooksInstaller, tmp_path: Path, path_mode: str
) -> None:
    """The actual installed descriptor works without package imports or FHS binaries."""
    installer.install()
    descriptor = json.loads((installer.target_dir / "terok-shield-createRuntime.json").read_text())[
        "hook"
    ]
    assert descriptor["path"] == sys.executable
    assert descriptor["args"][:2] == [sys.executable, "-I"]
    state = tmp_path / "task"
    state.mkdir(mode=0o700)
    (state / "ruleset.nft").write_text("table inet terok_shield {}")
    payload = {
        "pid": os.getpid(),
        "annotations": {
            "terok.shield.state_dir": str(state),
            "terok.shield.version": str(BUNDLE_VERSION),
        },
    }
    for binary_dir in (tmp_path / "second-bin", tmp_path / "third-bin"):
        _tools(binary_dir)
        trace = tmp_path / "trace"
        trace.unlink(missing_ok=True)
        env = {
            "TRACE": str(trace),
            "PYTHONPATH": str(tmp_path / "nonexistent-packages"),
            "PYTHONHOME": str(tmp_path / "missing-python"),
        }
        if path_mode != "absent":
            env["PATH"] = str(binary_dir) if path_mode == "inherited" else ""
        run = subprocess.run(
            descriptor["args"],
            input=json.dumps(payload),
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if path_mode == "empty":
            assert run.returncode == 1
            assert "not found in PATH=''" in run.stderr
            assert not trace.exists()
        else:
            assert run.returncode == 0, run.stderr
            selected = binary_dir if path_mode == "inherited" else tmp_path / "first-bin"
            args = json.loads(trace.read_text())
            assert args[0] == str(selected / "nsenter")
            assert str(selected / "nft") in args


def test_poststop_needs_no_host_binaries(installer: HooksInstaller, tmp_path: Path) -> None:
    """Cleanup still works with empty PATH and an older running bundle."""
    installer.install()
    descriptor = json.loads((installer.target_dir / "terok-shield-poststop.json").read_text())[
        "hook"
    ]
    state = tmp_path / "old-task"
    state.mkdir(mode=0o700)
    payload = {
        "annotations": {
            "terok.shield.state_dir": str(state),
            "terok.shield.version": str(BUNDLE_VERSION - 1),
        }
    }
    run = subprocess.run(
        descriptor["args"],
        input=json.dumps(payload),
        env={"PATH": ""},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert run.returncode == 0, run.stderr


def test_hook_registration_public_check(installer: HooksInstaller) -> None:
    """Sibling packages can verify registration without parsing our files."""
    from terok_shield import user_hooks_dir_configured

    assert not user_hooks_dir_configured(installer.target_dir)
    installer.install()
    assert user_hooks_dir_configured(installer.target_dir)
