# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""OCI hook file generation and installation.

Writes two role-specific entrypoint scripts (``nft-hook`` and
``reader-hook``) plus a shared ``_oci_state.py`` ballast module to the
target hooks directory, alongside the JSON descriptors that tell
podman to invoke each one at ``createRuntime`` and ``poststop``.

Scripts and descriptors both land in
``namespace_state_dir("shield") / "hooks"`` under the operator's
``paths.root``.  ``containers.conf`` is patched so podman scans that
path.  Each sibling package owns its own subtree under ``paths.root``
the same way (see ``terok_sandbox.supervisor.install``).

Public entry points:

- [`HooksInstaller`][terok_shield.hooks.install.HooksInstaller] — global
  installation lifecycle (install + uninstall).

Pure file I/O — no runtime container interaction.
"""
# WAYPOINT: HookMode (hooks.mode)

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from importlib.metadata import version
from pathlib import Path

from terok_util import (
    SetupCheck,
    SetupReceipt,
    SetupStatus,
    find_host_tool,
    host_path,
    host_tools_source,
    python_identity,
    require_no_downgrade,
    require_setup,
)

from ..config import ANNOTATION_KEY
from ..podman_info._conf import _user_containers_conf
from ..podman_info.hooks_dir import _parse_hooks_dir_from_conf
from .reader_install import install_reader_resource

#: File name for the shared OCI-state ballast module.  Both role
#: scripts ``import _oci_state`` from their own directory at runtime,
#: so the module name and the on-disk file stem must agree exactly.
_BALLAST_NAME = "_oci_state.py"

#: File name for the nft + dnsmasq entrypoint.  Lifecycle: applies
#: the pre-generated ruleset at createRuntime, reaps dnsmasq at
#: poststop.
_NFT_ENTRYPOINT_NAME = "terok-shield-hook"

#: File name for the optional NFLOG-reader spawn/reap entrypoint.
#: Lifecycle: forks the per-container reader at createRuntime,
#: SIGTERMs it at poststop.
_READER_ENTRYPOINT_NAME = "terok-shield-bridge-hook"

_HOOK_STAGES = ("createRuntime", "poststop")

_RESOURCES = Path(__file__).parent.parent / "resources"


def _nft_hook_json(stage: str) -> str:
    """Per-stage filename for the nft hook JSON descriptor."""
    return f"terok-shield-{stage}.json"


def _bridge_hook_json(stage: str) -> str:
    """Per-stage filename for the reader (bridge) hook JSON descriptor."""
    return f"terok-shield-bridge-{stage}.json"


#: Files ``HooksInstaller.install`` writes to ``target_dir`` — both
#: the role scripts + ballast and the JSON descriptors podman scans.
_SCRIPT_FILES: tuple[str, ...] = (
    _BALLAST_NAME,
    "_host_tools.py",
    _NFT_ENTRYPOINT_NAME,
    _READER_ENTRYPOINT_NAME,
)

_DESCRIPTOR_FILES: tuple[str, ...] = (
    *(_nft_hook_json(stage) for stage in _HOOK_STAGES),
    *(_bridge_hook_json(stage) for stage in _HOOK_STAGES),
)


def _default_target_dir() -> Path:
    """Canonical hooks dir under ``paths.root``: ``<state_root>/shield/hooks``."""
    from ..paths import namespace_state_dir

    return namespace_state_dir("shield") / "hooks"


# ── Global installer ────────────────────────────────────


@dataclass(frozen=True)
class HooksInstaller:
    """Persistent installation of terok-shield's OCI hook pair.

    The createRuntime/poststop hook pair must persist across container
    restarts: podman ≥ 5.x drops per-container ``--hooks-dir`` on
    stop/start (containers/podman#17935), so global hooks are the
    only reliable activation path until that upstream regression is
    fixed.

    Scripts, ballast, and JSON descriptors all land in *target_dir*
    (default: ``namespace_state_dir("shield") / "hooks"``).
    ``containers.conf`` is patched to register that path so podman
    discovers the descriptors on the next container start.

    Symmetric lifecycle: [`install`][terok_shield.hooks.install.HooksInstaller.install]
    writes, [`uninstall`][terok_shield.hooks.install.HooksInstaller.uninstall]
    removes.  Both are idempotent.
    """

    target_dir: Path = field(default_factory=_default_target_dir)
    """Directory the hook scripts, ballast, and JSON descriptors all live in."""

    def _receipt(self) -> SetupReceipt:
        """Describe only Shield's own installed hook generation."""
        from ..paths import reader_script_path

        return SetupReceipt(
            self.target_dir.parent / "setup.json",
            "terok-shield",
            version("terok-shield"),
            {
                "python": python_identity(),
                "hooks": str(self.target_dir),
                "reader": str(reader_script_path()),
                "host_tools": hashlib.sha256(host_tools_source().encode()).hexdigest(),
            },
        )

    def check_setup(self, *, live: bool = False) -> tuple[SetupCheck, ...]:
        """Check Shield's receipt and hooks, optionally probing launch prerequisites."""
        checks = [self._receipt().check(), *self._check_artifacts()]
        if live:
            checks.extend(self._check_tools())
        return tuple(checks)

    def _check_tools(self) -> tuple[SetupCheck, ...]:
        """Probe required host tools without constructing a Shield runtime."""
        return tuple(
            SetupCheck(
                "terok-shield",
                name,
                SetupStatus.READY if find_host_tool(name) else SetupStatus.MISSING,
                f"Host tool {name!r} must be executable on PATH.",
            )
            for name in ("podman", "nft", "nsenter")
        )

    def _check_artifacts(self) -> tuple[SetupCheck, ...]:
        """Validate the installed bootstrap and every required owned artifact."""
        from ..paths import reader_script_path

        try:
            missing = [
                name
                for name in (*_SCRIPT_FILES, *_DESCRIPTOR_FILES)
                if not (self.target_dir / name).is_file()
            ]
            for path in (reader_script_path(), reader_script_path().parent / "_host_tools.py"):
                if not path.is_file():
                    missing.append(str(path))
            if missing:
                raise ValueError(f"Missing hook files: {', '.join(missing)}")
            if not os.access(sys.executable, os.X_OK):
                raise ValueError("Hook Python interpreter is not executable")
            for name, entrypoint in (
                (_nft_hook_json, _NFT_ENTRYPOINT_NAME),
                (_bridge_hook_json, _READER_ENTRYPOINT_NAME),
            ):
                for stage in _HOOK_STAGES:
                    expected = json.loads(
                        _generate_hook_json(str(self.target_dir / entrypoint), stage)
                    )
                    if json.loads((self.target_dir / name(stage)).read_text()) != expected:
                        raise ValueError("Hook bootstrap binding changed; rerun setup")
            if not user_hooks_dir_configured(self.target_dir):
                raise ValueError("Hook directory is not registered in containers.conf")
        except (OSError, ValueError) as exc:
            return (SetupCheck("terok-shield", "hooks", SetupStatus.STALE, str(exc)),)
        return (SetupCheck("terok-shield", "hooks", SetupStatus.READY),)

    def install(self) -> None:
        """Install global standalone hooks after preflight; certify only verified work."""
        require_no_downgrade(self.check_setup())
        require_setup(self._check_tools())
        receipt = self._receipt()
        receipt.clear()
        install_reader_resource()
        self.target_dir.mkdir(parents=True, exist_ok=True)
        _write_role_files(self.target_dir)
        ensure_user_hooks_dir_configured(self.target_dir)
        require_setup(self._check_artifacts())
        receipt.write()

    def uninstall(self) -> None:
        """Remove every hook file [`install`][terok_shield.hooks.install.HooksInstaller.install] would write.

        Idempotent — missing files are tolerated.  ``containers.conf``
        is left untouched: other terok packages may still register
        their own ``hooks_dir`` entries the operator wants to keep.
        """
        self._receipt().clear()
        for name in (*_SCRIPT_FILES, *_DESCRIPTOR_FILES):
            (self.target_dir / name).unlink(missing_ok=True)

    def is_installed(self) -> bool:
        """True when ``target_dir`` carries the canonical createRuntime hook JSON.

        Use ``check_setup`` for receipt, interpreter, and artifact validation.
        """
        return (self.target_dir / _nft_hook_json("createRuntime")).is_file()


# ── Installation mechanics ──────────────────────────────


def _write_role_files(target_dir: Path) -> None:
    """Copy standalone hook sources and bind descriptors to setup's interpreter."""
    from ..paths import reader_script_path

    ballast = (
        (_RESOURCES / _BALLAST_NAME)
        .read_text()
        .replace('"__SETUP_PATH__"', json.dumps(host_path()))
    )
    (target_dir / _BALLAST_NAME).write_text(ballast)
    (target_dir / "_host_tools.py").write_text(host_tools_source())
    (target_dir / _NFT_ENTRYPOINT_NAME).write_text((_RESOURCES / "nft_hook.py").read_text())
    reader = (
        (_RESOURCES / "reader_hook.py")
        .read_text()
        .replace('"__READER_SCRIPT_PATH__"', json.dumps(str(reader_script_path())))
    )
    (target_dir / _READER_ENTRYPOINT_NAME).write_text(reader)
    for entrypoint, descriptor in (
        (_NFT_ENTRYPOINT_NAME, _nft_hook_json),
        (_READER_ENTRYPOINT_NAME, _bridge_hook_json),
    ):
        (target_dir / entrypoint).chmod(0o755)
        for stage in _HOOK_STAGES:
            (target_dir / descriptor(stage)).write_text(
                _generate_hook_json(str(target_dir / entrypoint), stage)
            )


# ── containers.conf registration ────────────────────────


def user_hooks_dir_configured(hooks_dir: Path) -> bool:
    """Whether the user's containers.conf registers this package-owned hook directory."""
    return str(hooks_dir.expanduser()) in {
        str(Path(entry).expanduser())
        for entry in _parse_hooks_dir_from_conf(_user_containers_conf())
    }


def ensure_user_hooks_dir_configured(hooks_dir: Path | None = None) -> None:
    """Ensure ``~/.config/containers/containers.conf`` lists *hooks_dir*.

    The canonical SSOT for the rootless OCI hooks directory across
    every terok package: shield calls it at ``setup`` time; other
    installers (e.g. terok-sandbox's per-container supervisor) call
    it before dropping their own descriptors so they don't have to
    re-implement the containers.conf patcher.  Idempotent.

    *hooks_dir* defaults to ``namespace_state_dir("shield") / "hooks"``
    — shield's canonical install location under ``paths.root``.

    Creates the conf file if absent.  Inserts ``hooks_dir`` into the
    existing ``[engine]`` section or appends a new section if none
    exists.  Skips silently when *hooks_dir* is already listed.  When
    a different ``hooks_dir`` is configured, appends ours to the list
    rather than failing — the operator owns containers.conf and may
    have intentionally pinned other locations.

    Pure line-based editing — comments and formatting are preserved.
    """
    if hooks_dir is None:
        hooks_dir = _default_target_dir()
    conf_path = _user_containers_conf()
    hooks_str = str(hooks_dir)
    hooks_line = f'hooks_dir = ["{hooks_str}"]'

    if not conf_path.is_file():
        conf_path.parent.mkdir(parents=True, exist_ok=True)
        conf_path.write_text(f"[engine]\n{hooks_line}\n")
        return

    existing = _parse_hooks_dir_from_conf(conf_path)
    if not existing:
        _insert_hooks_line(conf_path, hooks_line)
        return

    if hooks_str in existing or str(hooks_dir.expanduser()) in existing:
        return  # already configured
    _append_to_hooks_dir(conf_path, hooks_str)


def _insert_hooks_line(conf_path: Path, hooks_line: str) -> None:
    """Insert *hooks_line* after ``[engine]`` in *conf_path*, or append a new section."""
    lines = conf_path.read_text().splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.strip() == "[engine]":
            lines.insert(i + 1, hooks_line + "\n")
            conf_path.write_text("".join(lines))
            return
    # No [engine] section — append one.
    with conf_path.open("a") as f:
        f.write(f"\n[engine]\n{hooks_line}\n")


def _append_to_hooks_dir(conf_path: Path, new_entry: str) -> None:
    """Append *new_entry* to the existing ``hooks_dir = [...]`` list in place."""
    import re

    text = conf_path.read_text()
    # The trailing group absorbs optional whitespace plus an inline ``# …``
    # comment so a commented line (``hooks_dir = ["/x"]  # note``) still
    # matches and the comment is preserved verbatim after the rewrite.
    list_pattern = re.compile(
        r"^(\s*hooks_dir\s*=\s*\[)(.*?)(\])([^\S\n]*(?:#[^\n]*)?)$",
        re.MULTILINE | re.DOTALL,
    )

    def _list_repl(m: re.Match[str]) -> str:
        body = m.group(2).rstrip()
        sep = ", " if body and not body.endswith(",") else ""
        return f'{m.group(1)}{body}{sep}"{new_entry}"{m.group(3)}{m.group(4)}'

    new_text, count = list_pattern.subn(_list_repl, text, count=1)
    if count:
        conf_path.write_text(new_text)
        return

    # Scalar form: ``hooks_dir = "/path"`` — promote to a two-element list.
    scalar_pattern = re.compile(
        r'^(\s*hooks_dir\s*=\s*)"([^"]+)"([^\S\n]*(?:#[^\n]*)?)$', re.MULTILINE
    )

    def _scalar_repl(m: re.Match[str]) -> str:
        return f'{m.group(1)}["{m.group(2)}", "{new_entry}"]{m.group(3)}'

    new_text, count = scalar_pattern.subn(_scalar_repl, text, count=1)
    if count:
        conf_path.write_text(new_text)


# ── Generators ──────────────────────────────────────────


def _generate_hook_json(entrypoint: str, stage: str) -> str:
    """Bind an OCI lifecycle stage to the installation's isolated Python."""
    hook = {
        "version": "1.0.0",
        "hook": {"path": sys.executable, "args": [sys.executable, "-I", entrypoint, stage]},
        "when": {"annotations": {ANNOTATION_KEY: ".*"}},
        "stages": [stage],
    }
    return json.dumps(hook, indent=2) + "\n"
