# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""OCI hook file generation and installation.

Writes two role-specific entrypoint scripts (``nft-hook`` and
``reader-hook``) plus a shared ``_oci_state.py`` ballast module to the
target hooks directory, alongside the JSON descriptors that tell
podman to invoke each one at ``createRuntime`` and ``poststop``.

Public entry points:

- [`HooksInstaller`][terok_shield.hooks.install.HooksInstaller] — global
  installation lifecycle (install + uninstall) at system or user scope.
- [`install_hooks`][terok_shield.hooks.install.install_hooks] — per-container
  install used by ``HookMode.pre_start``.

Pure file I/O — no runtime container interaction.
"""
# WAYPOINT: HookMode (hooks.mode)

from __future__ import annotations

import json
import subprocess  # nosec B404 — sudo escalation for system-wide installs
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..config import ANNOTATION_KEY
from ..podman_info._conf import _user_containers_conf
from ..podman_info.hooks_dir import (
    USER_HOOKS_DIR,
    _parse_hooks_dir_from_conf,
    system_hooks_dir,
)
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


#: Every file ``HooksInstaller.install`` writes to ``target_dir``.
#: Drives ``uninstall`` so the symmetric cleanup never drifts from
#: the install layout.
_INSTALLED_FILES: tuple[str, ...] = (
    _BALLAST_NAME,
    _NFT_ENTRYPOINT_NAME,
    _READER_ENTRYPOINT_NAME,
    *(_nft_hook_json(stage) for stage in _HOOK_STAGES),
    *(_bridge_hook_json(stage) for stage in _HOOK_STAGES),
)


# ── Global installer ────────────────────────────────────


@dataclass(frozen=True)
class HooksInstaller:
    """Persistent installation of terok-shield's OCI hook pair.

    The createRuntime/poststop hook pair must persist across container
    restarts: podman ≥ 5.x drops per-container ``--hooks-dir`` on
    stop/start (containers/podman#17935), so global hooks are the
    only reliable activation path until that upstream regression is
    fixed.  Two scopes, exposed as classmethod factories:

    - [`HooksInstaller.system`][terok_shield.hooks.install.HooksInstaller.system] —
      `/etc/containers/oci/hooks.d` (or the existing equivalent);
      escalates writes through ``sudo``, visible to root and every user.
    - [`HooksInstaller.user`][terok_shield.hooks.install.HooksInstaller.user] —
      `~/.local/share/containers/oci/hooks.d`; rootless, also patches
      ``hooks_dir`` into the user's ``containers.conf`` so podman
      discovers it.

    The lifecycle is symmetric: [`install`][terok_shield.hooks.install.HooksInstaller.install]
    writes, [`uninstall`][terok_shield.hooks.install.HooksInstaller.uninstall]
    removes.  Both are idempotent.
    """

    target_dir: Path
    """Directory the hook files (entrypoints, ballast, JSON descriptors) live in."""

    use_sudo: bool = False
    """Escalate file writes and removals through ``sudo`` (system scope)."""

    register_in_containers_conf: bool = False
    """Patch ``hooks_dir`` into the user's ``containers.conf`` on install.

    Only meaningful for the user scope — system hooks dirs are
    discovered by podman without registration.
    """

    @classmethod
    def system(cls) -> HooksInstaller:
        """Installer for the canonical system hooks directory (sudo-escalated).

        Targets the best-existing of ``/etc/containers/oci/hooks.d``
        and ``/usr/share/containers/oci/hooks.d`` — see
        [`system_hooks_dir`][terok_shield.podman_info.hooks_dir.system_hooks_dir]
        for the resolution rule.
        """
        return cls(target_dir=system_hooks_dir(), use_sudo=True)

    @classmethod
    def user(cls) -> HooksInstaller:
        """Installer for the rootless per-user hooks directory.

        Writes to ``~/.local/share/containers/oci/hooks.d`` and
        registers that directory in the user's ``containers.conf`` so
        podman scans it on the next container start.
        """
        return cls(
            target_dir=USER_HOOKS_DIR.expanduser(),
            use_sudo=False,
            register_in_containers_conf=True,
        )

    def install(self) -> None:
        """Write entrypoints, ballast, and JSON descriptors into ``target_dir``.

        Both hook pairs (nft + reader) and the shared ballast are
        written unconditionally — the reader hook soft-fails on
        missing clearance, so installing it on a shield-only host
        costs nothing and removes a configuration knob.  The
        standalone NFLOG reader resource is copied to its canonical
        per-user path regardless of scope.

        For [`HooksInstaller.user`][terok_shield.hooks.install.HooksInstaller.user]
        installs (``register_in_containers_conf=True``), also patches
        ``hooks_dir`` into the user's ``containers.conf``.
        """
        # Reader resource is per-user, never under target_dir; install it
        # before the hook JSONs so the path the JSONs reference is already
        # populated when the first container fires.
        install_reader_resource()
        if self.use_sudo:
            _install_via_sudo(self.target_dir)
        else:
            self.target_dir.mkdir(parents=True, exist_ok=True)
            _write_role_files(self.target_dir, self.target_dir)
        if self.register_in_containers_conf:
            _register_hooks_dir_in_containers_conf(self.target_dir)

    def uninstall(self) -> None:
        """Remove every hook file [`install`][terok_shield.hooks.install.HooksInstaller.install] would write.

        Idempotent — missing files are tolerated.  When ``use_sudo``
        is set, deletion runs under ``sudo`` so the calling process
        stays unprivileged.  Containers.conf is left untouched: the
        user's other hook directories may still need the entry.
        """
        paths = [self.target_dir / name for name in _INSTALLED_FILES]
        if self.use_sudo:
            _remove_via_sudo(paths)
        else:
            for path in paths:
                path.unlink(missing_ok=True)

    def is_installed(self) -> bool:
        """True when ``target_dir`` carries the canonical createRuntime hook JSON.

        A presence probe, not a version check — the
        [`Shield.check_environment`][terok_shield.Shield.check_environment]
        path compares the ballast's ``BUNDLE_VERSION`` separately.
        """
        return (self.target_dir / _nft_hook_json("createRuntime")).is_file()


# ── Per-container install (used by HookMode.pre_start) ──


def install_hooks(*, hook_entrypoint: Path, hooks_dir: Path) -> None:
    """Write OCI hook entrypoints, ballast, and JSON descriptors.

    Lays down both role scripts (nft + reader) plus the shared OCI
    ballast in ``hooks_dir``.  ``hook_entrypoint`` names both the
    target directory **and** the on-disk filename for the **nft**
    script — callers that pin a non-default name (per-container
    installs, future test scaffolding) get exactly the path they
    asked for in the JSON descriptors.  The reader entrypoint and
    ``_oci_state.py`` ballast land in the same parent directory under
    their canonical names.

    WORKAROUND(hooks-dir-persist): currently only used for global
    hooks (user or root) because podman does not persist per-container
    ``--hooks-dir`` across stop/start.  The per-container code path is
    kept for near-future use.

    Args:
        hook_entrypoint: Where to write the nft entrypoint script.
            The reader entrypoint and ``_oci_state.py`` ballast land
            in the same parent directory.
        hooks_dir: Directory for hook JSON descriptors.
    """
    hook_entrypoint.parent.mkdir(parents=True, exist_ok=True)
    hooks_dir.mkdir(parents=True, exist_ok=True)
    _write_role_files(hook_entrypoint.parent, hooks_dir, nft_entrypoint_name=hook_entrypoint.name)


# ── Installation mechanics ──────────────────────────────


def _install_via_sudo(target_dir: Path) -> None:
    """Write hooks to a temp dir, then sudo-copy to the target."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # JSONs must reference the final script paths, not the temp
        # copies — pass the install target as the JSON-side anchor.
        _write_role_files(tmp_path, tmp_path, json_dir=target_dir)

        subprocess.run(
            ["sudo", "mkdir", "-p", str(target_dir)],
            check=True,  # noqa: S603, S607
        )
        files = [str(tmp_path / name) for name in _INSTALLED_FILES]
        subprocess.run(
            ["sudo", "cp", *files, str(target_dir) + "/"],
            check=True,  # noqa: S603, S607
        )
        subprocess.run(
            [
                "sudo",
                "chmod",
                "+x",
                str(target_dir / _NFT_ENTRYPOINT_NAME),
                str(target_dir / _READER_ENTRYPOINT_NAME),
            ],  # noqa: S603, S607
            check=True,
        )


def _remove_via_sudo(paths: list[Path]) -> None:
    """Remove *paths* via ``sudo rm -f`` — idempotent, no error on missing files."""
    if not paths:
        return
    subprocess.run(
        ["sudo", "rm", "-f", *(str(p) for p in paths)],
        check=True,  # noqa: S603, S607
    )


def _write_role_files(
    script_dir: Path,
    hooks_dir: Path,
    *,
    json_dir: Path | None = None,
    nft_entrypoint_name: str = _NFT_ENTRYPOINT_NAME,
) -> None:
    """Write nft + reader entrypoints, the shared ballast, and the four hook JSONs.

    The two role scripts and the ``_oci_state.py`` ballast all land in
    *script_dir*; each role script imports the ballast as a sibling at
    runtime (Python's default ``sys.path[0]`` is the script's
    directory).

    Hook JSONs go into *hooks_dir* and reference the script paths
    under *json_dir* (defaulting to *script_dir* when the install is
    in-place, or the final target when staged for ``sudo cp``).

    Args:
        script_dir: Where to write ``_oci_state.py``, the nft
            entrypoint, and the reader entrypoint.
        hooks_dir: Where to write the four ``terok-shield*.json`` files.
        json_dir: Path to embed in hook JSONs.  Defaults to
            *script_dir*; overridden for sudo installs where the temp
            write location differs from the final install path.
        nft_entrypoint_name: On-disk filename for the nft entrypoint.
            Defaults to the canonical ``terok-shield-hook``; callers
            pinning a non-default path (``install_hooks``) thread
            their own filename through so the JSON descriptors point
            at the script the caller asked for.
    """
    anchor = json_dir or script_dir

    (script_dir / _BALLAST_NAME).write_text((_RESOURCES / _BALLAST_NAME).read_text())
    (script_dir / nft_entrypoint_name).write_text((_RESOURCES / "nft_hook.py").read_text())
    (script_dir / _READER_ENTRYPOINT_NAME).write_text((_RESOURCES / "reader_hook.py").read_text())
    (script_dir / nft_entrypoint_name).chmod(0o755)
    (script_dir / _READER_ENTRYPOINT_NAME).chmod(0o755)

    nft_path = str(anchor / nft_entrypoint_name)
    reader_path = str(anchor / _READER_ENTRYPOINT_NAME)
    for stage in _HOOK_STAGES:
        (hooks_dir / _nft_hook_json(stage)).write_text(
            _generate_hook_json(nft_path, stage, nft_entrypoint_name)
        )
        (hooks_dir / _bridge_hook_json(stage)).write_text(
            _generate_hook_json(reader_path, stage, _READER_ENTRYPOINT_NAME)
        )


# ── containers.conf registration (user scope only) ──────


def _register_hooks_dir_in_containers_conf(hooks_dir: Path) -> None:
    """Ensure ``~/.config/containers/containers.conf`` lists *hooks_dir*.

    Creates the file if absent.  Inserts ``hooks_dir`` into the
    existing ``[engine]`` section or appends a new section if none
    exists.  Warns (does not fail) when ``hooks_dir`` is already set
    to a different value — the operator owns containers.conf and may
    have intentionally pinned a different location.

    Pure line-based editing — comments and formatting are preserved.
    """
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
    print(
        f"Warning: {conf_path} already has hooks_dir = {existing}\n"
        f"Add {hooks_str!r} to the list manually if needed."
    )


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


# ── Generators ──────────────────────────────────────────


def _generate_hook_json(entrypoint: str, stage: str, hook_name: str) -> str:
    """Build an OCI hook JSON descriptor for a given lifecycle stage.

    *hook_name* is cosmetic (the kernel's shebang loader discards the
    exec-supplied ``argv[0]``) but is kept so ``ps`` still shows a
    recognizable name.  Each role script self-dispatches by ``argv[1]``
    (``createRuntime`` / ``poststop``); no shared dispatch flag.

    Args:
        entrypoint: Absolute path to the hook entrypoint script.
        stage: OCI hook stage (``createRuntime`` or ``poststop``).
        hook_name: Cosmetic program name placed at ``args[0]``.
    """
    hook = {
        "version": "1.0.0",
        "hook": {"path": entrypoint, "args": [hook_name, stage]},
        "when": {"annotations": {ANNOTATION_KEY: ".*"}},
        "stages": [stage],
    }
    return json.dumps(hook, indent=2) + "\n"
