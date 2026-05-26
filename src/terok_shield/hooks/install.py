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
- [`install_hooks`][terok_shield.hooks.install.install_hooks] — per-container
  install used by ``HookMode.pre_start``.

Pure file I/O — no runtime container interaction.
"""
# WAYPOINT: HookMode (hooks.mode)

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

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

    def install(self) -> None:
        """Write entrypoints, ballast, and descriptors to ``target_dir``.

        Both hook pairs (nft + reader) and the shared ballast are
        written unconditionally — the reader hook soft-fails on
        missing clearance, so installing it on a shield-only host
        costs nothing and removes a configuration knob.  The
        standalone NFLOG reader resource is copied to its canonical
        per-user path.

        ``containers.conf`` is patched to list ``target_dir`` in
        ``hooks_dir`` so podman discovers the descriptors.
        """
        install_reader_resource()
        self.target_dir.mkdir(parents=True, exist_ok=True)
        _write_role_files(self.target_dir, self.target_dir)
        ensure_user_hooks_dir_configured(self.target_dir)

    def uninstall(self) -> None:
        """Remove every hook file [`install`][terok_shield.hooks.install.HooksInstaller.install] would write.

        Idempotent — missing files are tolerated.  ``containers.conf``
        is left untouched: other terok packages may still register
        their own ``hooks_dir`` entries the operator wants to keep.
        """
        for name in (*_SCRIPT_FILES, *_DESCRIPTOR_FILES):
            (self.target_dir / name).unlink(missing_ok=True)

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
    hooks because podman does not persist per-container
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


def _write_role_files(
    script_dir: Path,
    hooks_dir: Path,
    *,
    nft_entrypoint_name: str = _NFT_ENTRYPOINT_NAME,
) -> None:
    """Write nft + reader entrypoints, the shared ballast, and the four hook JSONs.

    The two role scripts and the ``_oci_state.py`` ballast all land in
    *script_dir*; each role script imports the ballast as a sibling at
    runtime (Python's default ``sys.path[0]`` is the script's
    directory).  Hook JSONs go into *hooks_dir* and reference the
    script paths under *script_dir*.

    Args:
        script_dir: Where to write ``_oci_state.py``, the nft
            entrypoint, and the reader entrypoint.
        hooks_dir: Where to write the four ``terok-shield*.json`` files.
        nft_entrypoint_name: On-disk filename for the nft entrypoint.
            Defaults to the canonical ``terok-shield-hook``; callers
            pinning a non-default path (``install_hooks``) thread
            their own filename through so the JSON descriptors point
            at the script the caller asked for.
    """
    from ..paths import reader_script_path

    (script_dir / _BALLAST_NAME).write_text((_RESOURCES / _BALLAST_NAME).read_text())
    (script_dir / nft_entrypoint_name).write_text((_RESOURCES / "nft_hook.py").read_text())
    # The reader hook carries an absolute path to the NFLOG reader
    # script as a baked constant; rewrite the placeholder so the hook
    # always finds the reader exactly where ``reader_script_path()``
    # resolved at this ``terok-shield setup`` call.
    reader_hook_source = (_RESOURCES / "reader_hook.py").read_text()
    reader_hook_rendered = reader_hook_source.replace(
        '"__READER_SCRIPT_PATH__"', json.dumps(str(reader_script_path()))
    )
    (script_dir / _READER_ENTRYPOINT_NAME).write_text(reader_hook_rendered)
    (script_dir / nft_entrypoint_name).chmod(0o755)
    (script_dir / _READER_ENTRYPOINT_NAME).chmod(0o755)

    nft_path = str(script_dir / nft_entrypoint_name)
    reader_path = str(script_dir / _READER_ENTRYPOINT_NAME)
    for stage in _HOOK_STAGES:
        (hooks_dir / _nft_hook_json(stage)).write_text(
            _generate_hook_json(nft_path, stage, nft_entrypoint_name)
        )
        (hooks_dir / _bridge_hook_json(stage)).write_text(
            _generate_hook_json(reader_path, stage, _READER_ENTRYPOINT_NAME)
        )


# ── containers.conf registration ────────────────────────


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
