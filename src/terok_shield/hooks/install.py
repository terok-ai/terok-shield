# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""OCI hook file generation and installation.

Writes the hook entrypoint script and JSON descriptors that tell podman
to invoke terok-shield at ``createRuntime`` and ``poststop``.  Two entry
points: :func:`install_hooks` for per-container setup during pre_start,
and :func:`setup_global_hooks` for one-time system-wide installation.

Pure file I/O — no runtime container interaction.
"""
# WAYPOINT: HookMode (hooks.mode)

import json
from pathlib import Path

from ..config import ANNOTATION_KEY

_ENTRYPOINT_NAME = "terok-shield-hook"
_BRIDGE_HOOK_NAME = "terok-shield-bridge-hook"
# The entrypoint dispatches to the bridge branch when this token is the first
# positional argv after the script path.  WORKAROUND(shebang-argv0-stripped):
# shebang scripts lose the exec-supplied argv[0], so we cannot dispatch by the
# conventional ``args[0]`` program name alone — see hook_entrypoint.py header.
_BRIDGE_DISPATCH_FLAG = "--bridge"
_HOOK_STAGES = ("createRuntime", "poststop")


# ── Public API ──────────────────────────────────────────


def install_hooks(*, hook_entrypoint: Path, hooks_dir: Path) -> None:
    """Write OCI hook entrypoint and JSON descriptors to a given directory.

    WORKAROUND(hooks-dir-persist): currently only used for global hooks
    (user or root) because podman does not persist per-container
    ``--hooks-dir`` across stop/start.  The per-container code path is
    kept for near-future use.

    Args:
        hook_entrypoint: Where to write the entrypoint script.
        hooks_dir: Directory for hook JSON descriptors.
    """
    hook_entrypoint.parent.mkdir(parents=True, exist_ok=True)
    hooks_dir.mkdir(parents=True, exist_ok=True)
    _write_hook_files(hook_entrypoint, hooks_dir)


def install_bridge_hooks(*, hook_entrypoint: Path, hooks_dir: Path) -> None:
    """Register the bridge hook pair that spawns and reaps the NFLOG reader.

    Reuses the shared entrypoint script (no extra binary on disk) —
    dispatch to the reader spawn/reap branch rides on a ``--bridge``
    positional flag in ``args`` (see ``_BRIDGE_DISPATCH_FLAG`` for why
    the seemingly-more-natural ``args[0]`` program name can't be used).
    Users who install without this (``terok setup --no-dbus-bridge``) only
    see the nft hook pair in their hooks directory.

    Args:
        hook_entrypoint: The already-installed shared entrypoint script path.
        hooks_dir: Directory for hook JSON descriptors.
    """
    hooks_dir.mkdir(parents=True, exist_ok=True)
    _write_bridge_hook_files(hook_entrypoint, hooks_dir)


def uninstall_bridge_hooks(*, hooks_dir: Path) -> None:
    """Remove bridge hook JSON files, leaving the nft hook pair intact.

    Args:
        hooks_dir: Directory the hook JSON files live in.
    """
    for stage in _HOOK_STAGES:
        (hooks_dir / f"terok-shield-bridge-{stage}.json").unlink(missing_ok=True)


def setup_global_hooks(target_dir: Path, *, use_sudo: bool = False) -> None:
    """Install OCI hooks system-wide for restart persistence.

    Called by the ``setup`` CLI command.  When *use_sudo* is True, writes
    to a temp directory first and copies via ``sudo cp`` — avoids needing
    the Python process itself to run as root.

    Args:
        target_dir: Global hooks directory to install into.
        use_sudo: Copy files via ``sudo`` instead of writing directly.
    """
    if use_sudo:
        _install_via_sudo(target_dir)
    else:
        target_dir.mkdir(parents=True, exist_ok=True)
        _write_hook_files(target_dir / _ENTRYPOINT_NAME, target_dir)


# ── Installation mechanics ──────────────────────────────


def _install_via_sudo(target_dir: Path) -> None:
    """Write hooks to a temp dir, then sudo-copy to the target."""
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # JSONs must reference the final entrypoint path, not the temp copy
        final_entrypoint = target_dir / _ENTRYPOINT_NAME
        _write_hook_files(tmp_path / _ENTRYPOINT_NAME, tmp_path, final_entrypoint)

        subprocess.run(
            ["sudo", "mkdir", "-p", str(target_dir)],
            check=True,  # noqa: S603, S607
        )
        files = [str(tmp_path / _ENTRYPOINT_NAME)]
        for stage in _HOOK_STAGES:
            files.append(str(tmp_path / f"terok-shield-{stage}.json"))
        subprocess.run(
            ["sudo", "cp", *files, str(target_dir) + "/"],
            check=True,  # noqa: S603, S607
        )
        subprocess.run(
            ["sudo", "chmod", "+x", str(final_entrypoint)],  # noqa: S603, S607
            check=True,
        )


def _write_hook_files(
    hook_entrypoint: Path,
    hooks_dir: Path,
    json_entrypoint_path: Path | None = None,
) -> None:
    """Write the entrypoint script and hook JSON descriptors.

    Args:
        hook_entrypoint: Where to write the entrypoint script.
        hooks_dir: Where to write the hook JSON files.
        json_entrypoint_path: Path to embed in hook JSONs.  Defaults to
            *hook_entrypoint*; overridden for sudo installs where the
            temp write location differs from the final install path.
    """
    hook_entrypoint.write_text(_generate_entrypoint())
    hook_entrypoint.chmod(0o755)
    ref_path = str(json_entrypoint_path or hook_entrypoint)
    for stage in _HOOK_STAGES:
        hook_json = _generate_hook_json(ref_path, stage, _ENTRYPOINT_NAME, bridge=False)
        (hooks_dir / f"terok-shield-{stage}.json").write_text(hook_json)


def _write_bridge_hook_files(hook_entrypoint: Path, hooks_dir: Path) -> None:
    """Write the bridge-hook JSON pair that references the shared entrypoint."""
    ref_path = str(hook_entrypoint)
    for stage in _HOOK_STAGES:
        hook_json = _generate_hook_json(ref_path, stage, _BRIDGE_HOOK_NAME, bridge=True)
        (hooks_dir / f"terok-shield-bridge-{stage}.json").write_text(hook_json)


# ── Generators ──────────────────────────────────────────


def _generate_entrypoint() -> str:
    """Read the self-contained OCI hook entrypoint from bundled resources.

    Uses ``#!/usr/bin/env python3`` so it resolves Python at execution
    time — no virtualenv path is baked in at install time.
    """
    return (Path(__file__).parent.parent / "resources" / "hook_entrypoint.py").read_text()


def _generate_hook_json(entrypoint: str, stage: str, hook_name: str, *, bridge: bool) -> str:
    """Build an OCI hook JSON descriptor for a given lifecycle stage.

    *hook_name* is cosmetic (the kernel's shebang loader discards the
    exec-supplied ``argv[0]``) but is kept so ``ps`` still shows a
    recognizable name.  *bridge* is what actually drives dispatch in the
    entrypoint: bridge hooks prepend the ``--bridge`` flag, which the
    shebang loader preserves as ``sys.argv[1]``.

    Args:
        entrypoint: Absolute path to the hook entrypoint script.
        stage: OCI hook stage (``createRuntime`` or ``poststop``).
        hook_name: Cosmetic program name placed at ``args[0]``.
        bridge: When True, prepend ``--bridge`` so the entrypoint
            dispatches to the reader spawn/reap branch.
    """
    args = [hook_name, _BRIDGE_DISPATCH_FLAG, stage] if bridge else [hook_name, stage]
    hook = {
        "version": "1.0.0",
        "hook": {"path": entrypoint, "args": args},
        "when": {"annotations": {ANNOTATION_KEY: ".*"}},
        "stages": [stage],
    }
    return json.dumps(hook, indent=2) + "\n"
