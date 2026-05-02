# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""OCI hook file generation and installation.

Writes two role-specific entrypoint scripts (``nft-hook`` and
``reader-hook``) plus a shared ``_oci_state.py`` ballast module to the
target hooks directory, alongside the JSON descriptors that tell
podman to invoke each one at ``createRuntime`` and ``poststop``.

Two entry points: [`install_hooks`][terok_shield.hooks.install.install_hooks] for per-container setup
during pre_start, and [`setup_global_hooks`][terok_shield.hooks.install.setup_global_hooks] for one-time
system-wide installation.

Pure file I/O — no runtime container interaction.
"""
# WAYPOINT: HookMode (hooks.mode)

import json
from pathlib import Path

from ..config import ANNOTATION_KEY
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


# ── Public API ──────────────────────────────────────────


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


def setup_global_hooks(target_dir: Path, *, use_sudo: bool = False) -> None:
    """Install OCI hooks system-wide for restart persistence.

    Called by the ``setup`` CLI command.  When *use_sudo* is True,
    writes to a temp directory first and copies via ``sudo cp`` —
    avoids needing the Python process itself to run as root.

    Both hook pairs (nft + reader) and the shared ballast are written
    unconditionally, and the standalone NFLOG reader resource is
    copied out of the package to its canonical on-disk path.  The
    reader hook soft-fails on missing clearance (no socket to deliver
    events to) rather than blocking container starts, so installing
    it unconditionally costs nothing on shield-only deployments and
    removes a configuration knob.

    Args:
        target_dir: Global hooks directory to install into.
        use_sudo: Copy files via ``sudo`` instead of writing directly.
    """
    # Reader resource is per-user, never under target_dir; install it
    # before the hook JSONs so the path the JSONs reference is already
    # populated when the first container fires.
    install_reader_resource()
    if use_sudo:
        _install_via_sudo(target_dir)
    else:
        target_dir.mkdir(parents=True, exist_ok=True)
        _write_role_files(target_dir, target_dir)


# ── Installation mechanics ──────────────────────────────


def _install_via_sudo(target_dir: Path) -> None:
    """Write hooks to a temp dir, then sudo-copy to the target."""
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # JSONs must reference the final script paths, not the temp
        # copies — pass the install target as the JSON-side anchor.
        _write_role_files(tmp_path, tmp_path, json_dir=target_dir)

        subprocess.run(
            ["sudo", "mkdir", "-p", str(target_dir)],
            check=True,  # noqa: S603, S607
        )
        scripts = (_BALLAST_NAME, _NFT_ENTRYPOINT_NAME, _READER_ENTRYPOINT_NAME)
        descriptors = [
            fn(stage) for stage in _HOOK_STAGES for fn in (_nft_hook_json, _bridge_hook_json)
        ]
        files = [str(tmp_path / name) for name in (*scripts, *descriptors)]
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
