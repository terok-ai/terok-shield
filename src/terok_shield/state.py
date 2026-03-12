# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Per-container state bundle layout contract.

Defines the canonical directory structure for a container's state
bundle and provides pure path-derivation functions.  Zero dependencies
beyond ``pathlib`` — this module is the single source of truth for
where files live within a state directory.

Bundle layout::

    {state_dir}/
    ├── hooks/
    │   ├── terok-shield-createRuntime.json
    │   └── terok-shield-poststop.json
    ├── terok-shield-hook              # entrypoint script
    ├── profile.allowed                # IPs from DNS resolution
    ├── live.allowed                   # IPs from allow/deny
    └── audit.jsonl                    # per-container audit log
"""

from pathlib import Path

BUNDLE_VERSION = 1
"""Integer version of the state bundle layout.

Bumped whenever the file layout changes in a backwards-incompatible way.
The OCI hook hard-fails if the annotation version does not match.
"""


def hooks_dir(state_dir: Path) -> Path:
    """Return the OCI hooks directory within the state bundle."""
    return state_dir / "hooks"


def hook_entrypoint(state_dir: Path) -> Path:
    """Return the path to the hook entrypoint script."""
    return state_dir / "terok-shield-hook"


def hook_json_path(state_dir: Path, stage: str) -> Path:
    """Return the path to a hook JSON file for a given OCI stage."""
    return hooks_dir(state_dir) / f"terok-shield-{stage}.json"


def profile_allowed_path(state_dir: Path) -> Path:
    """Return the path to the profile-derived allowlist file."""
    return state_dir / "profile.allowed"


def live_allowed_path(state_dir: Path) -> Path:
    """Return the path to the live allow/deny allowlist file."""
    return state_dir / "live.allowed"


def audit_path(state_dir: Path) -> Path:
    """Return the path to the per-container audit log."""
    return state_dir / "audit.jsonl"


def ensure_state_dirs(state_dir: Path) -> None:
    """Create the state directory and its required subdirectories."""
    state_dir.mkdir(parents=True, exist_ok=True)
    hooks_dir(state_dir).mkdir(parents=True, exist_ok=True)
