# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Shared test constants: filesystem paths.

Centralizes hardcoded path literals so SonarCloud only flags the constant
definition, not every usage.  Also gives semantic meaning to commonly used
placeholder and sentinel paths in test fixtures.
"""

from pathlib import Path

# ── Placeholder directories (constructor args in mocked tests, never accessed) ──

_BASE = Path("/tmp/terok-shield-testing")
FAKE_LOGS_DIR = _BASE / "logs"
FAKE_PROFILES_DIR = _BASE / "profiles"
FAKE_RESOLVED_DIR = _BASE / "resolved"
FAKE_STATE_DIR = _BASE / "state"
FAKE_STATE_DIR_STR: str = str(FAKE_STATE_DIR)
FAKE_CONFIG_DIR = _BASE / "config"
FAKE_XDG_STATE_HOME = _BASE / "xdg-state"
FAKE_XDG_CONFIG_HOME = _BASE / "xdg-config"

# ── Nonexistent path (guaranteed absent, for testing missing-file behavior) ──
# Tests that need specific subpaths can derive them:
#   NONEXISTENT_DIR / "logs", NONEXISTENT_DIR / "ep", etc.

NONEXISTENT_DIR = Path("/nonexistent")
NONEXISTENT_SENTINEL: str = str(NONEXISTENT_DIR / "sentinel")

# ── Forbidden path inputs (validation must reject these) ──
# Values are deliberately harmless — even a catastrophic test failure
# won't touch real system files or secrets.

FORBIDDEN_TRAVERSAL = "../nonexistent/forbidden"
FORBIDDEN_ABSOLUTE = "/nonexistent/forbidden"
RELATIVE_STATE_SUBPATH = "relative/path"

# ── Volume mount paths (for CLI run/prepare tests) ──
# These are podman -v bind-mount strings, not real filesystem paths.

VOLUME_MOUNT_HOST = "/host:/ctr"
VOLUME_MOUNT_DATA = "/data:/data"
STATE_DIR_WITH_SPACES = "/path/with spaces/dir"

# ── Binary paths (for mocking shutil.which results) ──

NFT_BINARY = "/usr/bin/nft"
NFT_SBIN = "/usr/sbin/nft"
PODMAN_BINARY = "/usr/bin/podman"

# ── Well-known terok-shield path segments used in tests ──

STATE_ROOT_NAME = "state"
CONFIG_ROOT_NAME = "config"
CONTAINERS_DIR_NAME = "containers"
CONFIG_FILENAME = "config.yml"
AUDIT_FILENAME = "audit.jsonl"
HOOK_ERROR_LOG_FILENAME = "hook-error.log"
TEST_CACHE_FILENAME = "test.resolved"
TEST_SUBDIR_NAME = "subdir"
BIN_DIR_NAME = "bin"
HOOKS_DIR_NAME = "hooks"
HOOK_ENTRYPOINT_NAME = "terok-shield-hook"
