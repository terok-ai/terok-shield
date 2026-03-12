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
FAKE_CONFIG_DIR = _BASE / "config"
FAKE_XDG_STATE_HOME = _BASE / "xdg-state"
FAKE_XDG_CONFIG_HOME = _BASE / "xdg-config"

# ── Nonexistent path (guaranteed absent, for testing missing-file behavior) ──
# Tests that need specific subpaths can derive them:
#   NONEXISTENT_DIR / "logs", NONEXISTENT_DIR / "ep", etc.

NONEXISTENT_DIR = Path("/nonexistent")

# ── Forbidden path inputs (validation must reject these) ──
# Values are deliberately harmless — even a catastrophic test failure
# won't touch real system files or secrets.

FORBIDDEN_TRAVERSAL = "../nonexistent/forbidden"
FORBIDDEN_ABSOLUTE = "/nonexistent/forbidden"

# ── Binary paths (for mocking shutil.which results) ──

NFT_BINARY = "/usr/bin/nft"
