# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""nft --check dry-run tests for generated rulesets."""

import shutil
import subprocess
import unittest

from terok_shield.nft import hardened_ruleset, standard_ruleset


def _nft_skip_reason() -> str | None:
    """Return a skip reason when nft syntax validation cannot run, or None."""
    if not shutil.which("nft"):
        return "nft not installed"
    # Empty input succeeds even without netlink; use a real table to test permissions.
    r = subprocess.run(
        ["nft", "-c", "-f", "-"],
        input="table ip _nft_check_test { }",
        capture_output=True,
        text=True,
        timeout=5,
    )
    if r.returncode == 0:
        return None
    if "operation not permitted" in r.stderr.lower():
        return "nft not permitted"
    raise RuntimeError(f"unexpected nft probe failure: {r.stderr}")


_NFT_SKIP = _nft_skip_reason()


@unittest.skipIf(_NFT_SKIP is not None, _NFT_SKIP or "")
class TestNftSyntaxValidation(unittest.TestCase):
    """Validate generated rulesets using nft --check."""

    def test_standard_ruleset_is_valid_nft(self) -> None:
        """Standard ruleset passes nft syntax check."""
        ruleset = standard_ruleset()
        result = subprocess.run(
            ["nft", "-c", "-f", "-"],
            input=ruleset,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, f"nft check failed: {result.stderr}")

    def test_hardened_ruleset_is_valid_nft(self) -> None:
        """Hardened ruleset passes nft syntax check."""
        ruleset = hardened_ruleset()
        result = subprocess.run(
            ["nft", "-c", "-f", "-"],
            input=ruleset,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, f"nft check failed: {result.stderr}")
