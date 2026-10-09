# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Pydantic schema for the CLI-loaded ``config.yml``.

The library proper is a pure function of its inputs and never reads a
config file — that concern belongs to the CLI (``cli/main.py``), which
loads and validates ``config.yml`` into a
[`ShieldFileConfig`][terok_shield.config_file.ShieldFileConfig] before
constructing a [`ShieldConfig`][terok_shield.config.ShieldConfig].

Kept apart from [`config`][terok_shield.config] so that importing the
package's public data vocabulary (``ShieldConfig``, ``ShieldMode``, …)
does not drag in pydantic: the schema below is the sole pydantic user
in the library, and only the CLI path touches it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

#: One count and one unit, the same grammar the nft element carries
#: (``terok_shield.nft.rules`` validates it again before interpolating).
_NFT_TIMEOUT_RE = re.compile(r"\d+[smhd]")


class AuditFileConfig(BaseModel):
    """Audit section of ``config.yml``."""

    enabled: bool = Field(default=True, description="Enable per-container JSON-lines audit logging")
    model_config = ConfigDict(extra="forbid")


class ShieldFileConfig(BaseModel):
    """Validated schema for ``config.yml``.

    Loaded by the CLI at startup.  ``extra="forbid"`` rejects unknown
    keys so typos (e.g. ``mod: hook``) produce a clear error instead
    of being silently ignored.
    """

    mode: Literal["auto", "hook"] = Field(
        default="auto",
        description="Firewall mode: ``auto`` selects the best available; ``hook`` forces OCI hook mode",
    )
    default_profiles: list[str] = Field(
        default_factory=list,
        description="Profiles applied when a command does not pass ``--profiles``; an empty list applies none",
    )
    audit: AuditFileConfig = Field(
        default_factory=AuditFileConfig, description="Audit logging settings"
    )
    dnsmasq_path: Path | None = Field(
        default=None,
        description="dnsmasq binary to run; found on the current host PATH when unset",
    )
    bypass_duration: str = Field(
        default="5m",
        description="How long the timed allow-all window stays open when no duration is named",
    )
    model_config = ConfigDict(extra="forbid")

    @field_validator("bypass_duration")
    @classmethod
    def _duration_is_an_nft_timeout(cls, v: str) -> str:
        """Reject at load what nft would reject at arm time — a count and one unit."""
        if not _NFT_TIMEOUT_RE.fullmatch(v):
            raise ValueError(
                f"bypass_duration must be an nft timeout such as '5m' or '2h', got {v!r}"
            )
        return v

    @field_validator("default_profiles")
    @classmethod
    def _profile_names_non_empty(cls, v: list[str]) -> list[str]:
        """Ensure every profile name is a non-empty string; an empty list names no profile."""
        if not all(isinstance(p, str) and p for p in v):
            raise ValueError("each profile must be a non-empty string")
        return v
