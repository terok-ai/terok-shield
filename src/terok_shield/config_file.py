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

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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
        description="dnsmasq binary to run; found on PATH and in the sbin directories when unset",
    )
    model_config = ConfigDict(extra="forbid")

    @field_validator("default_profiles")
    @classmethod
    def _profile_names_non_empty(cls, v: list[str]) -> list[str]:
        """Ensure every profile name is a non-empty string; an empty list names no profile."""
        if not all(isinstance(p, str) and p for p in v):
            raise ValueError("each profile must be a non-empty string")
        return v
