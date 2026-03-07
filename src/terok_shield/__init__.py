# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""terok-shield: nftables-based egress firewalling for Podman containers."""

__version__ = "0.1.0"

from .config import ShieldConfig, ShieldMode, load_shield_config

__all__ = ["ShieldConfig", "ShieldMode", "load_shield_config"]
