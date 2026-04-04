# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Security-critical core modules for terok-shield.

This subpackage contains the auditable security boundary: nftables
ruleset generation, DNS resolution, dnsmasq lifecycle management,
OCI hook execution, state-bundle path derivation, and subprocess
execution.  All code here is subject to security audit.
"""
