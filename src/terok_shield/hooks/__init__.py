# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""OCI hook system — installation and per-container lifecycle.

Collaborators:
    install — hook file generation and installation into hooks directories
    mode — HookMode strategy: per-container nft ruleset lifecycle via OCI hooks
"""
