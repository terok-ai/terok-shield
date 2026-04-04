# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Support-layer library modules for terok-shield.

Non-security-critical library code: event-stream watchers, profile
loading, and audit logging.  These modules may import from ``core``
and ``common`` but never from ``cli``.
"""
