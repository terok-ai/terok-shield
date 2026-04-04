# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""CLI and tool entry points for terok-shield.

This subpackage contains presentation-layer code: argument parsing,
command dispatch, interactive verdict loops, and the ``shield watch``
event-streaming entry point.  Library consumers should import from
``terok_shield`` (the public API facade) rather than from here.
"""
