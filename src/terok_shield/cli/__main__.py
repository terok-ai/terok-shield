# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""Package entry point so ``python -m terok_shield.cli`` works.

[`simple_clearance`][terok_shield.simple_clearance] shells out to
``python -m terok_shield.cli`` to apply operator verdicts, threading
the parent's ``sys.path`` through
[`child_process_env`][terok_shield.subprocess_env.child_process_env]
so Nix-wrapped interpreters still resolve the package.  Without an
explicit ``__main__`` module the ``-m`` switch refuses to execute the
package and every verdict fails as ``! verdict failed for <dest>``.

Delegates verbatim to [`main`][terok_shield.cli.main.main]; the
launch round-trip is regression-tested in
``tests/unit/test_cli_main_module.py``.
"""

from terok_shield.cli.main import main

main()
