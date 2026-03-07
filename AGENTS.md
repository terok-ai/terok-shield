# Agent Guide (terok-shield)

## Purpose

`terok-shield` provides nftables-based egress firewalling for rootless Podman containers. It enforces default-deny outbound network filtering with curated domain allowlists, RFC1918/link-local blocking, and connection audit logging.

## Technology Stack

- **Language**: Python 3.12+
- **Package Manager**: Poetry
- **Testing**: pytest with coverage
- **Linting/Formatting**: ruff
- **Security**: bandit (SAST)

## Repo layout

- `src/terok_shield/`: Python package (CLI in `cli.py`, engine modules at top level)
- `tests/`: `pytest` test suite
- `src/terok_shield/resources/dns/`: Bundled DNS domain allowlists

## Build, Lint, and Test Commands

**Before committing:**
```bash
make lint      # Run linter (required before every commit)
make format    # Auto-fix lint issues if lint fails
```

**Before pushing:**
```bash
make test       # Run full test suite with coverage
make docstrings # Check docstring coverage (minimum 95%)
make reuse      # Check REUSE (SPDX license/copyright) compliance
make check      # Run lint + test + security + docstrings + deadcode + reuse (equivalent to CI)
```

**Other useful commands:**
```bash
make install-dev  # Install all development dependencies
make security     # Run bandit SAST scan
make clean        # Remove build artifacts
make spdx NAME="Real Human Name" FILES="src/terok_shield/new_file.py"  # Add SPDX header
```

## Coding Standards

- **Style**: Follow ruff configuration in `pyproject.toml`
- **Line length**: 100 characters (ruff formatter target; `E501` is disabled so long strings that cannot be auto-wrapped are tolerated)
- **Imports**: Sorted with isort (part of ruff)
- **Type hints**: Use Python 3.12+ type hints
- **Docstrings**: Required for all public functions, classes, and modules (enforced by `docstr-coverage` at 95% minimum in CI)
- **Testing**: Add tests for new functionality; maintain coverage
- **SPDX headers**: Every source file (`.py`, `.sh`, etc.) must start with a compact two-line SPDX header — no blank line between them:
  ```python
  # SPDX-FileCopyrightText: 2026 Jiri Vyskocil
  # SPDX-License-Identifier: Apache-2.0
  ```
  Use `make spdx NAME="Real Human Name" FILES="path/to/file.py"` to add headers. Files covered by `REUSE.toml` glob patterns (`.md`, `.yml`, `.toml`, `.json`, etc.) do not need inline headers. `make reuse` checks compliance.
  **Copyright holder**: NAME must be the real name (ASCII-only) of the person who created or modified the file — not a project name. When creating new files, ask the user for their name if unknown. When modifying an existing file that already has an SPDX header, add a second copyright line with the contributor's name — do not replace the original author.
  **Year**: Use a single year (the year when that author first created or modified the file), not a range. Example: `2026 Jiri Vyskocil`, not `2025-2026 Jiri Vyskocil`.

## Security Boundary

`nft.py` is the auditable security boundary:
- **Zero non-stdlib imports** (only `ipaddress`, `re`, `textwrap`)
- All inputs validated (`safe_ip()`, `safe_name()`) before string interpolation
- RFC1918 blocks structurally before allow-set checks (ordering is load-bearing)
- Enforced by AST import isolation test + bandit SAST

## Development Workflow

1. Make changes in `src/terok_shield/`
2. Run `make lint` frequently during development
3. Add/update tests in `tests/`
4. Run `make test` to verify changes
5. Run `make check` before pushing

## Key Guidelines

- **Fail-closed**: Any hook/ruleset failure must prevent the container from starting unrestricted
- **Allowlisting**: Both IP addresses and DNS domains are supported in `.txt` allowlists; bundled defaults use DNS names because they are more stable and easier to audit
- **Minimal changes**: Make surgical, focused changes
- **Existing tests**: Never remove or modify unrelated tests
- **Dependencies**: Use Poetry; the only runtime dependency is PyYAML
