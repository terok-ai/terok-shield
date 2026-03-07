# Agent Guide (terok-shield)

## Purpose

`terok-shield` provides nftables-based egress firewalling for rootless Podman containers. It enforces default-deny outbound network filtering with curated domain allowlists, RFC1918/link-local blocking, and connection audit logging.

## Technology Stack

- **Language**: Python 3.12+
- **Package Manager**: Poetry
- **Testing**: pytest with coverage
- **Linting/Formatting**: ruff
- **Module Boundaries**: tach (enforced in CI via `tach.toml`)
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
make tach       # Check module boundary rules (tach.toml)
make docstrings # Check docstring coverage (minimum 95%)
make reuse      # Check REUSE (SPDX license/copyright) compliance
make check      # Run lint + test + tach + security + docstrings + deadcode + reuse (equivalent to CI)
```

**Integration tests (requires podman + nft on the host):**
```bash
make test-podman  # Run integration tests against real podman containers
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
- **Pythonic style**: Prefer modern Pythonic constructs (comprehensions, ternary expressions, walrus operator, unpacking) where they improve readability
- **Testing**: Add tests for new functionality; maintain coverage
- **SPDX headers**: Every source file (`.py`, `.sh`, etc.) must have an SPDX header. Use `make spdx` to add or update it — it handles both new files and existing files correctly:
  ```bash
  make spdx NAME="Real Human Name" FILES="path/to/file.py"
  ```
  - **New file** → creates the header:
    ```python
    # SPDX-FileCopyrightText: 2026 Jiri Vyskocil
    # SPDX-License-Identifier: Apache-2.0
    ```
  - **Existing file** → adds an additional copyright line (preserves the original):
    ```python
    # SPDX-FileCopyrightText: 2026 Jiri Vyskocil
    # SPDX-FileCopyrightText: 2026 New Contributor
    # SPDX-License-Identifier: Apache-2.0
    ```
  When modifying an existing file, always run `make spdx` with the contributor's name to add their copyright line. NAME must be a real person's name (ASCII-only), not a project name. Use a single year (year of first contribution), not a range. Ask the user for their name if unknown. Files covered by `REUSE.toml` glob patterns (`.md`, `.yml`, `.toml`, `.json`, etc.) do not need inline headers.

## Security Boundary

`nft.py` is the auditable security boundary:
- **Only stdlib + `nft_constants.py` imports** (`ipaddress`, `re`, `textwrap`, and the literals-only `nft_constants`)
- All inputs validated (`safe_ip()`, `safe_name()`) before string interpolation
- RFC1918 blocks structurally before allow-set checks (ordering is load-bearing)
- Enforced by AST import isolation test + bandit SAST

## Module Boundaries (tach)

The project uses [tach](https://github.com/gauge-sh/tach) to enforce module boundary rules defined in `tach.toml`. The critical constraint: `nft.py` may only import from `nft_constants.py` (and stdlib). When adding new cross-module imports:

- Check `tach.toml` for allowed dependencies
- Run `make tach` to verify
- If adding a new dependency between modules, update `depends_on` in `tach.toml`
- CI will reject boundary violations

## Development Workflow

1. Make changes in `src/terok_shield/`
2. Run `make lint` frequently during development
3. Add/update tests in `tests/`
4. Run `make test` to verify changes
5. If you added or changed cross-module imports, run `make tach` to verify module boundary rules
6. Run `make check` before pushing

## Integration Tests

Integration tests live in `tests/integration/` and require podman and nft on the host. They are **not** run in CI (GitHub Actions lacks nftables kernel support for user namespaces). Run them manually via `make test-podman`.

- Tests use `@pytest.mark.integration` and skip markers (`podman_missing`, `nft_unusable`) from `conftest.py`
- `conftest.py` provides fixtures: `container` (disposable Alpine container), `container_pid`, and the `nsenter_nft()` helper
- nft commands run inside the container's network namespace via `podman unshare nsenter -t PID -n nft`

## Key Guidelines

- **Fail-closed**: Any hook/ruleset failure must prevent the container from starting unrestricted
- **Allowlisting**: Both IP addresses and DNS domains are supported in `.txt` allowlists; bundled defaults use DNS names because they are more stable and easier to audit
- **Minimal changes**: Make surgical, focused changes
- **Existing tests**: Never remove or modify unrelated tests
- **Dependencies**: Use Poetry; the only runtime dependency is PyYAML
