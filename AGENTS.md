# Agent Guide (terok-shield)

## Purpose

`terok-shield` provides nftables-based egress firewalling for rootless Podman containers. It enforces default-deny outbound network filtering with curated allowlists (domains and IPs) and connection audit logging.

## Technology Stack

- **Language**: Python 3.12+
- **Package Manager**: Poetry
- **Testing**: pytest with coverage
- **Linting/Formatting**: ruff
- **Module Boundaries**: tach (enforced in CI via `tach.toml`)
- **Security**: bandit (SAST)

## Repo layout

- `src/terok_shield/`: Python package (CLI in `cli.py`, command registry in `registry.py`, engine modules at top level)
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
make test-unit   # Run unit tests with coverage
make tach       # Check module boundary rules (tach.toml)
make docstrings # Check docstring coverage (minimum 95%)
make reuse      # Check REUSE (SPDX license/copyright) compliance
make check      # Run lint + test-unit + tach + security + docstrings + deadcode + reuse
```

**Integration tests (filtered by marker):**
```bash
poetry install --with test  # ensure terok-shield is installed in Poetry's venv
make test-integration-host    # -m "needs_host_features" (no containers, runs in CI)
make test-integration-network # -m "needs_internet and not needs_podman" (dig + internet)
make test-integration-podman  # -m "needs_podman" (podman + nft + internet)
make test-integration       # all integration tests
make test-integration-map   # generate integration test map (Markdown)
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
- **No literal IPs/URLs in tests**: Never hardcode IP addresses, URLs, or domain names directly in test files. Instead, define named constants in `tests/testnet.py` and import them. This centralizes SonarCloud suppressions and makes network dependencies auditable
- **No literal filesystem paths in tests**: Never hardcode filesystem paths (`/tmp/...`, `/nonexistent/...`, `/etc/passwd`, `/usr/bin/nft`, etc.) directly in test files. Instead, define named constants in `tests/testfs.py` and import them. This centralizes SonarCloud suppressions for path-related security hotspots. Derive subpaths from base constants (e.g. `NONEXISTENT_DIR / "logs"`) rather than defining a new constant for every variant
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
- **Documentation filenames**: Markdown files under `docs/` use `lowercase.md` naming (e.g. `getting_started.md`, `cli.md`, `modes.md`) to match the MkDocs `index.md` convention. Root-level project files (e.g. `README.md`, `AGENTS.md`) stay UPPERCASE per standard convention.

## Security Boundary

`nft.py` is the auditable security boundary:
- **Only stdlib + `nft_constants.py` imports** (`ipaddress`, `re`, `textwrap`, and the literals-only `nft_constants`)
- All inputs validated (`safe_ip()`, `safe_name()`) before string interpolation
- Allowlisting private-range addresses (RFC 1918/RFC 4193) or large CIDRs generates a notice in the audit log
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
4. Run `make test-unit` to verify changes
5. If you added or changed cross-module imports, run `make tach` to verify module boundary rules
6. Run `make check` before pushing

## Integration Tests

Integration tests live in `tests/integration/` and are organized by **workflow/feature area**. Environment requirements are expressed via pytest markers, not directory placement:

| Directory | What it tests |
|-----------|--------------|
| `setup/` | Hook install, config paths, profiles, auto-detect |
| `launch/` | pre_start, apply_hook, hook_main, nft apply |
| `blocking/` | Default-deny, IPv6 drop, private-range reject, ICMP probe |
| `allow_deny/` | shield_allow/deny, CLI allow/deny, nft elements |
| `dns/` | resolve, caching, force-refresh, profile→DNS pipeline |
| `bypass/` | shield down/up, state detection, bypass traffic, lifecycle E2E |
| `observability/` | status, rules, logs, audit trail |
| `safety/` | Fail-closed error paths |
| `cli/` | CLI parsing/help (no container needed) |

Makefile targets filter by marker (not by directory):

```bash
poetry install --with test  # install package + test deps into Poetry's venv
make test-integration-host    # -m "needs_host_features" (fast, runs in CI)
make test-integration-network # -m "needs_internet and not needs_podman" (dig + internet)
make test-integration-podman  # -m "needs_podman" (podman + nft + internet)
make test-integration       # all integration tests
make test-integration-map   # generate integration test map (Markdown)
```

- **Markers**: `needs_host_features`, `needs_internet`, `needs_podman` — for test selection
- **Skip guards**: `podman_missing`, `nft_missing`, `dig_missing` — graceful degradation when binaries are absent
- `tests/integration/conftest.py` provides all shared fixtures: `container`, `container_pid`, `nft_in_netns`, `shielded_container`, `shield_env`, `nsenter_nft()`
- `tests/integration/helpers.py` provides assertion helpers: `assert_blocked`, `assert_reachable`, `assert_ruleset_applied`, `exec_in_container`, `wget`
- nft commands run inside the container's network namespace via `podman unshare nsenter -t PID -n nft` (not the host netns — rootless nft only has `CAP_NET_ADMIN` inside container-owned namespaces)

## Architecture

The library is a pure function of its inputs. Given a `ShieldConfig` with `state_dir`, it writes to that directory and nowhere else. No env-var reading, no config-file parsing inside the library.

### Core types

- **`ShieldConfig`** (frozen dataclass) — per-container configuration with required `state_dir: Path`
- **`Shield`** (facade) — public API; delegates to collaborators injected via constructor
- **`HookMode`** (strategy) — nft-based hook mode implementation of `ShieldModeBackend` protocol
- **`HookExecutor`** (command) — applies nft ruleset inside a container's netns
- **`AuditLogger`** — writes JSONL audit events to a single file
- **`DnsResolver`** — stateless DNS resolution; takes explicit `cache_path` parameter
- **`ProfileLoader`** — loads `.txt` allowlists from bundled + user directories
- **`RulesetBuilder`** — generates and verifies nft rulesets

### Per-container state bundle

Each container gets an isolated `state_dir` with this layout:

```text
{state_dir}/
├── hooks/
│   ├── terok-shield-createRuntime.json
│   └── terok-shield-poststop.json
├── terok-shield-hook              # entrypoint script
├── profile.allowed                # IPs from DNS resolution
├── live.allowed                   # IPs from allow/deny
└── audit.jsonl                    # per-container audit log
```

Path functions in `state.py` derive all paths from `state_dir`. `BUNDLE_VERSION` in `state.py` provides a cross-process contract between `pre_start()` and the OCI hook.

### Data flow

1. **CLI / terok** constructs `ShieldConfig(state_dir=...)` and creates `Shield(config)`
2. **`Shield.pre_start()`** installs hooks, resolves DNS → writes `profile.allowed`, sets OCI annotations (`state_dir`, `loopback_ports`, `version`), returns podman args
3. **OCI hook** (`hook_main()`) reads annotations, constructs `HookExecutor(state_dir=...)`, reads `profile.allowed` + `live.allowed`, applies nft ruleset
4. **`Shield.allow()` / `deny()`** modify nft sets immediately + persist to `live.allowed`
5. **`Shield.up()`** re-applies ruleset, restoring IPs from both allowlist files

### Configuration layer separation

- **Library** (`config.py`): Pure data definitions — `ShieldConfig`, `ShieldMode`, `ShieldState`, `ShieldModeBackend` protocol, annotation constants
- **Registry** (`registry.py`): Command definitions (`CommandDef`, `ArgDef`, `COMMANDS`) and reusable handler functions — single source of truth for all CLI subcommands
- **CLI** (`cli.py`): Config construction — reads `config.yml`, env vars, XDG paths; builds `ShieldConfig` for each command; builds argparse from the registry

## Key Guidelines

- **Fail-closed**: Any hook/ruleset failure must prevent the container from starting unrestricted
- **Allowlisting**: Both IP addresses and DNS domains are supported in `.txt` allowlists; bundled defaults use DNS names because they are more stable and easier to audit
- **Minimal changes**: Make surgical, focused changes
- **Existing tests**: Never remove or modify unrelated tests
- **Dependencies**: Use Poetry; the only runtime dependency is PyYAML
