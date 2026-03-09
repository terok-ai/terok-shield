# Contributing

## Development setup

```bash
git clone git@github.com:terok-ai/terok-shield.git
cd terok-shield
make install-dev
```

## Commands

```bash
# Before every commit
make lint             # ruff check + format check
make format           # auto-fix lint issues

# Before pushing
make test             # unit tests with coverage
make check            # full CI suite (lint + test + tach + security + docstrings + deadcode + reuse)

# Integration tests (filtered by marker)
make test-host        # -m "needs_host_features" — host-only, no containers
make test-network     # -m "needs_internet and not needs_podman" — needs dig + internet
make test-podman      # -m "needs_podman" — needs podman + nft + internet
make test-integration # all integration tests
make test-map         # generate integration test map (Markdown)

# Other
make tach             # check module boundary rules
make security         # bandit SAST scan
make docstrings       # docstring coverage (95% minimum)
make reuse            # SPDX license compliance
make docs             # serve documentation locally
```

## Conventions

- **Python 3.12+** with modern type hints (`X | None`, not `Optional[X]`)
- **ruff** for linting and formatting (100 char line length)
- **SPDX headers** on all `.py` files — use `make spdx NAME="Real Human Name" FILES="path"`
- **Docstrings** on all public functions (95% coverage enforced in CI)
- **`nft.py` must not import non-stdlib modules** — auditable security boundary
- **Module boundaries** enforced by tach (`tach.toml`) — run `make tach` after changing imports
- **Documentation filenames** under `docs/` use `lowercase.md` (e.g. `getting_started.md`, `cli.md`) to match MkDocs convention; root-level files (`README.md`, `AGENTS.md`) stay UPPERCASE

## Testing

### Unit tests

```bash
make test    # runs tests/unit/ with coverage
```

Unit tests mock all subprocess calls and filesystem access. No network, no
containers.

### Integration tests

Integration tests are organized by **workflow/feature area** (not environment tier).
Environment requirements are expressed via pytest markers:

| Marker | What it needs | CI |
|--------|---------------|-----|
| `needs_host_features` | Linux kernel only (IP_RECVERR, filesystem) | Yes |
| `needs_internet` | `dig` + outbound internet | No |
| `needs_podman` | podman + nft (+ internet) | No |

Directories group tests by what they test: `setup/`, `launch/`, `blocking/`,
`allow_deny/`, `dns/`, `observability/`, `safety/`, `cli/`. See the
[Integration Test Map](test_map.md) for a full listing.

Skip guards (`podman_missing`, `nft_missing`, `dig_missing`) handle
graceful degradation when binaries are absent.

`needs_host_features` tests run in CI alongside unit tests. `needs_podman`
and `needs_internet` tests can be triggered manually via the **Integration
Tests** workflow (`workflow_dispatch`).

### Network access

Integration tests in `network/` and `podman/` make outbound connections to
public DNS services (Cloudflare, Google). All targets are defined in
[`tests/testnet.py`](https://github.com/terok-ai/terok-shield/blob/master/tests/testnet.py).
No private or authenticated endpoints are contacted.

**Never hardcode IP addresses, URLs, or domain names in test files.** Define
named constants in `tests/testnet.py` and import them. This centralizes
SonarCloud suppressions and keeps network dependencies auditable in one place.
