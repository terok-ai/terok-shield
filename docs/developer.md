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
make test-unit        # unit tests with coverage
make check            # core local suite (lint + test-unit + tach + security + docstrings + deadcode + reuse)

# Integration tests (filtered by marker)
make test-integration-host    # -m "needs_host_features" — host-only, no containers
make test-integration-network # -m "needs_internet and not needs_podman" — needs dig + internet
make test-integration-podman  # -m "needs_podman" — needs podman + nft + internet
make test-integration # all integration tests
make test-integration-map     # generate integration test map (Markdown)
make ci-map           # generate CI workflow map (Markdown)

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
make test-unit    # runs tests/unit/ with coverage
```

Unit tests mock all subprocess calls. Filesystem access uses real temp
directories (`tmp_path`). No network, no containers. Generated local reports
go under `reports/`.

### Integration tests

Integration tests are organized by **workflow/feature area** (not environment tier).
Environment requirements are expressed via pytest markers:

| Marker | What it needs | CI |
|--------|---------------|-----|
| `needs_host_features` | Linux kernel only (IP_RECVERR, filesystem) | Yes |
| `needs_internet` | `dig` + outbound internet | No |
| `needs_podman` | podman + nft (+ internet) | No |

Directories group tests by what they test: `setup/`, `launch/`, `blocking/`,
`allow_deny/`, `dns/`, `bypass/`, `observability/`, `safety/`, `cli/`. See
the [Integration Test Map](test-map.md) for a full listing. See the
[CI Workflow Map](ci-map.md) for the generated workflow/job inventory.

Skip guards (`podman_missing`, `nft_missing`, `dig_missing`) handle
graceful degradation when binaries are absent.

`needs_host_features` tests run in CI alongside unit tests. `needs_podman`
and `needs_internet` tests can be triggered manually via the **Integration
Tests** workflow (`workflow_dispatch`).

### Network access

Integration tests marked `needs_internet` or `needs_podman` make outbound
connections to public DNS services (Cloudflare, Google). All targets are
defined in
[`tests/testnet.py`](https://github.com/terok-ai/terok-shield/blob/master/tests/testnet.py).
No private or authenticated endpoints are contacted.

**Never hardcode IP addresses, URLs, or domain names in test files.** Define
named constants in `tests/testnet.py` and import them. This centralizes
SonarCloud suppressions and keeps network dependencies auditable in one place.
