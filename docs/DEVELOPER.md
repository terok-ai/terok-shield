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

# Integration tests (each target = one directory)
make test-host        # tests/integration/host/    — host-only, no containers
make test-network     # tests/integration/network/ — needs dig + internet
make test-podman      # tests/integration/podman/  — needs podman + nft + internet
make test-integration # all tiers

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

## Testing

### Unit tests

```bash
make test    # runs tests/unit/ with coverage
```

Unit tests mock all subprocess calls and filesystem access. No network, no
containers.

### Integration tests

Integration tests are organized into directories by environment requirements:

| Directory | Marker | What it needs | CI |
|-----------|--------|---------------|-----|
| `host/` | `needs_host_features` | Linux kernel only (IP_RECVERR, filesystem) | Yes |
| `network/` | `needs_internet` | `dig` + outbound internet | No |
| `podman/` | `needs_podman` + `needs_internet` | podman + nft + internet | No |

Run any tier by targeting its directory — or right-click the directory in your
IDE. Skip markers (`podman_missing`, `nft_missing`, `dig_missing`) handle
graceful degradation when binaries are absent.

`host/` tests run in CI alongside unit tests. `podman/` and `network/` tests
can be triggered manually via the **Integration Tests** workflow
(`workflow_dispatch`).

### Network access

Integration tests in `network/` and `podman/` make outbound connections to
public DNS services (Cloudflare, Google). All targets are defined in
[`tests/testnet.py`](https://github.com/terok-ai/terok-shield/blob/master/tests/testnet.py).
No private or authenticated endpoints are contacted.

**Never hardcode IP addresses, URLs, or domain names in test files.** Define
named constants in `tests/testnet.py` and import them. This centralizes
SonarCloud suppressions and keeps network dependencies auditable in one place.
