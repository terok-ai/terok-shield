# Contributing

## Development setup

```bash
git clone git@github.com:terok-ops/terok-shield.git
cd terok-shield
make install-dev
```

## Commands

```bash
make lint        # ruff check + format check
make format      # auto-fix
make test        # pytest with coverage
make security    # bandit SAST scan
make docstrings  # docstring coverage (95% minimum)
make deadcode    # vulture dead code check
make reuse       # SPDX license compliance
make check       # all of the above
make docs        # serve documentation locally
make docs-build  # build documentation for deployment
```

## Module overview

| File | Role |
|------|------|
| `nft.py` | **Security boundary** — nftables ruleset generation, input validation, self-verification. Zero non-stdlib imports. |
| `config.py` | `ShieldConfig` dataclass, `ShieldMode` enum, path helpers, config loading |
| `run.py` | Subprocess wrappers for `nft`, `nsenter`, `dig`, `podman inspect` |
| `dns.py` | Domain allowlist parsing, DNS resolution, timestamp-based caching |
| `profiles.py` | Profile (domain list) loading and composition |
| `hook.py` | OCI hook entry point — fail-closed container firewall application |
| `standard.py` | Standard mode lifecycle (OCI hooks, per-container netns) |
| `hardened.py` | Hardened mode lifecycle (bridge network, rootless-netns) |
| `audit.py` | JSON-lines audit logging |
| `cli.py` | Standalone CLI entry point |

## Conventions

- **Python 3.12+** with type hints
- **ruff** for linting and formatting (100 char line length)
- **SPDX headers** on all `.py` files — use `make spdx NAME="Real Human Name" FILES="path"` to add them. NAME must be the real name (ASCII-only) of the person who created the file. Use a single year, not a range
- **Docstrings** on all public functions (95% coverage enforced)
- **`nft.py` must not import non-stdlib modules** — this is the auditable security boundary

## Testing

```bash
make test        # unit tests (no network, no podman)
make test-podman # integration tests (requires podman, nft, internet)
make check       # full CI suite (unit tests + lint + tach + ...)
```

Tests live in `tests/` and mirror the source structure. When adding new functionality,
add corresponding tests.

### Integration tests and network access

The integration tests in `tests/integration/` exercise real container networking
and **make outbound connections to the public internet**. They require:

- `podman` and `nft` installed
- Outbound internet access (HTTP/HTTPS and DNS)

The following external IPs, domains, and URLs are contacted during test runs.
This list is auto-generated from
[`tests/testnet.py`](https://github.com/terok-ops/terok-shield/blob/master/tests/testnet.py):

```python
--8<-- "tests/testnet.py:outbound-targets"
```

All targets are well-known public DNS services. No private or
authenticated endpoints are contacted. If your environment blocks
outbound traffic, these tests will be skipped automatically (the
`_check_internet()` helper detects missing connectivity).

### Integration tests in CI

Integration tests are excluded from the main CI workflow (`-m "not integration"`).
A separate **Integration Tests** workflow can be triggered manually from the
Actions tab (`workflow_dispatch`) — select the workflow, pick the branch, and run.
