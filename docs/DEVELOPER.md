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
- **SPDX headers** on all `.py` files — use `make spdx` to add them
- **Docstrings** on all public functions (95% coverage enforced)
- **`nft.py` must not import non-stdlib modules** — this is the auditable security boundary

## Testing

```bash
make test
```

Tests live in `tests/` and mirror the source structure. When adding new functionality, add corresponding tests.
