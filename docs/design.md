# Architecture

## Firewall mode

### Hook mode

Uses OCI hooks to apply per-container nftables rules inside the container's own
network namespace. Each container gets an isolated firewall. Works with pasta
(rootless default) and slirp4netns.

Lifecycle: `Shield.pre_start()` installs the OCI hook (idempotent), resolves DNS,
writes `profile.allowed`, and returns podman args with annotations. On each
container start, the OCI hook reads those annotations and applies the ruleset.

## Allowlisting

Allowlists are `.txt` files with one entry per line — domain names or raw
IP/CIDRs. Lines starting with `#` are comments.

Bundled defaults use domain names because they're stable across IP rotations and
easy to audit. Resolution happens via `dig +short A` at pre-start time. Resolved
IPs are cached in `profile.allowed` with `st_mtime`-based freshness (default
1 hour).

### Bundled profiles

| Profile | Contents |
|---------|----------|
| `base.txt` | OS repos (Ubuntu, Debian, Fedora, Alpine), NTP, OCSP/CRL |
| `dev-standard.txt` | GitHub, Docker Hub, PyPI, npm, crates.io, Go proxy, GitLab |
| `dev-python.txt` | PyPI, conda-forge, readthedocs |
| `dev-node.txt` | npm, Yarn, jsDelivr, unpkg |
| `nvidia-hpc.txt` | CUDA toolkit, NGC, NVIDIA repos |

Users can add custom profiles in `$XDG_CONFIG_HOME/terok-shield/profiles/`.

## Audit logging

### JSON-lines lifecycle logs

Each container has its own audit log at `{state_dir}/audit.jsonl`. Each
`HookExecutor.apply()` step produces a separate entry:

```json
{"ts":"...","container":"myproj-1","action":"setup","detail":"ruleset applied"}
{"ts":"...","container":"myproj-1","action":"setup","detail":"[ips] cached: 1.1.1.1, 1.0.0.1"}
{"ts":"...","container":"myproj-1","action":"setup","detail":"verification passed"}
```

Detail lines prefixed with `[ips]` contain full IP lists. The `"note"` action
is used for RFC1918 and link-local allowlisting events. Audit logging is
best-effort — failures are silently ignored to avoid blocking container
operations.

### Kernel per-packet logs

nftables log rules generate per-packet entries in dmesg/journald:

- `TEROK_SHIELD_ALLOWED:` — traffic hitting the allow set (rate-limited)
- `TEROK_SHIELD_DENIED:` — traffic rejected by the deny-all rule
- `TEROK_SHIELD_RFC1918:` — non-allowlisted RFC1918 traffic rejected

## Public API

The package exports a `Shield` facade class for integration with
[terok](https://github.com/terok-ai/terok):

```python
from pathlib import Path
from terok_shield import Shield, ShieldConfig
shield = Shield(ShieldConfig(state_dir=Path("/path/to/state")))
```

| Method | Purpose |
|--------|---------|
| `pre_start(container, profiles)` | Install hooks, resolve DNS, return extra podman args |
| `allow(container, target)` | Live-allow a domain/IP for a running container |
| `deny(container, target)` | Live-deny a domain/IP (best-effort) |
| `down(container)` | Switch to bypass mode (accept-all + log) |
| `up(container)` | Restore deny-all mode |
| `state(container)` | Query container shield state (`UP`, `DOWN`, `DOWN_ALL`, `INACTIVE`) |
| `rules(container)` | Return current nft ruleset for a container |
| `resolve(container, profiles)` | Resolve DNS profiles and cache results |
| `status()` | Return mode, profiles, audit config |
| `preview(down, allow_all)` | Show ruleset that would be applied |

`ShieldConfig` is a frozen dataclass with required `state_dir: Path` and
optional mode, default profiles, loopback ports, profiles dir, and audit
settings. The library never reads environment variables or config files — all
configuration comes from the caller.

terok imports terok-shield as a library dependency and calls the Python API
directly — never the CLI.

## Module structure

| Module | Role |
|--------|------|
| `__init__.py` | `Shield` facade — public API entry point |
| `nft.py` | **Security boundary** — ruleset generation, input validation, self-verification |
| `nft_constants.py` | Shared literals (`NFT_TABLE`, `RFC1918`) — no logic |
| `config.py` | `ShieldConfig`, `ShieldMode`, `ShieldState`, `ShieldModeBackend` protocol, annotation constants |
| `state.py` | Per-container state bundle layout — pure path derivation, zero deps |
| `mode_hook.py` | Hook mode strategy (OCI hooks, per-container netns) |
| `oci_hook.py` | OCI hook entry point — fail-closed firewall application |
| `dns.py` | Stateless DNS resolution via `dig`, file-based caching |
| `profiles.py` | Profile loading and composition |
| `audit.py` | JSON-lines audit logging (single file per container) |
| `run.py` | Subprocess wrappers (`nft`, `nsenter`, `dig`, `podman`) |
| `validation.py` | Input validation (container names, path safety) |
| `util.py` | Small shared utilities |
| `cli.py` | Standalone CLI entry point + config construction from env/YAML |

Module boundaries are enforced by [tach](https://github.com/gauge-sh/tach)
(`tach.toml`). The critical constraint: `nft.py` may only import from
`nft_constants.py` and stdlib.
