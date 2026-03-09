# Architecture

## Firewall mode

### Hook mode

Uses OCI hooks to apply per-container nftables rules inside the container's own
network namespace. Each container gets an isolated firewall. Works with pasta
(rootless default) and slirp4netns.

Lifecycle: `shield_setup()` installs the OCI hook script. On each container
start, the hook applies the ruleset and loads cached IPs into the allow set.

## Allowlisting

Allowlists are `.txt` files with one entry per line — domain names or raw
IP/CIDRs. Lines starting with `#` are comments.

Bundled defaults use domain names because they're stable across IP rotations and
easy to audit. Resolution happens via `dig +short A` at setup/runtime. Resolved
IPs are cached with `st_mtime`-based freshness (default 1 hour).

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

Firewall events are written as JSON-lines to `state_dir/logs/{container}.jsonl`.
Each `apply_hook()` step produces a separate entry:

```json
{"ts":"...","container":"myproj-1","action":"setup","detail":"ruleset applied"}
{"ts":"...","container":"myproj-1","action":"setup","detail":"[ips] cached: 1.1.1.1, 1.0.0.1"}
{"ts":"...","container":"myproj-1","action":"setup","detail":"verification passed"}
```

Detail lines prefixed with `[ips]` contain full IP lists. The `"note"` action
is used for RFC1918 and link-local allowlisting events. Audit logging is best-effort — failures
are silently ignored to avoid blocking container operations.

### Kernel per-packet logs

nftables log rules generate per-packet entries in dmesg/journald:

- `TEROK_SHIELD_ALLOWED:` — traffic hitting the allow set (rate-limited)
- `TEROK_SHIELD_DENIED:` — traffic rejected by the deny-all rule
- `TEROK_SHIELD_RFC1918:` — non-allowlisted RFC1918 traffic rejected

## Public API

The package exports a lifecycle-oriented API for integration with
[terok](https://github.com/terok-ai/terok):

| Function | Purpose |
|----------|---------|
| `shield_setup()` | Install OCI hook |
| `shield_status()` | Return mode, profiles, audit config |
| `shield_pre_start()` | Return extra podman args |
| `shield_resolve()` | Resolve DNS profiles and cache results |
| `shield_allow()` | Live-allow a domain/IP for a running container |
| `shield_deny()` | Live-deny a domain/IP (best-effort) |
| `shield_rules()` | Return current nft ruleset for a container |

All functions accept an optional `config: ShieldConfig` parameter (defaults to
`load_shield_config()` if `None`). The config is a frozen dataclass with mode,
default profiles, gate port, and audit settings.

terok imports terok-shield as a library dependency and calls the Python API
directly — never the CLI.

## Module structure

| Module | Role |
|--------|------|
| `nft.py` | **Security boundary** — ruleset generation, input validation, self-verification |
| `nft_constants.py` | Shared literals (`NFT_TABLE`, `RFC1918`) — no logic |
| `config.py` | `ShieldConfig`, `ShieldMode`, path helpers, config loading |
| `mode_hook.py` | Hook mode lifecycle (OCI hooks, per-container netns) |
| `oci_hook.py` | OCI hook entry point — fail-closed firewall application |
| `dns.py` | DNS resolution via `dig`, timestamp-based caching |
| `profiles.py` | Profile loading and composition |
| `audit.py` | JSON-lines audit logging |
| `run.py` | Subprocess wrappers (`nft`, `nsenter`, `dig`, `podman`) |
| `util.py` | Small shared utilities |
| `cli.py` | Standalone CLI entry point |

Module boundaries are enforced by [tach](https://github.com/gauge-sh/tach)
(`tach.toml`). The critical constraint: `nft.py` may only import from
`nft_constants.py` and stdlib.
