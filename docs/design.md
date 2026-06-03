# Architecture

## Firewall mode

### Hook mode

Uses OCI hooks to apply per-container nftables rules inside the container's own
network namespace. Each container gets an isolated firewall. Works with pasta
(rootless default) and slirp4netns.

Lifecycle: `Shield.pre_start()` installs the OCI hook (idempotent), resolves DNS,
writes `profile.allowed`, pre-generates the complete nft ruleset to `ruleset.nft`,
and returns podman args with annotations. On each container start, the OCI hook
reads `state_dir` from annotations, applies the pre-generated `ruleset.nft` inside
the container's network namespace, discovers the gateway from `/proc/{pid}/net/route`,
and optionally starts a per-container *dnsmasq* instance.

## Allowlisting

Allowlists are `.txt` files with one entry per line — domain names or raw
IP/CIDRs. Lines starting with `#` are comments.

Bundled defaults use domain names because they're stable across IP rotations and
easy to audit. DNS resolution uses the best available tier:

1. **dnsmasq** (preferred) — a per-container dnsmasq instance is started by the OCI
   hook with `--nftset=allow_v4,allow_v6`, automatically populating the nft allow sets
   on every resolution at runtime. Handles IP rotation without manual intervention.
   Container DNS is redirected to `127.0.0.1:53` via a `resolv.conf` volume mount.
2. **dig** — pre-start `dig +short A/AAAA` resolution; IPs cached in `profile.allowed`
   with `st_mtime`-based freshness (default 1 hour).
3. **getent** — fallback when `dig` is also absent.

`detect_dns_tier()` selects the tier automatically based on available binaries and
dnsmasq compile-time nftset support.

### Bundled profiles

| Profile | Contents |
|---------|----------|
| `base.txt` | OS repos (Ubuntu, Debian, Fedora, Alpine), NTP, OCSP/CRL |
| `dev-standard.txt` | GitHub, Docker Hub, PyPI, npm, crates.io, Go proxy, GitLab |
| `dev-python.txt` | PyPI, conda-forge, readthedocs |
| `dev-node.txt` | npm, Yarn, jsDelivr, unpkg |
| `nvidia-hpc.txt` | CUDA toolkit, NGC, NVIDIA repos |

Users can add custom profiles in `$XDG_CONFIG_HOME/terok-shield/profiles/`.

## Persistent deny

When a user denies an IP that came from a loaded preset (`profile.allowed`),
the deny must survive `shield up` and container restarts. The mechanism:

- `deny.list` — a per-container file in `state_dir` listing IPs that override
  presets
- On deny: if the IP is in `profile.allowed`, append to `deny.list`
- On allow: if the IP is in `deny.list`, remove it (un-deny)
- On reload (`shield_up`, OCI hook apply): compute effective IPs as
  `(profile.allowed ∪ live.allowed) − deny.list`

`deny.list` stays minimal — only IPs that truly override a preset are stored.
Denying a live-only IP just removes it from `live.allowed` (no `deny.list`
entry needed). Deny-list reconciliation happens in `state.py` before ruleset
generation; `nft.py` receives a flat IP list with denied entries already
subtracted.

### IP normalization

`safe_ip()` normalizes all IPs to their canonical string form via
`ipaddress.ip_address()` / `ip_network()`. This ensures string comparisons
across state files are reliable regardless of input notation (e.g.
`2001:0db8::1` and `2001:db8::1` both normalize to `2001:db8::1`).

### State bundle layout

```text
{state_dir}/
├── hooks/                                # only if per-container hooks are supported
│   ├── terok-shield-createRuntime.json   # only if per-container hooks are supported
│   └── terok-shield-poststop.json        # only if per-container hooks are supported
├── terok-shield-hook              # entrypoint script (stdlib-only), for per-container hooks
├── ruleset.nft                    # pre-generated nft ruleset (written by pre_start)
├── gateway                        # discovered gateway IP (written by OCI hook)
├── profile.allowed                # IPs from DNS resolution (preset)
├── profile.domains                # domain names for dnsmasq config
├── live.allowed                   # IPs from manual allow/deny
├── live.domains                   # domains added at runtime via allow_domain
├── deny.list                      # persistent deny overrides
├── denied.domains                 # domains denied at runtime via deny_domain
├── dnsmasq.conf                   # generated dnsmasq configuration (dnsmasq tier)
├── dnsmasq.pid                    # dnsmasq PID (dnsmasq tier)
├── resolv.conf                    # bind-mounted over /etc/resolv.conf (dnsmasq tier)
├── upstream.dns                   # persisted upstream DNS address
├── dns.tier                       # persisted active DNS tier
└── audit.jsonl                    # per-container audit log
```

The `hooks/` descriptors and the `terok-shield-hook` entrypoint are part of
the per-container bundle only when podman supports persistent per-container
hooks. It does not today — podman drops a per-container `--hooks-dir` across
stop/start ([containers/podman#17935](https://github.com/containers/podman/issues/17935)) —
so shield instead installs the hooks once into a **global** directory and
registers that directory in podman's `containers.conf` (`hooks_dir` under
`[engine]`; `~/.config/containers/containers.conf` for rootless). `terok-shield
setup` installs the global hooks and patches `containers.conf`; the rest of the
bundle above stays per-container regardless.

### Data flow diagrams

**`deny_ip` flow:**

```text
deny_ip(container, ip)
│
├── safe_ip(ip)                 validate + normalize
│
├── nft delete element          remove from kernel set
│   (best-effort, catch         (IP may not be in set if
│    ExecError)                  already denied earlier)
│
├── remove from live.allowed    always runs regardless
│                               of nft success
│
└── ip in profile.allowed?
    ├── yes → append to deny.list   (persistent override)
    └── no  → done                  (live-only, no persist needed)
```

**`allow_ip` flow:**

```text
allow_ip(container, ip)
│
├── safe_ip(ip)                 validate + normalize
│
├── ip in deny.list?
│   └── yes → remove from deny.list   (un-deny)
│
├── nft add element             add to kernel set
│
└── append to live.allowed      (deduplicated)
```

**`shield_up` / OCI hook apply (effective IP merge):**

```text
read_effective_ips(state_dir)
│
├── read_allowed_ips()
|   |
│   ├── profile.allowed ──┐
│   └── live.allowed ─────┤
│                         │
│                         ▼
│              union (dedup, profile-first)
│
├── read_denied_ips()
|   |
│   └── deny.list ──→ deny set
│
└── effective = allowed − denied
         │
         ▼
  add_elements_dual()     flat IP list to nft
  (nft.py boundary)       (deny.list already subtracted)
```

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
is used for private-range (RFC 1918/RFC 4193) allowlisting events. Audit logging is
best-effort — failures are silently ignored to avoid blocking container
operations.

### Kernel per-packet logs

nftables log rules generate per-packet entries in dmesg/journald:

- `TEROK_SHIELD_ALLOWED:` traffic hitting the allow set (rate-limited)
- `TEROK_SHIELD_DENIED:` traffic rejected by the deny-all rule
- `TEROK_SHIELD_PRIVATE:` non-allowlisted private-range traffic rejected (RFC 1918/RFC 4193)

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
| `state(container)` | Query container shield state (`UP`, `DOWN`, `DISENGAGED`, `OFFLINE`) |
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
| `__init__.py` | `Shield` public API entry point |
| `nft.py` | ruleset generation, input validation, self-verification |
| `nft_constants.py` | Shared literals (`NFT_TABLE`, `RFC1918`) — no logic |
| `config.py` | `ShieldConfig`, `ShieldMode`, `ShieldState`, `DnsTier`, `ShieldModeBackend` protocol, annotation constants |
| `state.py` | Per-container state bundle layout — path derivation, effective IP merging |
| `mode_hook.py` | Hook mode strategy (OCI hooks, per-container netns, dnsmasq lifecycle) |
| `oci_hook.py` | OCI hook entry point — fail-closed firewall application |
| `dnsmasq.py` | dnsmasq config generation, launch/kill lifecycle, domain add/remove |
| `dns.py` | DNS resolution via `dig` / `getent`, file-based caching |
| `profiles.py` | Profile loading and composition |
| `audit.py` | JSON-lines audit logging (single file per container) |
| `run.py` | Subprocess wrappers (`nft`, `nsenter`, `dig`, `podman`) |
| `validation.py` | Input validation (container names, path safety) |
| `util.py` | Small shared utilities |
| `registry.py` | Command registry — subcommand definitions, metadata, and reusable handlers |
| `cli.py` | Standalone CLI entry point + config construction from env/YAML |
| `resources/hook_entrypoint.py` | Stdlib-only OCI hook script — installed verbatim, no terok_shield imports |

Module boundaries are enforced by [tach](https://github.com/gauge-sh/tach)
(`tach.toml`). `nft.py` may only import from `nft_constants.py` and stdlib.
