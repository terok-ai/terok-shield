# Configuration

terok-shield uses XDG-compliant directories and an optional YAML config file.

## Config file

Optional. Located at `~/.config/terok/shield/config.yml`
(or `$XDG_CONFIG_HOME/terok/shield/config.yml`).

The file is validated with Pydantic (`extra="forbid"`).  Typos and wrong
types produce a clear error at startup instead of being silently ignored.
See [Config Reference](../config-reference.md) for the full field table
and annotated YAML example.

If the config file is missing, defaults are used.  Unparseable YAML
(syntax errors) falls back to defaults with a warning.

!!! note "Library vs CLI"
    The config file is only read by the CLI. When using terok-shield as a
    library, all configuration is passed programmatically via `ShieldConfig`.

### Mode selection

Currently there is only one mode, the "hook mode". Setting `mode: auto` or `mode: hook`
both resolve to hook mode. Future modes may be added for different network
topologies.

## Directories

### State directory

Default: `~/.local/state/terok/shield/`
Override: `TEROK_SHIELD_STATE_DIR` or `--state-dir` flag

Each container gets an isolated state bundle under `containers/`:

```text
~/.local/state/terok/shield/
└── containers/
    └── my-container/
        ├── hooks/                  # only if per-container hooks are supported
        │   ├── terok-shield-createRuntime.json
        │   └── terok-shield-poststop.json
        ├── terok-shield-hook       # OCI hook entrypoint (stdlib-only Python), per-container hooks only
        ├── ruleset.nft             # Pre-generated nft ruleset
        ├── gateway                 # Discovered gateway IP
        ├── profile.allowed         # Pre-resolved IPs from DNS profiles
        ├── profile.domains         # Domain names for dnsmasq config
        ├── live.allowed            # IPs from runtime allow/deny
        ├── live.domains            # Domains added at runtime
        ├── deny.list               # Persistent deny overrides
        ├── denied.domains          # Domains denied at runtime
        ├── dnsmasq.conf            # Generated dnsmasq config (dnsmasq tier)
        ├── dnsmasq.pid             # dnsmasq PID (dnsmasq tier)
        ├── resolv.conf             # Bind-mounted /etc/resolv.conf (dnsmasq tier)
        ├── upstream.dns            # Persisted upstream DNS address
        ├── dns.tier                # Persisted active DNS tier
        └── audit.jsonl             # Per-container audit log
```

> **Where the hooks live.** The `hooks/` descriptors and the
> `terok-shield-hook` entrypoint are part of this per-container bundle only
> when podman supports persistent per-container hooks. It does not today —
> podman drops a per-container `--hooks-dir` across stop/start
> ([containers/podman#17935](https://github.com/containers/podman/issues/17935)) —
> so shield installs the hooks once into a **global** directory and registers
> it in podman's `containers.conf` (`hooks_dir` under `[engine]`;
> `~/.config/containers/containers.conf` for rootless). Run `terok-shield setup`
> to install the global hooks and patch `containers.conf`. The `pre_start()`
> rows below describe the per-container-hooks layout.

| File | Written by | Purpose |
|------|-----------|---------|
| `hooks/` | `pre_start()` | OCI hook descriptors (per-container hooks only) |
| `terok-shield-hook` | `pre_start()` | Stdlib-only hook entrypoint script (per-container hooks only) |
| `ruleset.nft` | `pre_start()` | Pre-generated nft ruleset applied by the hook |
| `gateway` | OCI hook | Gateway IP discovered from `/proc/{pid}/net/route` |
| `profile.allowed` | `pre_start()` / `resolve()` | Cached IPs from DNS resolution |
| `profile.domains` | `pre_start()` | Domain names for dnsmasq `--nftset` entries |
| `live.allowed` | `allow()` / `deny()` | Runtime allow/deny IP persistence |
| `live.domains` | `allow_domain()` | Domains added at runtime |
| `deny.list` | `deny()` | IPs denied from presets (survives `up`/`down` cycles) |
| `denied.domains` | `deny_domain()` | Domains denied at runtime |
| `dnsmasq.conf` | `pre_start()` | Generated dnsmasq configuration (dnsmasq tier only) |
| `dnsmasq.pid` | OCI hook | dnsmasq PID for lifecycle management |
| `resolv.conf` | `pre_start()` | Redirects container DNS to `127.0.0.1:53` (dnsmasq tier) |
| `upstream.dns` | `pre_start()` | Persisted upstream DNS forwarder address |
| `dns.tier` | `pre_start()` | Persisted tier (`dnsmasq`, `dig`, or `getent`) |
| `audit.jsonl` | Hook + Shield methods | Per-container audit log |

### Config directory

Default: `~/.config/terok/shield/`
Override: `TEROK_SHIELD_CONFIG_DIR`

| Path | Contents |
|------|----------|
| `profiles/` | Custom allowlist profiles (override bundled ones) |
| `config.yml` | Shield configuration |

## DNS resolution

DNS resolution behaviour depends on the active tier, selected automatically by
`detect_dns_tier()`:

**dnsmasq tier** (preferred): a per-container dnsmasq instance is started by
the OCI hook. It uses `--nftset` to auto-populate the nft `allow_v4`/`allow_v6`
sets on every resolution at runtime. `profile.allowed` still holds the
pre-start resolved IPs, but dynamic resolution handles IP rotation
automatically — no cache expiry needed.

**dig / getent tiers** (fallback): resolved IPs are stored in `profile.allowed`,
one IP per line. The cache uses file modification time (`st_mtime`) for
freshness checking — entries older than 1 hour are automatically re-resolved.

Force a cache refresh (all tiers):

```bash
terok-shield resolve my-container --force
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `TEROK_SHIELD_STATE_DIR` | Override state directory location |
| `TEROK_SHIELD_CONFIG_DIR` | Override config directory location |
| `XDG_STATE_HOME` | XDG state base (default: `~/.local/state`) |
| `XDG_CONFIG_HOME` | XDG config base (default: `~/.config`) |

## OCI annotations

These annotations are set automatically by `terok-shield run` (or
`pre_start()` in the Python API) and read by the OCI hook:

| Annotation | Value | Purpose |
|------------|-------|---------|
| `terok.shield.profiles` | Colon-separated names | Which profiles to apply |
| `terok.shield.name` | Container name | Audit log identification |
| `terok.shield.state_dir` | Absolute path | Where the hook finds its state bundle |
| `terok.shield.loopback_ports` | Colon-separated ints | Ports for ruleset generation |
| `terok.shield.version` | Integer | Bundle version (hard-fail on mismatch) |
| `terok.shield.audit_enabled` | `true` / `false` | Whether to write audit logs |
| `terok.shield.upstream_dns` | IP address | Upstream DNS forwarder for dnsmasq |
| `terok.shield.dns_tier` | `dnsmasq` / `dig` / `getent` | Active DNS resolution tier |
