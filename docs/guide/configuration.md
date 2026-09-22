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
        ├── policy/                 # v15 tiered +/- policy, one file per tier set
        │   ├── 10-override         #   → nft set t10_override (break-glass allow)
        │   ├── 20-security-deny    #   → nft set t20_security_deny (vault hosts + operator deny)
        │   ├── 30-provider-allow   #   → nft set t30_provider_allow (provider egress)
        │   ├── 40-project-allow    #   → nft set t40_project_allow (project allowlist)
        │   └── live                #   Runtime allow/deny overlay (+/- lines)
        ├── resolved.ips            # Resolved allow IPs (t40 seed; every tier but dnsmasq-live)
        ├── ruleset.nft             # Pre-generated nft ruleset (gateways baked in)
        ├── dnsmasq.conf            # Generated dnsmasq config (dnsmasq tiers)
        ├── dnsmasq.pid             # dnsmasq PID (dnsmasq tiers)
        ├── dnsmasq.bin             # The dnsmasq binary the hook launches
        ├── resolv.conf             # Bind-mounted /etc/resolv.conf (every tier)
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
| `ruleset.nft` | `pre_start()` | Pre-generated nft ruleset applied by the hook (gateways baked in) |
| `policy/10-override` | `pre_start()` | Break-glass allow tier (`t10_override`) |
| `policy/20-security-deny` | `pre_start()` / `deny()` | Vault-host + operator deny tier (`t20_security_deny`) |
| `policy/30-provider-allow` | `pre_start()` | Provider-egress allow tier (`t30_provider_allow`) |
| `policy/40-project-allow` | `pre_start()` | Project allowlist tier (`t40_project_allow`) — authored domains and IPs |
| `policy/live` | `allow()` / `deny()` | Runtime allow/deny overlay (`+`/`-` lines; a later verdict flips an earlier one) |
| `resolved.ips` | `pre_start()` / `resolve()` | Resolved allow IPs seeding `t40_project_allow` (every tier but `dnsmasq-live`) |
| `dnsmasq.conf` | `pre_start()` | Generated dnsmasq configuration (dnsmasq tiers) |
| `dnsmasq.pid` | OCI hook | dnsmasq PID for lifecycle management |
| `dnsmasq.bin` | `pre_start()` | The dnsmasq binary the hook launches and matches |
| `resolv.conf` | `pre_start()` | Points container DNS at dnsmasq, or at the upstream forwarder on the tiers without it |
| `upstream.dns` | `pre_start()` | Persisted upstream DNS forwarder address |
| `dns.tier` | `pre_start()` | Persisted tier (`dnsmasq-live`, `dnsmasq-static`, `lookup`, or `getent`) |
| `audit.jsonl` | Hook + Shield methods | Per-container audit log |

### Config directory

Default: `~/.config/terok/shield/`
Override: `TEROK_SHIELD_CONFIG_DIR`

| Path | Contents |
|------|----------|
| `profiles/` | Custom allowlist profiles (override bundled ones) |
| `config.yml` | Shield configuration |

## DNS resolution

The active tier decides how the allowlist reaches the nft sets; see
[DNS tiers](modes.md#dns-tiers) for what each tier provides.

On `dnsmasq-live` there is no resolution at launch: dnsmasq populates the sets
per query, before the reply reaches the workload (`cache-size=0`).

On every other tier the allowlist is resolved at launch into the per-container
`resolved.ips` cache, one IP per line, and the terminal reports the batch
before and after. Domains resolve concurrently with a 2 s per-lookup budget.
Entries older than 1 hour, or older than the authored policy, are re-resolved.
A shared host cache under `<state root>/dns-cache/` (or
`ShieldConfig.dns_cache_dir`) lets every container with the same allowlist
reuse one resolution; a resolve where every domain failed is never shared.

Force a refresh of a container's resolution caches, even when they are fresh:

```bash
terok-shield resolve my-container --force
```

### dnsmasq binary

Shield finds dnsmasq on `PATH` and in the sbin directories. To run a dnsmasq
installed elsewhere, for example one built with nftset support in your home,
set `dnsmasq_path` in `config.yml` (or `ShieldConfig.dnsmasq_path`). A path
that is not an executable file stops the launch.

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
| `terok.shield.version` | Integer | Bundle version (hard-fail on mismatch — re-create the task to fix) |
| `terok.shield.audit_enabled` | `true` / `false` | Whether to write audit logs |
| `terok.shield.upstream_dns` | IP address | Upstream DNS forwarder for dnsmasq |
| `terok.shield.dns_tier` | `dnsmasq-live` / `dnsmasq-static` / `lookup` / `getent` | Active DNS resolution tier |
