# CLI Reference

All commands are invoked as `terok-shield <command> [options]`.

Global options:

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--state-dir <path>` | Override state root directory |

## run

Launch a shielded container via podman. Resolves DNS, installs hooks, and
execs into `podman run` with the correct flags.

```bash
terok-shield run <container> [--profiles <profile>...] -- <image> [cmd...]
```

| Argument | Description |
|----------|-------------|
| `container` | Container name |
| `--profiles` | Override default profiles (space-separated) |
| `-- ...` | Everything after `--` is passed to `podman run` |

```bash
# Basic usage
terok-shield run my-container -- alpine:latest sh

# With custom profiles
terok-shield run my-container --profiles dev-standard dev-python -- alpine:latest sh

# With extra podman flags (after --)
terok-shield run my-container -- --rm -it -e FOO=bar alpine:latest sh
```

Shield-managed flags (`--name`, `--hooks-dir`, `--annotation`, `--cap-drop`,
`--cap-add`, `--security-opt`, `--network`) are set automatically and rejected
if passed after `--`.

## prepare

Resolve DNS, install hooks, and print the podman flags needed to launch a
shielded container. Useful for scripting or inspecting what `run` would do.

```bash
terok-shield prepare <container> [--profiles <profile>...] [--json]
```

| Argument | Description |
|----------|-------------|
| `container` | Container name |
| `--profiles` | Override default profiles (space-separated) |
| `--json` | Output as a JSON array (machine-readable) |

```bash
# Shell-quoted output (default)
terok-shield prepare my-container
# --hooks-dir /home/user/.local/state/... --annotation ... --name my-container

# Use with eval for manual podman invocations
eval "podman run $(terok-shield prepare my-ctr) alpine:latest sh"

# JSON output for programmatic consumption
terok-shield prepare my-container --json
# ["--hooks-dir", "/home/user/.local/state/...", "--name", "my-container"]
```

## status

Show current shield status, or query a specific container's firewall state.

```bash
terok-shield status [container]
```

| Argument | Description |
|----------|-------------|
| `container` | Optional — when given, prints the container's firewall state |

Without a container name, shows the global shield configuration:

```bash
terok-shield status
```

```text
Mode:     hook
Audit:    enabled
Profiles: base, dev-node, dev-python, dev-standard, nvidia-hpc
```

With a container name, prints the live firewall state (`up`, `down`, `disengaged`,
`offline`, or `error`). Useful for scripting and integration:

```bash
terok-shield status my-container
# up
```

## resolve

Resolve DNS domains from the configured profiles and cache the resulting IPs.

```bash
terok-shield resolve <container> [--force]
```

| Argument | Description |
|----------|-------------|
| `container` | Container name (used as the cache key) |
| `--force` | Bypass cache freshness and re-resolve all domains |

```bash
terok-shield resolve my-container
# Resolved 28 IPs for my-container

terok-shield resolve my-container --force
# Resolved 28 IPs for my-container (forced)
```

Cached IPs are stored in the container's `resolved.ips` file and
automatically refreshed when stale (default: 1 hour).

## allow

Add a domain or IP to a running container's allow set.

```bash
terok-shield allow <container> <target>
```

| Argument | Description |
|----------|-------------|
| `container` | Container name or ID |
| `target` | Domain name or IP address to allow |

```bash
terok-shield allow my-container example.com
# Allowed example.com -> <resolved-ip> for my-container

terok-shield allow my-container 203.0.113.10
# Allowed 203.0.113.10 -> 203.0.113.10 for my-container
```

If `target` is a domain name, it is resolved to IPs automatically.
Changes take effect immediately. The allow is persisted to the `policy/live`
overlay (as a `+` line) and survives `down`/`up` posture cycles. If the target
was previously denied, the allow flips that verdict automatically.

## deny

Remove a domain or IP from a running container's allow set.

```bash
terok-shield deny <container> <target>
```

| Argument | Description |
|----------|-------------|
| `container` | Container name or ID |
| `target` | Domain name or IP address to deny |

```bash
terok-shield deny my-container example.com
# Denied example.com (<resolved-ip>) for my-container
```

The IP is removed from the nft `t40_project_allow` set (if present; errors are
logged but do not prevent the deny from being persisted) and added to the
`t20_security_deny` set. The deny is recorded as a `-` line in the `policy/live`
overlay, so it persists across `up`/`down` cycles and container restarts and
flips any prior allow of the same target.

## down

Switch a container to the DOWN posture. Public traffic is accepted with
logging; private ranges (RFC 1918/RFC 4193) remain blocked unless
`--disengage` is used.

```bash
terok-shield down <container> [--disengage]
```

| Argument | Description |
|----------|-------------|
| `container` | Container name or ID |
| `--disengage` | Enforce nothing — lift the deny set and every range reject (DISENGAGED posture) |

Plain DOWN keeps three rejects: the hard-deny floor (link-local, IMDS),
the security-deny set, and the private ranges (RFC 1918, RFC 4193).
`--disengage` lifts all three. The DISENGAGED posture accepts every
destination and logs each new connection.

A t10 override opens one private host or one private range in every
enforcing posture. Shield logs a CIDR override as a warning. The
private-range reject sits above the allow tiers, so an allowlist entry does
not open a private address. The hard-deny floor sits above t10, so no
override reaches a link-local or IMDS address.

## up

Restore normal deny-all mode for a container.

```bash
terok-shield up <container>
```

Re-applies the deny-all ruleset and restores the effective allow IPs
(the composed `policy/` tiers with the runtime overlay, minus the
security-deny tier). Allow-set state the container learned through dnsmasq
survives the transition — a down/up round trip never forgets IPs the
workload already resolved.

## reset

Forget DNS-learned allow-set state, returning the allow sets to their
just-launched contents.

```bash
terok-shield reset <container>
```

The dnsmasq tier accumulates every IP the workload legitimately resolved
(elements also age out on their own via the set timeout). `reset` drops
that learned state in one transaction while re-seeding the authored policy
literals, and touches neither the deny tier nor runtime `allow`/`deny`
overlay entries. The workload re-earns its state on its next DNS queries.

## preview

Show the nftables ruleset that would be applied.

```bash
terok-shield preview [--down] [--disengage]
```

| Option | Description |
|--------|-------------|
| `--down` | Show the DOWN-posture ruleset instead of default deny-all |
| `--disengage` | Show the DISENGAGED ruleset: no deny set, no range rejects (requires `--down`) |

## rules

Display the active nftables rules for a container.

```bash
terok-shield rules <container>
```

Shows the container's shield state and the full nftables ruleset in its
network namespace.

## profiles

List available shield profiles.

```bash
terok-shield profiles
```

```text
base
dev-node
dev-python
dev-standard
nvidia-hpc
```

Lists both bundled profiles and any user-defined profiles from the
config profiles directory.

## logs

Show audit log entries.

```bash
terok-shield logs [--container <name>] [-n <count>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--container` | all | Filter by container name |
| `-n` | 50 | Number of recent entries to show |

```bash
terok-shield logs --container my-container -n 10
terok-shield logs -n 5   # last 5 entries across all containers
```

Each entry is a JSON object printed on one line. See [Audit Logging](logging.md)
for the log format.
