# CLI Reference

All commands are invoked as `terok-shield <command> [options]`.

## setup

Install the firewall hook (hook mode) or verify bridge prerequisites
(bridge mode).

```bash
terok-shield setup              # hook mode — installs OCI hook
terok-shield setup --bridge     # bridge mode — verifies bridge network
```

**What it does:**

- Creates shield directories (`hooks/`, `logs/`, `dns/`, `resolved/`, `profiles/`)
- **Hook**: generates the OCI hook entrypoint script and JSON descriptor
- **Bridge**: verifies that the `ctr-egress` bridge network exists

Run this once after installation.

## status

Show current shield status: active mode, available profiles, audit state.

```bash
terok-shield status
```

```text
Mode:     hook
Audit:    enabled
Profiles: base, dev-node, dev-python, dev-standard, nvidia-hpc
Logs:     2 container(s)
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

Cached IPs are stored in `~/.local/state/terok-shield/resolved/<container>.resolved`
and automatically refreshed when stale (default: 1 hour).

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
Changes take effect immediately.

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

## rules

Display the active nftables rules for a container.

```bash
terok-shield rules <container>
```

```bash
terok-shield rules my-container
```

Shows the full nftables ruleset applied in the container's network namespace.

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
