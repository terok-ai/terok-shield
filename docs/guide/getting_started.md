# Getting Started

This guide walks through installing terok-shield and running your first
shielded container.

## Prerequisites

- **Linux** with nftables (`nft` binary available)
- **Podman** (rootless mode)
- **Python 3.12+**
- **`dig`** (from `dnsutils` or `bind-utils`) for DNS resolution

## Install

```bash
pip install terok-shield
```

Verify the installation:

```bash
terok-shield --version
```

## Quick start

```bash
terok-shield run my-container -- alpine:latest sh
```

This single command:

1. Resolves DNS domains from your allowlist profiles into cached IPs
2. Installs OCI hooks in the container's state directory
3. Launches `podman run` with all required flags (annotations, hooks-dir,
   cap-drop, security-opt)

The container starts with a default-deny firewall — only destinations in the
default `dev-standard` profile are reachable.

### Multiple profiles

```bash
terok-shield run my-container --profiles dev-standard dev-python my-project \
  -- alpine:latest sh
```

### Passing extra podman flags

Everything after `--` is forwarded to `podman run`. Shield-managed flags
(`--name`, `--hooks-dir`, `--annotation`, `--cap-drop`, `--security-opt`)
are set automatically and cannot be overridden:

```bash
terok-shield run my-container -- --rm -it -e FOO=bar alpine:latest sh
```

!!! tip "Scripting and advanced usage"
    Use `terok-shield prepare` to get the podman flags without launching.
    See the [CLI Reference](cli.md#prepare) for details.

### What happens at startup

1. Podman sees the `terok.shield.profiles` annotation and fires the OCI hook
2. The hook reads `state_dir` from annotations, enters the container's network
   namespace via the PID
3. nftables rules are applied: default-deny policy with the allowlisted IPs
4. The hook verifies the rules are correctly applied
5. If any step fails, the container is torn down (fail-closed)

From inside the container, only the allowed destinations are reachable.
All other outbound traffic is dropped. Allowlisting private-range addresses
(RFC 1918, RFC 4193) or large CIDRs generates a notice in the audit log.

## Allow or deny destinations at runtime

While the container is running, you can modify its allow set:

```bash
# Allow a domain (resolves to IPs automatically)
terok-shield allow my-container example.com
# Allowed example.com -> <resolved-ip> for my-container

# Allow a raw IP
terok-shield allow my-container 203.0.113.10

# Revoke access
terok-shield deny my-container example.com
```

Changes take effect immediately — no container restart needed. Allowed IPs are
persisted to `live.allowed`, and denying a preset IP persists it to `deny.list`,
so both survive `down`/`up` bypass cycles and container restarts.

## Inspect the firewall

```bash
# Show active nftables rules for a container
terok-shield rules my-container

# Show recent audit log entries
terok-shield logs --container my-container -n 10
```

## Bypass mode

Temporarily disable the firewall for debugging or traffic discovery:

```bash
terok-shield down my-container          # bypass (private ranges still blocked)
terok-shield down my-container --all    # bypass everything

terok-shield up my-container            # restore deny-all
```

## Next steps

- [Allowlist Profiles](profiles.md) — customize what your containers can reach
- [Firewall Modes](modes.md) — understand hook mode
- [CLI Reference](cli.md) — full command reference
