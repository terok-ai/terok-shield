# Getting Started

This guide walks through installing terok-shield, setting up the firewall,
and running your first shielded container.

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

## Set up the firewall hook

```bash
terok-shield setup
```

This creates an [OCI hook](modes.md#hook-mode) that podman will fire
whenever an annotated container starts. The hook applies nftables rules inside
the container's network namespace before the workload begins.

No changes to your container images are needed. The firewall lives entirely
outside the container — it's applied at `podman run` time.

Verify with:

```bash
terok-shield status
```

```text
Mode:     hook
Audit:    enabled
Profiles: base, dev-node, dev-python, dev-standard, nvidia-hpc
```

## Resolve DNS allowlists

Before starting a container, pre-resolve the domains from your allowlist
profiles into cached IPs:

```bash
terok-shield resolve my-container
```

```text
Resolved 28 IPs for my-container
  140.82.121.3
  140.82.121.4
  ...
```

The IPs are cached in `~/.local/state/terok-shield/resolved/` and
automatically refreshed when stale (default: 1 hour). You can force
a refresh with `--force`.

## Run a shielded container

```bash
podman run --rm -it \
  --name my-container \
  --annotation terok.shield.profiles=dev-standard \
  --hooks-dir ~/.local/state/terok-shield/hooks \
  --cap-drop NET_ADMIN --cap-drop NET_RAW \
  --security-opt no-new-privileges \
  alpine:latest sh
```

Breaking this down:

| Flag | Purpose |
|------|---------|
| `--name my-container` | Names the container (used by `allow`, `deny`, `rules`, etc.) |
| `--annotation terok.shield.profiles=dev-standard` | Tells the OCI hook which allowlist profiles to apply |
| `--hooks-dir ~/.local/state/terok-shield/hooks` | Points podman to the shield's hook directory |
| `--cap-drop NET_ADMIN` | Prevents the workload from modifying the firewall |
| `--cap-drop NET_RAW` | Prevents raw socket access |
| `--security-opt no-new-privileges` | Prevents privilege escalation |

!!! tip "Multiple profiles"
    Combine profiles with commas:
    `--annotation terok.shield.profiles=dev-standard,dev-python,nvidia-hpc`

### What happens at startup

1. Podman sees the `terok.shield.profiles` annotation and fires the OCI hook
2. The hook reads the container's PID and enters its network namespace
3. nftables rules are applied: default-deny policy with the allowlisted IPs
4. The hook verifies the rules are correctly applied
5. If any step fails, the container is torn down (fail-closed)

From inside the container, only the allowed destinations are reachable.
All other outbound traffic is dropped. Allowlisting RFC1918 (private
networks), link-local addresses, or large CIDRs generates a notice in
the audit log.

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

Changes take effect immediately — no container restart needed.

## Inspect the firewall

```bash
# Show active nftables rules for a container
terok-shield rules my-container

# Show recent audit log entries
terok-shield logs --container my-container -n 10
```

## Next steps

- [Allowlist Profiles](profiles.md) — customize what your containers can reach
- [Firewall Modes](modes.md) — understand hook mode
- [CLI Reference](cli.md) — full command reference
