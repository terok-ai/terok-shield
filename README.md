# terok-shield

nftables-based egress firewalling for Podman containers.

## Overview

terok-shield provides default-deny outbound network filtering for rootless
Podman containers using nftables. It is designed for environments where
containers must be isolated from the internet except for explicitly
allowed domains.

### Features

- **Default-deny egress** with curated domain allowlists
- **DNS-based allowlisting** — domains resolved at setup, cached with freshness tracking
- **Live allow/deny** at runtime for individual containers
- **Connection audit logging** (JSON-lines)
- **Two modes**: standard (OCI hook, zero-root) and hardened (bridge + rootless-netns)
- **Fail-closed**: hook failure tears down the container

### Requirements

- Linux with nftables (`nft` binary)
- Podman (rootless)
- Python 3.12+
- `dig` (from `dnsutils` / `bind-utils`) for DNS resolution

## Installation

```bash
pip install terok-shield
```

Or from a GitHub release wheel:

```bash
pip install https://github.com/terok-ops/terok-shield/releases/download/v0.1.0/terok_shield-0.1.0-py3-none-any.whl
```

## Quick start

```bash
# Set up the firewall (installs OCI hook)
terok-shield setup

# Check status
terok-shield status

# Resolve DNS allowlists (refreshes cached IPs)
terok-shield resolve --force
```

## Usage with terok

terok-shield is a hard dependency of [terok](https://github.com/terok-ops/terok).
When installed alongside terok, the `terokctl shield` commands delegate to
terok-shield's library API.

## Development

```bash
# Install dev dependencies
make install-dev

# Run all checks (lint, test, security, docstrings, deadcode, reuse)
make check

# Format code
make format
```

## License

Apache-2.0 — see [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt).
