# terok-shield

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![REUSE status](https://api.reuse.software/badge/github.com/terok-ai/terok-shield)](https://api.reuse.software/info/github.com/terok-ai/terok-shield)
[![codecov](https://codecov.io/gh/terok-ai/terok-shield/graph/badge.svg?token=D74Q7lvnIF)](https://codecov.io/gh/terok-ai/terok-shield)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=terok-ai_terok-shield&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=terok-ai_terok-shield)

nftables-based egress firewalling for rootless Podman containers.

## Overview

terok-shield enforces **default-deny outbound** network filtering on Podman
containers using nftables. Containers can only reach explicitly allowed
destinations — everything else is dropped.

### Features

- **Default-deny egress** with curated allowlists (domains and IPs)
- **DNS-based allowlisting** — domain names resolved before container start, cached automatically
- **Live allow/deny** at runtime for individual containers
- **Connection audit logging** (JSON-lines lifecycle logs + kernel-level per-packet nftables logs)
- **Two modes**: hook (OCI hook, self-contained) and bridge (bridge network + rootless-netns)
- **Fail-closed**: hook failure prevents the container from starting

### Requirements

- Linux with nftables (`nft` binary)
- Podman (rootless)
- Python 3.12+
- `dig` (from `dnsutils` / `bind-utils`) for DNS resolution
- `dnsmasq` (optional, only for [bridge mode](https://terok-ai.github.io/terok-shield/guide/modes/#bridge-mode))

## Installation

```bash
pip install terok-shield
```

## Quick start

### 1. Install the firewall hook

```bash
terok-shield setup
terok-shield status       # verify installation
```

This installs an OCI hook that fires when annotated containers start.
No changes to your Dockerfiles or container images are needed — the firewall
is applied externally at container creation time.

### 2. Choose your allowlists

terok-shield ships with several bundled profiles
(see [Allowlist Profiles](https://terok-ai.github.io/terok-shield/guide/profiles/)):

| Profile | Domains |
|---------|---------|
| `base` | DNS roots, NTP, OCSP, OS package repos |
| `dev-standard` | GitHub, Docker Hub, PyPI, npm, crates.io, Go |
| `dev-python` | Conda, Read the Docs, Python docs |
| `dev-node` | Yarn, jsDelivr, unpkg |
| `nvidia-hpc` | CUDA, NGC, NVIDIA drivers |

The default profile is `dev-standard`. To add a custom allowlist, create a
`.txt` file with one domain or IP per line:

```bash
mkdir -p ~/.config/terok-shield/profiles
cat > ~/.config/terok-shield/profiles/my-project.txt << 'EOF'
api.example.com
cdn.example.com
203.0.113.10
EOF
```

### 3. Start a container with the shield

```bash
terok-shield resolve my-container    # pre-resolve DNS → cached IPs

podman run --rm -it \
  --name my-container \
  --annotation terok.shield.profiles=dev-standard,my-project \
  --hooks-dir ~/.local/state/terok-shield/hooks \
  --cap-drop NET_ADMIN --cap-drop NET_RAW \
  --security-opt no-new-privileges \
  alpine:latest sh
```

The container starts with a default-deny firewall — only destinations in the
`dev-standard` and `my-project` profiles are reachable.

### 4. Allow a domain at runtime

```bash
terok-shield allow my-container example.com
# Allowed example.com -> <resolved-ip> for my-container

terok-shield deny my-container example.com   # revoke later
```

## Documentation

- **[User Guide](https://terok-ai.github.io/terok-shield/guide/)** —
  getting started, allowlist profiles, firewall modes, CLI reference
- **[Developer Guide](https://terok-ai.github.io/terok-shield/developer/)** —
  contributing, security model, architecture

## License

Apache-2.0 — see [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt).
