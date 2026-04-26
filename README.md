# terok-shield

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![REUSE status](https://api.reuse.software/badge/github.com/terok-ai/terok-shield)](https://api.reuse.software/info/github.com/terok-ai/terok-shield)
[![codecov](https://codecov.io/gh/terok-ai/terok-shield/branch/master/graph/badge.svg?token=D74Q7lvnIF)](https://codecov.io/gh/terok-ai/terok-shield)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=terok-ai_terok-shield&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=terok-ai_terok-shield)

Default-deny egress firewall for rootless Podman containers.

terok-shield enforces **default-deny outbound** network filtering on
Podman containers using nftables.  Containers can only reach
explicitly allowed destinations — everything else is rejected with
an ICMP error and a per-packet audit entry.  No changes to images,
no daemon, no host-wide rules.

<p align="center">
  <img src="docs/img/architecture.svg" alt="terok ecosystem — terok-shield is the security boundary at the bottom of the stack">
</p>

## Where it sits in the stack

terok-shield is the security-boundary layer of the terok ecosystem.
The hardened-Podman runtime
([terok-sandbox](https://github.com/terok-ai/terok-sandbox)) installs
the OCI hooks at setup time; the operator-in-the-loop verdict
service ([terok-clearance](https://github.com/terok-ai/terok-clearance))
mutates the live ruleset on Allow / Deny decisions.  The shield
itself is independent of all of these — it works on any rootless
Podman container, with or without the rest of terok, and is the
piece you would use first to evaluate the approach before adopting
the full stack.

## Features

- **Default-deny egress** with curated allowlists (domains and IPs)
- **Dynamic DNS allowlisting** — per-container dnsmasq with
  `--nftset` auto-populates allow sets on every DNS resolution,
  handling IP rotation at runtime; falls back to static pre-start
  resolution via `dig` or `getent` when dnsmasq is unavailable
- **Live allow/deny** at runtime for individual containers
- **Per-container isolation** — each container gets its own state
  bundle, hooks, and audit log
- **Connection audit logging** (JSON-lines lifecycle logs +
  kernel-level per-packet nftables logs)
- **Fail-closed** — hook failure prevents the container from
  starting

## Requirements

- Linux with nftables (`nft` binary) — tested on Fedora 43,
  Debian 12 and 13, and Ubuntu 24.04, also works on other modern
  Linux distros
- Podman (rootless, recommended ≥ 5.6.0, untested < 4.3.1)
- Python 3.12+
- `dnsmasq` (recommended) for dynamic DNS-based egress control;
  `dig` (`dnsutils` / `bind-utils`) as fallback

## Installation

```bash
pip install terok-shield
```

## Quick start

### 1. Choose your allowlists

terok-shield ships with several bundled profiles
(see [Allowlist Profiles](https://terok-ai.github.io/terok-shield/guide/profiles/)):

| Profile | Domains |
|---------|---------|
| `base` | DNS roots, NTP, OCSP, OS package repos |
| `dev-standard` | GitHub, Docker Hub, PyPI, npm, crates.io, Go |
| `dev-python` | Conda, Read the Docs, Python docs |
| `dev-node` | Yarn, jsDelivr, unpkg |
| `nvidia-hpc` | CUDA, NGC, NVIDIA drivers |

The default profile is `dev-standard`.  To add a custom allowlist,
create a `.txt` file with one domain or IP per line:

```bash
mkdir -p ~/.config/terok/shield/profiles
cat > ~/.config/terok/shield/profiles/my-project.txt << 'EOF'
api.example.com
cdn.example.com
203.0.113.10
EOF
```

### 2. Start a container with the shield

```bash
terok-shield run my-container -- alpine:latest sh
```

This resolves DNS, installs OCI hooks, and launches the container
with a default-deny firewall — only destinations in the
`dev-standard` profile are reachable.  To use custom profiles:

```bash
terok-shield run my-container --profiles dev-standard my-project -- alpine:latest sh
```

### 3. Allow a domain at runtime

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
