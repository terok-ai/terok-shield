# terok-shield

nftables-based egress firewalling for rootless Podman containers.

## What it does

terok-shield enforces **default-deny outbound** network filtering on Podman containers using nftables. Containers can only reach explicitly allowed destinations — everything else is rejected.

### Key properties

- **Default-deny egress** — containers start with no outbound access
- **DNS-based allowlisting** — allowed destinations specified as domain names, resolved and cached automatically
- **RFC1918 blocking** — private networks and link-local addresses are always blocked (LAN isolation)
- **Fail-closed** — if the firewall hook fails, the container is torn down
- **Audit logging** — all allowed and denied connections logged as JSON-lines

### Two operating modes

| Mode | Network | Firewall scope | Requirements |
|------|---------|----------------|--------------|
| **Standard** | pasta/slirp (rootless default) | Per-container netns via OCI hook | `nft` binary |
| **Hardened** | Named bridge (`ctr-egress`) | rootless-netns (shared) | `nft` + `dnsmasq` + bridge network |

## Quick start

```bash
pip install terok-shield

terok-shield setup        # install OCI hook
terok-shield status       # verify
terok-shield resolve      # resolve DNS allowlists
```

## Documentation

- [Security Model](SECURITY.md) — threat model, architecture, trust boundaries
- [Contributing](DEVELOPER.md) — development setup and conventions
- [Code Quality](quality-report.md) — auto-generated quality metrics
- [API Reference](reference/) — auto-generated from docstrings
