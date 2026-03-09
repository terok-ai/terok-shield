# terok-shield

nftables-based egress firewalling for rootless Podman containers.

## What it does

terok-shield enforces **default-deny outbound** network filtering on Podman
containers using nftables. Containers can only reach explicitly allowed
destinations — everything else is rejected with an ICMP error.

### Key properties

- **Default-deny egress** — containers start with no outbound access
- **DNS-based allowlisting** — allowed destinations specified as domain names, resolved and cached automatically
- **RFC1918 awareness** — allowlisting private network or link-local addresses generates a notice in the audit log
- **IPv6 dropped** — all IPv6 traffic unconditionally dropped (IPv4-only allow sets)
- **Fail-closed** — if the firewall hook fails, the container is torn down
- **Audit logging** — JSON-lines lifecycle logs + kernel-level per-packet nftables logs
- **Live allow/deny** — add or remove IPs at runtime without restarting the container

### Two operating modes

| Mode | Network | Firewall scope | Requirements |
|------|---------|----------------|--------------|
| **Hook** | pasta/slirp (rootless default) | Per-container netns via OCI hook | `nft` binary |
| **Bridge** | Named bridge (`ctr-egress`) | rootless-netns (shared) | `nft` + `dnsmasq` + bridge network |

See [Firewall Modes](guide/modes.md) for details on when to use each.

## Quick start

### 1. Install and set up

```bash
pip install terok-shield

terok-shield setup        # install OCI hook
terok-shield status       # verify
```

No changes to your Dockerfiles or container images are needed — the firewall
is applied externally at container creation time.

### 2. Start a shielded container

```bash
terok-shield resolve my-container    # pre-resolve DNS → cached IPs

podman run --rm -it \
  --name my-container \
  --annotation terok.shield.profiles=dev-standard \
  --hooks-dir ~/.local/state/terok-shield/hooks \
  --cap-drop NET_ADMIN --cap-drop NET_RAW \
  --security-opt no-new-privileges \
  alpine:latest sh
```

The container starts with a default-deny firewall — only destinations in the
`dev-standard` [allowlist profile](guide/profiles.md) are reachable.

### 3. Allow a domain at runtime

While the container is running, you can add or remove destinations:

```bash
terok-shield allow my-container example.com
# Allowed example.com -> <resolved-ip> for my-container

terok-shield deny my-container example.com   # revoke later
```

### 4. Inspect

```bash
terok-shield rules my-container     # show active nft rules
terok-shield logs --container my-container -n 10   # recent audit log
```

## Next steps

- [Getting Started](guide/getting_started.md) — full setup walkthrough
- [Allowlist Profiles](guide/profiles.md) — bundled profiles and custom allowlists
- [CLI Reference](guide/cli.md) — all commands and options
- [Firewall Modes](guide/modes.md) — hook vs. bridge
- [Configuration](guide/configuration.md) — config file, paths, caching
- [Audit Logging](guide/logging.md) — log format and inspection
