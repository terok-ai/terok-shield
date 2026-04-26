# terok-shield

Default-deny egress firewall for rootless Podman containers.

terok-shield enforces **default-deny outbound** network filtering on
Podman containers using nftables.  Containers can only reach
explicitly allowed destinations — everything else is rejected with
an ICMP error and a per-packet audit entry.  No changes to images,
no daemon, no host-wide rules.

![terok ecosystem — terok-shield is the security boundary at the bottom of the stack](img/architecture.svg)

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

### Key properties

- **Default-deny egress** — containers start with no outbound access
- **DNS-based allowlisting** — allowed destinations specified as domain names, resolved and cached automatically
- **Private-range awareness** — allowlisting RFC 1918/RFC 4193 (private network) addresses generates a notice in the audit log
- **Dual-stack** — full IPv4 and IPv6 support with separate allow sets
- **Fail-closed** — if the firewall hook fails, the container is torn down
- **Audit logging** — JSON-lines lifecycle logs + kernel-level per-packet nftables logs
- **Live allow/deny** — add or remove IPs at runtime without restarting the container
- **Per-container isolation** — each container gets its own state bundle, hooks, and audit log

### Hook mode

Uses an OCI hook to apply per-container nftables rules inside each container's
network namespace. Works with pasta/slirp (rootless default). Only requires the
`nft` binary.

See [Firewall Modes](guide/modes.md) for details.

## Quick start

### 1. Install

```bash
pip install terok-shield
```

No changes to your Dockerfiles or container images are needed — the firewall
is applied externally at container creation time.

### 2. Start a shielded container

```bash
terok-shield run my-container -- alpine:latest sh
```

This resolves DNS, installs OCI hooks, and launches the container with a
default-deny firewall — only destinations in the `dev-standard`
[allowlist profile](guide/profiles.md) are reachable. To use custom profiles:

```bash
terok-shield run my-container --profiles dev-standard dev-python -- alpine:latest sh
```

!!! tip "Scripting"
    For scripting or advanced workflows, use `terok-shield prepare` to get
    the podman flags without launching — see the [CLI Reference](guide/cli.md).

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
- [Firewall Modes](guide/modes.md) — hook mode details
- [Configuration](guide/configuration.md) — config file, paths, caching
- [Audit Logging](guide/logging.md) — log format and inspection
