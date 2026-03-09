# Firewall Modes

terok-shield uses **hook mode** — an OCI hook that applies nftables rules inside
each container's own network namespace.

## Hook mode

Self-contained. Uses an OCI hook to apply nftables rules inside each container's
own network namespace.

```text
┌──────────────────────────────────────────┐
│ Container netns                          │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │ nftables (applied by OCI hook)    │  │
│  │ policy: DROP                      │  │
│  │ allow: DNS, gate, @allow_v4       │  │
│  │ reject: RFC1918                   │  │
│  └────────────────────────────────────┘  │
│                                          │
│  Workload (CAP_NET_ADMIN dropped)        │
└──────────────────────────────────────────┘
```

### How it works

1. `terok-shield setup` installs an OCI hook — a JSON descriptor and shell
   script in `~/.local/state/terok-shield/hooks/`
2. When podman creates a container with the `terok.shield.profiles` annotation,
   it fires the hook at the `createRuntime` stage
3. The hook reads the container's PID, enters its network namespace via
   `nsenter`, and applies nftables rules
4. The workload starts with `CAP_NET_ADMIN` and `CAP_NET_RAW` dropped, so it
   cannot modify the rules

### Chain evaluation order

```text
IPv6 drop → loopback → established → DNS → gate port → allow_v4 → RFC1918 reject → deny all
```

### When to use

- Single containers or small deployments
- When you want per-container isolation (each container has its own firewall)
- Simplest setup — just needs `nft` binary

### Setup

```bash
terok-shield setup
```

### Running containers

```bash
podman run \
  --name my-container \
  --annotation terok.shield.profiles=dev-standard \
  --hooks-dir ~/.local/state/terok-shield/hooks \
  --cap-drop NET_ADMIN --cap-drop NET_RAW \
  --security-opt no-new-privileges \
  my-image
```

!!! note "Future modes"
    Additional modes for different network topologies may be added in the future.
