# Firewall Modes

terok-shield supports two operating modes. Both enforce the same default-deny
policy — they differ in where the nftables rules are applied and how traffic
flows.

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

## Bridge mode

Uses a dedicated bridge network (`ctr-egress`) with nftables rules applied in
podman's rootless-netns. All container traffic traverses the bridge and is
filtered centrally. Requires infrastructure (`ctr-egress` bridge + `dnsmasq`).

```text
┌─────────────────────────────────────────────────┐
│ rootless-netns                                  │
│                                                 │
│  ┌───────────────────────────────────────────┐  │
│  │ nftables (forward chain)                 │  │
│  │ policy: DROP                             │  │
│  │ per-container allow sets + forward rules │  │
│  └───────────────────────────────────────────┘  │
│              │                                  │
│     ┌────────┴────────┐                         │
│     │  ctr-egress     │  (bridge network)       │
│     │  10.91.0.0/24   │                         │
│     └────┬───────┬────┘                         │
│          │       │                              │
│    ┌─────┘       └─────┐                        │
│    ▼                   ▼                        │
│ Container A       Container B                   │
└─────────────────────────────────────────────────┘
```

### How it works

1. A named bridge network (`ctr-egress`, subnet `10.91.0.0/24`) is created
   with dnsmasq providing DNS
2. Containers are started on this bridge network instead of the default pasta/slirp
3. nftables rules in the rootless-netns forward chain filter all traffic passing
   through the bridge
4. Each container gets its own allow set and forward rules, managed via the
   Python API lifecycle hooks

### Chain evaluation order

```text
IPv6 drop → established → DNS → gate → allow_v4 → RFC1918 reject → ICMP → intra-bridge → deny all
```

### When to use

- Multiple containers that share a controlled network
- When you want centralized firewall management
- Rules live outside the container's namespace entirely

### Prerequisites

- `nft` binary
- `dnsmasq` for bridge DNS
- The bridge network must exist before setup:

```bash
podman network create --subnet 10.91.0.0/24 --gateway 10.91.0.1 ctr-egress
```

### Setup

```bash
terok-shield setup --bridge
```

### Running containers (via Python API)

Bridge mode is typically used via the Python API rather than the CLI, because
it requires lifecycle hooks around `podman run`:

```python
from terok_shield import shield_pre_start, shield_post_start, shield_pre_stop

# Before podman run — returns args like ["--network", "ctr-egress", "--dns", "10.91.0.1"]
args = shield_pre_start("my-container", ["dev-standard"])

# Start container with the returned args
# podman run <args> my-image

# After container starts — creates per-container rules in rootless-netns
shield_post_start("my-container", ["dev-standard"])

# Before stopping — cleans up per-container rules
shield_pre_stop("my-container")
```

## Comparison

| | Hook | Bridge |
|--|------|--------|
| **Network** | pasta/slirp (default) | Named bridge (`ctr-egress`) |
| **Firewall location** | Container's netns | rootless-netns (shared) |
| **Isolation** | Per-container | Centralized |
| **Requirements** | `nft` | `nft` + `dnsmasq` + bridge |
| **Setup** | `terok-shield setup` | Bridge creation + `terok-shield setup --bridge` |
| **Container start** | Podman annotation + hooks-dir | Python API lifecycle hooks |
| **Best for** | Simple deployments | Multi-container environments |
