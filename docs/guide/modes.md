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
│  │ allow: DNS, lo, @allow_v4/v6      │  │
│  │ reject: RFC1918, RFC4193           │  │
│  └────────────────────────────────────┘  │
│                                          │
│  Workload (CAP_NET_ADMIN dropped)        │
└──────────────────────────────────────────┘
```

### How it works

1. `Shield.pre_start()` installs hooks into the container's state directory,
   resolves DNS to `profile.allowed`, and returns podman args with OCI
   annotations (`state_dir`, `loopback_ports`, `version`)
2. When podman creates a container with the `terok.shield.profiles` annotation,
   it fires the hook at the `createRuntime` stage
3. The hook reads `state_dir` from annotations, enters the container's network
   namespace via `nsenter`, and applies nftables rules
4. The workload starts with `CAP_NET_ADMIN` and `CAP_NET_RAW` dropped, so it
   cannot modify the rules

### Chain evaluation order

```text
loopback → established → DNS → loopback ports → allow_v4/v6 → private-range reject (RFC1918 + RFC4193) → deny all
```

### When to use

- Single containers or small deployments
- When you want per-container isolation (each container has its own firewall)
- Simplest setup — just needs `nft` binary

### Per-container state bundle

Each container's hooks and state are isolated in its own directory:

```text
{state_dir}/
├── hooks/                                  # OCI hook descriptors
├── terok-shield-hook                       # Hook entrypoint script
├── profile.allowed                         # IPs from DNS resolution
├── live.allowed                            # IPs from allow/deny
└── audit.jsonl                             # Per-container audit log
```

### Running containers

Via the CLI (recommended for standalone usage):

```bash
terok-shield run my-container -- my-image
```

Via the Python API (this is how [terok](https://github.com/terok-ai/terok)
uses terok-shield as a library):

```python
from terok_shield import Shield, ShieldConfig
shield = Shield(ShieldConfig(state_dir=Path("~/.local/state/terok-shield/containers/my-ctr")))
extra_args = shield.pre_start("my-ctr", ["dev-standard"])
# pass extra_args to podman run
```

!!! note "Future modes"
    Additional modes for different network topologies may be added in the future.
