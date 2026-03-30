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
   resolves DNS, writes `profile.allowed`, pre-generates the complete nft ruleset
   to `ruleset.nft`, and returns podman args with OCI annotations (`state_dir`,
   `loopback_ports`, `version`, `upstream_dns`, `dns_tier`)
2. When podman creates a container with the `terok.shield.profiles` annotation,
   it fires the stdlib-only hook script at the `createRuntime` stage
3. The hook reads `state_dir` from annotations, applies `ruleset.nft` inside the
   container's network namespace via `nsenter`, discovers the gateway from
   `/proc/{pid}/net/route`, and starts a per-container dnsmasq instance if the
   dnsmasq tier is active
4. dnsmasq runs inside the container's network namespace with `--nftset` pointing
   to the `allow_v4`/`allow_v6` sets — every DNS resolution automatically adds the
   resolved IPs to the live nft allow sets
5. The workload starts with `CAP_NET_ADMIN` and `CAP_NET_RAW` dropped, so it
   cannot modify the rules

### Chain evaluation order

```text
loopback → established → DNS → gateway ports → loopback ports → allow_v4/v6 → private-range reject (RFC1918 + RFC4193) → deny all
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
├── terok-shield-hook                       # Hook entrypoint (stdlib-only Python)
├── ruleset.nft                             # Pre-generated nft ruleset
├── gateway                                 # Discovered gateway IP
├── profile.allowed                         # IPs from pre-start DNS resolution
├── profile.domains                         # Domain names for dnsmasq config
├── live.allowed                            # IPs from allow/deny
├── deny.list                               # Persistent deny overrides
├── dnsmasq.conf                            # Generated dnsmasq config (dnsmasq tier)
├── dnsmasq.pid                             # dnsmasq PID (dnsmasq tier)
├── resolv.conf                             # Bind-mounted /etc/resolv.conf (dnsmasq tier)
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

### dnsmasq and the nft allow sets

When dnsmasq is active, the allow sets are populated dynamically — no manual
`terok-shield allow` calls are needed for domains already in the profile.
Every `dig`, `getaddrinfo`, or HTTP request that triggers a DNS lookup inside
the container adds the resolved IPs to `allow_v4`/`allow_v6` automatically.

To watch the sets grow in real time:

```bash
watch terok-shield rules my-container
```

!!! note "Future modes"
    Additional modes for different network topologies may be added in the future.
