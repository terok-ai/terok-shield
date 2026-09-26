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
│  │ nftables (applied by OCI hook)     │  │
│  │ policy: DROP                       │  │
│  │ allow: DNS, lo, @t40_project_allow │  │
│  │ reject: RFC1918, RFC4193           │  │
│  └────────────────────────────────────┘  │
│                                          │
│  Workload (CAP_NET_ADMIN dropped)        │
└──────────────────────────────────────────┘
```

### How it works

1. `Shield.pre_start()` installs the OCI hooks (see
   [Per-container state bundle](#per-container-state-bundle) for where they
   land), processes the allowlist profiles, and pre-generates the complete nft
   ruleset to `ruleset.nft`. On the live tier the composed policy lands in
   `policy/40-project-allow` and only literal IP entries seed the sets; on every
   other tier the domains are resolved now, into `resolved.ips`, and the
   terminal says so (see [DNS tiers](#dns-tiers)).

   Returns podman args with OCI annotations (`state_dir`, `loopback_ports`,
   `version`, `upstream_dns`, `dns_tier`)
2. When podman creates a container with the `terok.shield.profiles` annotation,
   it fires the stdlib-only hook script at the `createRuntime` stage
3. The hook reads `state_dir` from annotations and applies the pre-generated
   `ruleset.nft` (gateway addresses already baked in at `pre_start`) inside the
   container's network namespace via `nsenter`, then starts the recorded
   dnsmasq binary when `dnsmasq.conf` is present
4. On the live tier dnsmasq runs with `--nftset` pointing to the
   `t40_project_allow_v4`/`t40_project_allow_v6` sets — every DNS resolution
   adds the resolved IPs to the live nft project-allow sets before the answer
   reaches the workload
5. The workload starts with `CAP_NET_ADMIN` and `CAP_NET_RAW` dropped, so it
   cannot modify the rules

### DNS tiers

Shield picks the best tier the host supports and records it per container.
Only the first tier resolves live; the others resolve the allowlist once at
launch and cannot follow an address that rotates afterwards.

| Capability | `dnsmasq-live` | `dnsmasq-static` | `lookup` | `getent` |
|---|---|---|---|---|
| Allow sets follow IP rotation | yes | no | no | no |
| Subdomains of an allowed domain reachable | yes | no | no | no |
| Wildcard entries such as `*.example.com` | yes | refused at launch | refused at launch | refused at launch |
| Blocked-connection events carry the name | yes | yes | IP only | IP only |
| Denied names fail fast with NXDOMAIN | yes | yes | no | no |
| `allow name` while running | addresses now, rotation later | addresses now | addresses now | addresses now |
| Host needs | dnsmasq built with nftset support | any dnsmasq | `dig` or `drill` | glibc only |

To reach the live tier, install the distro's dnsmasq (`dnsmasq-base` on Debian
and Ubuntu). Distros whose package lacks nftset support (the RHEL 9 and 10
family, Ubuntu 22.04, Gentoo, Alpine's default package) land on
`dnsmasq-static`; a dnsmasq built from source with `COPTS=-DHAVE_NFTSET`, for
example in your home, restores the live tier without root. Point shield at it
with `dnsmasq_path` (see [Configuration](configuration.md#dnsmasq-binary)).

### Chain evaluation order

```text
preamble (lo, established, DNS, infra ports, +localhost grants) → t00 hard-deny (link-local + IMDS) → t10 override → t20 security-deny (@t20_security_deny + RFC1918/RFC4193) → t30 provider allow → t40 project allow → bypass window → terminal reject (log BLOCKED)
```

### When to use

- Single containers or small deployments
- When you want per-container isolation (each container has its own firewall)
- Simplest setup — just needs `nft` binary

### Per-container state bundle

Each container's state is isolated in its own directory:

```text
{state_dir}/
├── policy/                                 # v15 tiered +/- policy, one file per tier set
│   ├── 10-override                         #   → nft set t10_override (break-glass allow)
│   ├── 20-security-deny                    #   → nft set t20_security_deny (vault hosts + operator deny)
│   ├── 30-provider-allow                   #   → nft set t30_provider_allow (provider egress)
│   ├── 40-project-allow                    #   → nft set t40_project_allow (project allowlist)
│   └── live                                #   Runtime allow/deny overlay (+/- lines)
├── resolved.ips                            # Resolved allow IPs (t40 seed; every tier but dnsmasq-live)
├── ruleset.nft                             # Pre-generated nft ruleset (gateways baked in)
├── dnsmasq.conf                            # Generated dnsmasq config (dnsmasq tiers)
├── dnsmasq.pid                             # dnsmasq PID (dnsmasq tiers)
├── dnsmasq.bin                             # Live dnsmasq identity (cleanup only)
├── resolv.conf                             # Bind-mounted /etc/resolv.conf (every tier)
├── upstream.dns                            # Persisted upstream DNS address
├── dns.tier                                # Persisted active DNS tier
└── audit.jsonl                             # Per-container audit log
```

> **Global hooks.** `terok-shield setup` installs hooks under
> `<state_root>/shield/hooks` and registers them in `containers.conf`.
> Task preparation never modifies them; bare Podman restarts remain protected.

### Running containers

Via the CLI (recommended for standalone usage):

```bash
terok-shield run my-container -- my-image
```

Via the Python API (this is how [terok](https://github.com/terok-ai/terok)
uses terok-shield as a library):

```python
from pathlib import Path

from terok_shield import Shield, ShieldConfig

shield = Shield(ShieldConfig(state_dir=Path.home() / ".local/state/terok/shield/containers/my-ctr"))
extra_args = shield.pre_start("my-ctr", ["dev-standard"])
# pass extra_args to podman run
```

### dnsmasq and the nft allow sets

On the live tier the allow sets are populated dynamically — no manual
`terok-shield allow` calls are needed for domains already in the profile.
Every `dig`, `getaddrinfo`, or HTTP request that triggers a DNS lookup inside
the container adds the resolved IPs to `t40_project_allow_v4`/`t40_project_allow_v6`
automatically.

To watch the sets grow in real time:

```bash
watch terok-shield rules my-container
```

!!! note "Future modes"
    Additional modes for different network topologies may be added in the future.
