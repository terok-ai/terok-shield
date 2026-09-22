# Allowlist Profiles

Profiles are `.txt` files that list the domains and IPs a container is allowed
to reach. terok-shield ships with several bundled profiles and supports custom
user-defined ones.

## Bundled profiles

| Profile | Contents |
|---------|----------|
| `base` | DNS roots, NTP, OCSP, OS package repos (Ubuntu, Debian, Fedora, Alpine) |
| `dev-standard` | GitHub, GitLab, Docker Hub, GHCR, PyPI, npm, crates.io, Go proxy |
| `dev-python` | Conda, Read the Docs, Python docs |
| `dev-node` | Yarn, jsDelivr, unpkg, CDN resources |
| `nvidia-hpc` | CUDA downloads, NGC registry, NVIDIA drivers |

No profile applies unless you name one. You can see all available profiles with:

```bash
terok-shield status
```

## Profile file format

Each profile is a plain text file with one entry per line. Entries can be
domain names or IP addresses/CIDRs. Comments start with `#`.

```text
# My project's API servers
api.example.com
cdn.example.com

# Static IP for internal service
203.0.113.10
10.0.0.5/32
```

!!! note "Private-range addresses in profiles"
    Private network addresses like `10.0.0.5/32` (RFC 1918) or ULA addresses
    (RFC 4193) are valid in profiles. Allowlisting them generates a notice
    in the audit log.

## Custom profiles

To create a custom profile, place a `.txt` file in your profiles directory:

```bash
mkdir -p ~/.config/terok/shield/profiles

cat > ~/.config/terok/shield/profiles/my-project.txt << 'EOF'
# APIs my project needs
api.example.com
webhooks.example.com

# Static infrastructure
203.0.113.10
EOF
```

Custom profiles appear alongside the bundled ones:

```bash
terok-shield status
# Available profiles: base, dev-node, dev-python, dev-standard, krun_guest, my-project, nvidia-hpc
```

### Overriding bundled profiles

If you create a custom profile with the same name as a bundled one
(e.g. `~/.config/terok/shield/profiles/dev-standard.txt`), your version
takes precedence. The bundled version is ignored.

## Using profiles

### At container start

Specify profiles with the `--profiles` flag:

```bash
# One profile
terok-shield run my-container --profiles dev-standard -- alpine:latest sh

# Multiple profiles (comma-separated)
terok-shield run my-container --profiles dev-standard,dev-python,my-project \
  -- alpine:latest sh
```

DNS resolution happens automatically. On `dnsmasq-live` domains are resolved
per query at runtime; on every other tier they are resolved at launch and
cached in the container's `resolved.ips` file (default freshness: 1 hour), and
a wildcard entry such as `*.example.com` stops the launch, because nothing
resolves it there. See [DNS tiers](modes.md#dns-tiers).

### Pre-resolving DNS

You can also re-resolve a prepared container's DNS separately, for debugging
or to inspect the resolved IPs. `resolve` refreshes the container's resolution
caches from the policy it launched with and rewrites no policy:

```bash
terok-shield resolve my-container
terok-shield resolve my-container --force   # re-resolve even when the cache is fresh
```

### Default profiles

`default_profiles` in `~/.config/terok/shield/config.yml` names the profiles
that apply when a command does not pass `--profiles`. The list is empty unless
you set it:

```yaml
default_profiles:
  - dev-standard
  - dev-python
  - my-project
```

## Profile composition

When multiple profiles are specified, their entries are merged with
deduplication (first occurrence wins). This lets you layer profiles —
for example:

```bash
terok-shield run my-container \
  --profiles base,dev-standard,dev-python,my-project \
  -- alpine:latest sh
```

Each profile must be listed explicitly. There is no implicit inclusion —
if you want `base` infrastructure domains, include `base` in the list.
