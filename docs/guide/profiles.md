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

The default profile is `dev-standard`. You can see all available profiles with:

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

!!! note "RFC1918 addresses in profiles"
    Private network addresses like `10.0.0.5/32` are valid in profiles.
    Allowlisting them (or link-local addresses) generates a notice in the audit log.

## Custom profiles

To create a custom profile, place a `.txt` file in your profiles directory:

```bash
mkdir -p ~/.config/terok-shield/profiles

cat > ~/.config/terok-shield/profiles/my-project.txt << 'EOF'
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
# Profiles: base, dev-node, dev-python, dev-standard, my-project, nvidia-hpc
```

### Overriding bundled profiles

If you create a custom profile with the same name as a bundled one
(e.g. `~/.config/terok-shield/profiles/dev-standard.txt`), your version
takes precedence. The bundled version is ignored.

## Using profiles

### At container start

Specify profiles via the podman annotation:

```bash
# Single profile
podman run --annotation terok.shield.profiles=dev-standard ...

# Multiple profiles (comma-separated, merged with deduplication)
podman run --annotation terok.shield.profiles=dev-standard,dev-python,my-project ...
```

### Pre-resolving DNS

Before starting a container, resolve the profile domains to IPs:

```bash
terok-shield resolve my-container
```

This resolves all domains from the configured profiles using `dig` and caches
the results. The cache is automatically refreshed when stale (default: 1 hour).
Force a refresh with:

```bash
terok-shield resolve my-container --force
```

### Changing the default profile

Edit `~/.config/terok-shield/config.yml`:

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
podman run --annotation terok.shield.profiles=base,dev-standard,dev-python,my-project ...
```

Each profile must be listed explicitly. There is no implicit inclusion —
if you want `base` infrastructure domains, include `base` in the list.
