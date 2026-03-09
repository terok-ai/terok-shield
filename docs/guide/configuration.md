# Configuration

terok-shield uses XDG-compliant directories and an optional YAML config file.

## Config file

Optional. Located at `~/.config/terok-shield/config.yml`
(or `$XDG_CONFIG_HOME/terok-shield/config.yml`).

```yaml
mode: hook              # currently only "hook" is supported
default_profiles:
  - dev-standard
gate_port: 9418
audit:
  enabled: true
  log_allowed: true
```

| Key | Default | Description |
|-----|---------|-------------|
| `mode` | `auto` | Firewall mode. `auto` selects the best available mode |
| `default_profiles` | `["dev-standard"]` | Profiles used when resolving without explicit profile list |
| `gate_port` | `9418` | Loopback port allowed for the gate server |
| `audit.enabled` | `true` | Enable JSON-lines audit logging |
| `audit.log_allowed` | `true` | Log allowed connections (not just denied) |

If the config file is missing or unparseable, defaults are used.

### Mode selection

Currently only hook mode is supported. Setting `mode: auto` or `mode: hook`
both resolve to hook mode. Future modes may be added for different network
topologies.

## Directories

All paths follow XDG conventions and can be overridden with environment variables.

### State directory

Default: `~/.local/state/terok-shield/`
Override: `TEROK_SHIELD_STATE_DIR`

| Subdirectory | Contents |
|-------------|----------|
| `hooks/` | OCI hook JSON descriptor and entrypoint script |
| `resolved/` | Pre-resolved IP cache files (one per container) |
| `logs/` | Audit logs (JSON-lines, one file per container) |
| `dns/` | Downloaded DNS allowlists |

### Config directory

Default: `~/.config/terok-shield/`
Override: `TEROK_SHIELD_CONFIG_DIR`

| Subdirectory | Contents |
|-------------|----------|
| `profiles/` | Custom allowlist profiles (override bundled ones) |
| `config.yml` | Shield configuration |

## DNS caching

Resolved IPs are stored in `<state_dir>/resolved/<container>.resolved` as
plain text, one IP per line. The cache uses file modification time
(`st_mtime`) for freshness checking — entries older than 1 hour are
automatically re-resolved.

Force a cache refresh:

```bash
terok-shield resolve my-container --force
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `TEROK_SHIELD_STATE_DIR` | Override state directory location |
| `TEROK_SHIELD_CONFIG_DIR` | Override config directory location |
| `XDG_STATE_HOME` | XDG state base (default: `~/.local/state`) |
| `XDG_CONFIG_HOME` | XDG config base (default: `~/.config`) |
