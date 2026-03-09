# Audit Logging

terok-shield logs firewall events at two levels: application-level JSON-lines
logs and kernel-level per-packet nftables logs.

## Application logs (JSON-lines)

Firewall events are logged to `~/.local/state/terok-shield/logs/<container>.jsonl`.

Each line is a JSON object:

```json
{"ts": "2026-03-07T12:00:00+00:00", "container": "my-container", "action": "setup", "detail": "ruleset applied"}
{"ts": "2026-03-07T12:00:00+00:00", "container": "my-container", "action": "setup", "detail": "read 3 cached IPs"}
{"ts": "2026-03-07T12:00:00+00:00", "container": "my-container", "action": "setup", "detail": "verification passed"}
```

### Actions

| Action | Meaning |
|--------|---------|
| `setup` | Firewall setup step (ruleset applied, IPs loaded, verification) |
| `allow` | Domain/IP added to allow set at runtime |
| `deny` | Domain/IP removed from allow set at runtime |
| `note` | Advisory event (e.g. RFC1918 or link-local address allowlisted) |
| `error` | Something failed |

### Viewing logs

```bash
# Last 10 entries for a specific container
terok-shield logs --container my-container -n 10

# Last 5 entries across all containers
terok-shield logs -n 5
```

### Detail prefixes

Lines prefixed with `[ips]` contain full IP lists and can be filtered out
by log readers that only need summaries:

```json
{"action": "setup", "detail": "[ips] cached: 1.1.1.1, 1.0.0.1, 10.0.0.5"}
{"action": "setup", "detail": "[ips] added to allow_v4: 1.1.1.1, 1.0.0.1"}
```

## Kernel packet logs

nftables rules generate per-packet entries in dmesg/journald using log
prefixes:

| Prefix | Meaning |
|--------|---------|
| `TEROK_SHIELD_DENIED:` | Packet dropped by deny-all rule |
| `TEROK_SHIELD_ALLOWED:` | Packet accepted by allow set (rate-limited: 10/sec) |
| `TEROK_SHIELD_RFC1918:` | Packet rejected by RFC1918 rule |

View with:

```bash
journalctl -k --grep TEROK_SHIELD
```

## Disabling audit logging

In `~/.config/terok-shield/config.yml`:

To disable logging of allowed connections only (denied connections are still logged):

```yaml
audit:
  enabled: true
  log_allowed: false
```

To disable all application logging:

```yaml
audit:
  enabled: false
```
