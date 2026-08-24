# Audit Logging

terok-shield logs firewall events at two levels: application-level JSON-lines
logs and kernel-level per-packet nftables logs.

## Application logs (JSON-lines)

Each container has its own audit log at `{state_dir}/audit.jsonl` (e.g.
`~/.local/state/terok/shield/containers/my-container/audit.jsonl`).

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
| `allowed` | Domain/IP added to allow set at runtime |
| `denied` | Domain/IP removed from allow set at runtime |
| `shield_down` | Container switched to the DOWN posture |
| `shield_up` | Container restored to deny-all mode |
| `note` | Advisory event (e.g. private-range address allowlisted — RFC 1918/RFC 4193) |
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
{"action": "setup", "detail": "[ips] added to allow sets: 1.1.1.1, 1.0.0.1"}
```

## Kernel packet logs

nftables rules generate per-packet entries in dmesg/journald using log
prefixes:

| Prefix | Meaning |
|--------|---------|
| `TEROK_SHIELD_ALLOWED:` | New connection accepted by allow set (not rate-limited; established traffic is accepted earlier in the chain and not logged) |
| `TEROK_SHIELD_DENIED:` | Packet rejected by the explicit deny set (operator refused) |
| `TEROK_SHIELD_PRIVATE:` | Packet rejected by private-range rule (RFC 1918 + RFC 4193/4291) |
| `TEROK_SHIELD_BLOCKED:` | Packet rejected by the terminal default-deny rule (unclassified) |
| `TEROK_SHIELD_BYPASS:` | Packet accepted through the bypass window or while the shield is down |

View with:

```bash
journalctl -k --grep TEROK_SHIELD
```

## Disabling audit logging

In `~/.config/terok/shield/config.yml`:

```yaml
audit:
  enabled: false
```

This disables all application-level logging. Kernel packet logs are
controlled by the nftables ruleset and remain active regardless.
