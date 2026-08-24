# down/ — Shield Down/Up Posture Tests

Tests for the manual posture toggle that temporarily switches a container
from the deny-all UP posture to the accept+log DOWN (or DISENGAGED) posture
for traffic discovery.

## Stories

| File | What it tests |
|------|---------------|
| `test_state.py` | `shield_state()` detection: UP, DOWN, DISENGAGED, OFFLINE |
| `test_traffic.py` | Network behavior while down: traffic flows, RFC1918 protection, IPv6 drop |
| `test_cli.py` | CLI `down`, `up`, `rules --state`, `preview --down` commands |
| `test_lifecycle.py` | Full E2E lifecycle: state transitions, idempotency, IP restoration, audit trail |
