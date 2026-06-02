# AppArmor & the dnsmasq DNS tier

shield's strongest DNS-egress mode runs a per-container **dnsmasq** that
auto-populates the nft allow sets from live DNS replies (the `dnsmasq`
tier — it handles domains with rotating IPs). That dnsmasq reads its
config and writes its pid/log under the per-task shield state directory
in your home (`~/.local/share/terok/.../shield/`).

## On AppArmor-enforcing hosts

Distributions that ship an **enforcing AppArmor profile for
`/usr/sbin/dnsmasq`** (Arch/Manjaro, and anywhere the [`apparmor.d`][1]
profile set is installed) confine dnsmasq to the conventional server
paths and forbid your home directory, so the confined dnsmasq is denied
reading its config there.

shield handles this automatically: at pre-start it probes whether a
confined dnsmasq can read the state dir (running `dnsmasq --test` — no
root needed) and, if not, **falls back to the `dig` tier**. Egress
filtering stays fully enforced; only DNS handling degrades — domain
allowlists resolve statically at pre-start instead of tracking IP
rotation live. The fallback is recorded in the per-container audit log.

## Keeping the dnsmasq tier

Extend the host's `dnsmasq` profile to allow the shield state tree.
Substitute your sandbox root for `STATE_ROOT` (default
`~/.local/share/terok/sandbox-live`):

```
owner STATE_ROOT/tasks/*/*/shield/dnsmasq.conf r,
owner STATE_ROOT/tasks/*/*/shield/dnsmasq.pid rwk,
owner STATE_ROOT/tasks/*/*/shield/dnsmasq.log rwk,
/usr/share/iproute2/* r,
```

Drop the rules into the profile's local include and reload:

- Debian/Ubuntu (`/etc/apparmor.d/usr.sbin.dnsmasq`): edit
  `/etc/apparmor.d/local/usr.sbin.dnsmasq`, then
  `sudo apparmor_parser -r -W /etc/apparmor.d/usr.sbin.dnsmasq`.
- `apparmor.d` / Arch (profile named `dnsmasq`): edit
  `/etc/apparmor.d/local/dnsmasq`, then
  `sudo apparmor_parser -r -W /etc/apparmor.d/dnsmasq`.

`sudo aa-status` should still show `dnsmasq` in enforce mode; re-run a
task and `dns.tier` in the shield state dir returns to `dnsmasq`.

> AppArmor mediates by pathname, so the addendum names your state root —
> regenerate it if you move the sandbox dir (`TEROK_*_DIR` /
> `XDG_DATA_HOME`).

## If you can't install the profile

The automatic `dig` fallback keeps you working unprivileged; no action
needed. shield does not bypass the profile (e.g. by running dnsmasq
unconfined), as that would override a policy the host administrator set.

## Not yet implemented

- **Installer / setup advertising** for the addendum above — it is
  currently a manual step. Generating it belongs to the orchestrator
  (terok), which owns the per-task directory layout.
- **Explicit DNS-tier pinning** — tier selection is automatic; there is
  no config knob to force or disable a tier yet.

[1]: https://github.com/roddhjav/apparmor.d
