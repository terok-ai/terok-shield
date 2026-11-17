# Changelog

## v0.10.0 — A Man Alone

- **Breaking:** no profile applies by default. `default_profiles` is empty until
  `ShieldConfig` or `config.yml` names profiles; it used to be `dev-standard`, which stays
  under `resources/examples` as an example to name explicitly ([#448](https://github.com/terok-ai/terok-shield/pull/448)).
- **Breaking:** the bundle version is 20. Re-create a container that an older shield
  prepared; the hook refuses its bundle ([#485](https://github.com/terok-ai/terok-shield/pull/485)).
- `harvest` reads the audit log of a container and gives one entry for each refused target,
  with the tier that refused it (`blocked`, `security_deny` or `private_range`) and the
  remedies that the tier permits. It gives the same result with the shield up or down. An
  audit log that cannot be read is an error, not an empty harvest ([#485](https://github.com/terok-ai/terok-shield/pull/485)).
- `override <container> <target> --expires DATE --reason TEXT` opens a break-glass path
  through the security tier, also to a provider host that the vault relays, and `--off`
  revokes it. The kernel ends the override at its expiry, and the audit log records the
  reason. An override never opens the hard-deny floor or the host loopback ([#485](https://github.com/terok-ai/terok-shield/pull/485)).
- `bypass` shows, opens and closes the timed allow-all window. The window opens only while
  the shield is up ([#485](https://github.com/terok-ai/terok-shield/pull/485)).
- A live `allow` refuses a target that the security tier refuses: by name, by parent domain
  and by address. On a stopped container, `allow` records the target for the next start
  ([#485](https://github.com/terok-ai/terok-shield/pull/485)).
- A DNS tier without dnsmasq resolves names only at launch and at `up` and `down`. The
  shield names those pinned names at each of these points, because their grants break when
  an address rotates ([#485](https://github.com/terok-ai/terok-shield/pull/485)).
- `host.docker.internal` gets the forwarded host address, as `host.containers.internal`
  does. Podman no longer gives it an address that it detected, which could be a private LAN
  address ([#490](https://github.com/terok-ai/terok-shield/pull/490)).
- A `+localhost:PORT` grant in a profile reaches the ruleset. `prepare` and `run` launch a
  container that does not exist yet without `--state-dir`, and `preview --profiles` shows
  the ruleset that a launch would apply ([#473](https://github.com/terok-ai/terok-shield/pull/473)).
- Lowering the shield installs the accepting table, the mandatory denies and the overrides
  in one nftables transaction, and it no longer races live grants, revocations and denies
  ([#493](https://github.com/terok-ai/terok-shield/pull/493)).
- Python 3.15 is supported.

**Full Changelog**: https://github.com/terok-ai/terok-shield/compare/v0.9.0...v0.10.0

## v0.9.0 — At Your Service

- Own setup receipts and bind standalone global hooks to the setup interpreter.
- Resolve host tools from each launch's PATH, including NixOS; retain Podman 4.8 support.
- Remove per-task hook installation. Rerun setup and recreate old bundle containers.
- Serialize setup with the other packages and preserve command errors for missing host tools.

## What's Changed
* preserve host PATH in standalone hooks by @sliwowitz in https://github.com/terok-ai/terok-shield/pull/455
* host tool fixes in util by @sliwowitz in https://github.com/terok-ai/terok-shield/pull/456

**Full Changelog**: https://github.com/terok-ai/terok-shield/compare/v0.8.0...v0.9.0

## v0.8.0 — Past Prologue

## What's Changed
* feat!: tiered egress policy engine by @sliwowitz in https://github.com/terok-ai/terok-shield/pull/352
* perf(dns): parallel resolution, 2s per-lookup budget, shared host-level cache by @sliwowitz in https://github.com/terok-ai/terok-shield/pull/397
* feat: route logging through terok-util unified facility by @sliwowitz in https://github.com/terok-ai/terok-shield/pull/407
* feat(watch): Landlock-confine the reader daemons by @sliwowitz in https://github.com/terok-ai/terok-shield/pull/408
* Keep DNS working on the AppArmor dig and getent fallback by @sliwowitz in https://github.com/terok-ai/terok-shield/pull/429
* feat!: reserve 'bypass' for the timed window; DISENGAGED enforces nothing; a t10 override accepts a CIDR by @sliwowitz in https://github.com/terok-ai/terok-shield/pull/430
* feat(dns)!: the lookup tier accepts drill alongside dig by @sliwowitz in https://github.com/terok-ai/terok-shield/pull/435
* feat(dns): tiers that say what they provide, and the dnsmasq binary to run by @sliwowitz in https://github.com/terok-ai/terok-shield/pull/444

**Full Changelog**: https://github.com/terok-ai/terok-shield/compare/v0.7.2...v0.8.0

## v0.7.2 — The Celestial Temple

Test, build, and docs infrastructure changes only.

**Full Changelog**: https://github.com/terok-ai/terok-shield/compare/v0.7.1...v0.7.2

## v0.7.1 — Emissary, Part II

Added PyPI version badge and logo, https://github.com/terok-ai/terok-shield/pull/347, homepage URL, terok cross-link, and docs https://github.com/terok-ai/terok-shield/pull/348, and updated dependencies.

**Full Changelog**: https://github.com/terok-ai/terok-shield/compare/v0.7.0...v0.7.1

## v0.7.0 — The Emissary

**First public PyPi release**

## What's Changed

* move command registry to top-level terok_shield.commands, https://github.com/terok-ai/terok-shield/pull/309
* bundle krun_guest egress profile, https://github.com/terok-ai/terok-shield/pull/318
* runtime-aware dnsmasq bind for krun guests, https://github.com/terok-ai/terok-shield/pull/327
* split podman_info into info/hooks_dir/network submodules (W5.D.2), https://github.com/terok-ai/terok-shield/pull/334
* fall back to dig when AppArmor confines dnsmasq, https://github.com/terok-ai/terok-shield/pull/341
* per-container shield state; single user-owned install layout, https://github.com/terok-ai/terok-shield/pull/342


**Full Changelog**: https://github.com/terok-ai/terok-shield/compare/v0.6.41...v0.7.0
