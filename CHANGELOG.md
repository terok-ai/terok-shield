# Changelog
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

