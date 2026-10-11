### Behaviour change: the verified-domain requirement for platform sensors is a console setting, off by default

- New platform setting in Console > System > Platform scanning: "Require a
  verified domain before platform sensors scan a target". Default **off**:
  assets come from many sources, and the organization's scope entry is the
  authorization, so no scan, preflight or scope view is blocked with
  "Proof needed". On: jobs reach platform sensors only for targets at or under
  a verified domain of the organization, and intrusive (T2) probes need one
  on any sensor (RFC-054 §8.1). A public multi-tenant cloud should turn it on.
- Changing it needs a super admin, a fresh console authenticator code and a
  reason; it is written to the admin audit log at critical severity and the
  other platform administrators are emailed. An unreadable stored value
  counts as on.
- The scope gate, exclusions, the platform deny list, scan zones for private
  addresses and tier ceilings do not depend on it and stay in force.
- **Removed:** the environment variable `SCOPE_ACTIVE_PROOF` and its `all`
  mode. Startup refuses a set `SCOPE_ACTIVE_PROOF` with a hint; remove it and
  turn the setting on in the console when the install is a public cloud.
  Upgrading a self-service install that relied on the old `platform_sensors`
  default: turn the setting on after the upgrade.
