### Behaviour change: seeds are scope entries; only scope entries authorize scans

- Root-domain seeds are folded into scope entries (migration `001245`,
  research/53 SC1). Each seed became the permanent entry `*.<domain>`
  (`origin: seed_migration`, `t1`, in effect), unless an active permanent
  wildcard entry already covered it; nothing that was allowed before is
  refused after. `GET/POST/PATCH/DELETE /api/v1/easm/seeds` are removed: add
  a root domain as a scope entry (`POST /api/v1/scope/targets` with
  `*.example.com`).
- Scope entries gain `discovery` (default on): names under a permanent domain
  entry are discovered (Certificate Transparency, DNS checks) and join the
  inventory. One-off and non-domain entries never discover. Turning discovery
  on needs `attack_surface:scope:approve` and step-up, and notifies the
  administrators.
- A verified domain is proof of control only (SC2): it marks the entries at or
  under it as verified and is what platform sensors and intrusive checks
  require, but it no longer authorizes a scan by itself. Every `easm`
  verified domain that no entry covered became an entry `*.<domain>`, so
  nothing is lost; a domain verified for SSO sign-in got no entry.
- Web: the Seeds tab of Scoping › Scope is replaced by **Domain proof**
  (`/scope?tab=proof`). The old `/settings/integrations/verified-domains`
  redirect is removed (no redirects for moved pages).
- **Upgrade note:** API clients that used `/api/v1/easm/seeds` create scope
  entries instead. No action is needed for existing seeds.
