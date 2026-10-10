### Added: modules per plan, with grants for trials and add-ons

- A plan now decides which modules its organizations may use: Console > System > Plans >
  Plan modules (super admin, fresh authenticator code). Until it is saved every plan
  includes every module, so nothing changes on upgrade.
- One organization can be granted a module beyond its plan (a trial with an expiry, an
  add-on) or denied one: Console > Organizations > Plan > Modules (ops admin and up; granting,
  denying and removing each need a reason and a fresh authenticator code; admin audit log). Changes, and a change of plan, apply at once on every API
  replica.
- An organization cannot switch on a module its plan does not include; Settings > Modules
  shows it as "Not in your plan". A page of such a module says so, and
  `MODULE_NOT_ENABLED` carries reason `not_entitled`. If the entitlement cannot be read, the
  gate answers 503 rather than opening (fail-closed).
- Migration 001781 adds `tenant_module_grants`.

### Removed: organization-chosen product bundles

- `GET/POST /api/v1/tenants/{tenant}/settings/modules/bundles` and the Products card are
  removed: packaging is the plan's. Onboarding offers one optional starting set (a preset,
  applied once). No organization had a bundle subscription; migration 001781 clears the
  setting.
