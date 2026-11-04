### Added: extension point for things that are off unless granted

- The core asks one entitlement answer for granted extras (`Addon`, `RequireAddon` with 403 `ADDON_NOT_LICENSED` / `ADDON_LICENSE_EXPIRED`, and installation notices for banners). The Community build has no provider: nothing is granted, there are no notices, and no Community feature, limit or security control changes.
- RFC-145 is re-scoped to the grant seam and the guarantees every grant provider keeps (a grant only adds, fails closed for grants only, never touches sign-in, SSO, MFA, audit or security controls, keeps data, makes no outbound call). No migration, no licence code, no grant key and no new setting in this repository.
