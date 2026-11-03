### Added: licence store and the grant answer for granted extras

- Migration 20261103090231 adds `subscription_licenses` (append-only history of the installation's signed licences) and `subscription_state` (installation id, time and key-set high-water marks, revocations). Both are installation-wide with no organization data; the migration creates the installation id.
- `internal/app/subscription` re-verifies every stored licence with the roots compiled into the build on each load, picks the licence in force (renewals take over at their start with no gap), and keeps the state fresh on every replica. `entitlement.Service.Addon` and `RequireAddon` (codes `ADDON_NOT_LICENSED`, `ADDON_LICENSE_EXPIRED`) are the one entry point for gates on granted extras. RFC-145.
- No gate calls it yet and no Community feature, limit, sign-in, SSO, MFA or audit path depends on it: every installation behaves as before.
