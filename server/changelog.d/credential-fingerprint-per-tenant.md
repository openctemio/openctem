### Security: leaked-secret fingerprints are keyed per organization

- The fingerprint of a leaked credential's secret was keyed with one install-wide key, so the same password leaked for two organizations had the same fingerprint and a database reader could link them. It is now HMAC-SHA256 under an organization key derived with HKDF from `APP_ENCRYPTION_KEY` and the organization id. Dedup inside one organization is unchanged.
- Stored fingerprints are re-keyed on every start (idempotent, resumable, batched, recomputed from the sealed value; only the two fingerprint keys of `exposure_events.details` change, no schema migration). Rows whose value cannot be decrypted are left as they are and logged.
- **Upgrade note:** nothing to do. Rehearse with `go run ./cmd/encrypt-credentials -dry-run` on a restored backup; to roll back to an older build, stop the new servers and run `go run ./cmd/encrypt-credentials -revert-credential-fingerprints`.

### Added: organizations choose whether leaked secret values are kept

- New organization setting **Settings > Leaked credentials** (`/api/v1/organization/settings/credentials`, owners and administrators) and platform default **System > Leaked credentials** in the console (`/api/v1/admin/settings/leaked-secret-storage`, super admin with a fresh step-up and a reason). While the platform default is unset, values are kept on a self-managed install (as before) and not kept on a managed service (`MANAGED_SERVICE`).
- When off, an import keeps only the masked form, the credential type and the fingerprint; nothing can be revealed. Values already kept stay.
