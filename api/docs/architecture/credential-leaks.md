# Credential leaks

Leaked credentials (an e-mail or username with the password, token or key that
leaked) are `credential_leaked` exposure events. They are imported by JSON or
CSV ([API](../api/credential-import.md)) or created by the secret-scanning
bridge ([secret scanning](secret-scanning.md)), and listed on the
**Credentials** page.

Status: shipped (Community). This page covers how the leaked secret is
protected; import, dedup and lifecycle are in the API document.

## What is stored about the secret

| Field (`exposure_events.details`) | What | Returned by reads |
|---|---|---|
| `secret_masked` | `********`, or a 4-character vendor prefix for long API keys and tokens | yes |
| `secret_fingerprint` | HMAC-SHA256 (first 128 bits, hex) under the organization's fingerprint key | yes |
| `secret_fingerprint_version` | `2`: the per-organization recipe | yes |
| `secret_value_enc`, `secret_enc_scheme` | the value, AES-256-GCM under `APP_ENCRYPTION_KEY`, **only when the organization keeps values** | never (only the audited reveal) |
| `credential_type` | password, api_key, ... | yes |

The plaintext is never stored, logged or returned by a list or detail read.
`POST /api/v1/credentials/{id}/reveal` decrypts it for a holder of
`findings:credentials:reveal` and writes an audit event first.

## Per-organization fingerprint

The fingerprint key of organization `T` is

```
HKDF-SHA256(secret = APP_ENCRYPTION_KEY string,
            salt   = "openctem:credential-fingerprint:v2:",
            info   = "openctem:credential-fingerprint:v2:" || T)
```

(`pkg/domain/credential/secret.go`, `SecretProtector.Fingerprint`). The same
secret leaked twice in one organization has one fingerprint, so the
organization can see a reused or re-shared password. The same secret in two
organizations has two unrelated fingerprints: a database reader, an insider or
a backup cannot tell that two organizations share a leaked password. The key
material is never used directly as an HMAC key, and no fingerprint is written
without an organization.

### Re-key of stored fingerprints

Builds before this keyed every fingerprint with one install-wide key. On
every start the server, after sealing any plaintext rows, runs
`postgres.RekeyLeakedCredentialFingerprints`:

- it selects rows with a sealed value and a fingerprint not marked version 2,
  in batches of 200 ordered by id, each batch its own transaction with the rows
  locked `FOR UPDATE`;
- it decrypts the value, recomputes the organization's fingerprint and sets
  only `secret_fingerprint` and `secret_fingerprint_version` (the sealed value
  and every key are untouched), with the `UPDATE` pinned to the row's tenant;
- a row whose value cannot be decrypted (wrong key) is left as it is, counted
  as `unrecomputable` and logged;
- it is idempotent (a re-keyed row is no longer selected) and resumable (an
  interrupted run continues on the next start); replicas may run it at the
  same time.

Rehearse on a restored backup with
`go run ./cmd/encrypt-credentials -dry-run` (counts the rows to re-key). To
roll back to an older build, stop the new servers and run
`go run ./cmd/encrypt-credentials -revert-credential-fingerprints`, which puts
back the install-wide fingerprint computed from each sealed value. No schema
migration is involved.

`cmd/rekey` (rotation of `APP_ENCRYPTION_KEY`) recomputes the fingerprint
under the new key in the per-organization recipe.

## Keeping the value: an organization setting

Whether the value is kept is decided per organization:

| Layer | Where | Who |
|---|---|---|
| Organization | `tenants.settings.credentials.store_secret_values` (true, false, or absent), **Settings > Leaked credentials**, `GET/PUT /api/v1/organization/settings/credentials` | owners and administrators; audited high (`tenant.credential_settings_updated`) |
| Platform default | `platform_settings` key `credentials.leaked_secret_storage`, console **System > Leaked credentials**, `GET/PUT /api/v1/admin/settings/leaked-secret-storage` | any administrator reads; a super admin with a fresh step-up and a reason changes it; audited critical, every administrator is told |
| Code default | while nothing is stored: kept on a self-managed install, not kept on a managed service (`MANAGED_SERVICE`) | – |

The organization's own choice wins; absent, the platform default applies. When
the value is not kept, an import stores only the mask, the type and the
fingerprint: nothing is revealable (`has_secret` false, reveal answers 404).
A re-import of a credential whose old value was kept removes that ciphertext
when the new value is not kept. An unreadable setting keeps nothing (fail
closed). The decision is read once per import.

The setting applies to new writes (credential import and the generic exposure
create and ingest endpoints). Values kept before the setting was turned off
stay until the credential is deleted; the start-up sealing of legacy plaintext
rows encrypts them as they are.

## Threat model

- **Cross-tenant correlation** (database reader, insider, backup): fingerprints
  are keyed per organization; the re-key removes install-wide fingerprints.
- **Offline guessing of a fingerprint**: needs `APP_ENCRYPTION_KEY`.
- **Exposure of stored values** (SaaS operator, breach of the database plus
  key): an organization or the platform default can keep no value at all.
- **A member widening storage**: only owners and administrators change the
  organization setting; only a super admin changes the platform default.
- **Tenant isolation**: the organization comes from the authenticated
  principal, never the request body; every update is pinned to `tenant_id`.

## Key files

- `pkg/domain/credential/secret.go`: protector, fingerprint recipes, re-key outcomes
- `internal/infra/postgres/credential_fingerprint_rekey.go`: start-up re-key and reversal
- `internal/app/leakedsecretpolicy/`: platform default and per-organization resolver
- `internal/app/integration/credential_import.go`, `internal/app/exposure/service.go`: write paths
- `internal/infra/http/handler/tenant_credential_settings.go`, `admin_platform_settings_handler.go`: routes
- `web/src/app/(dashboard)/settings/leaked-credentials`, `web/console/src/app/(console)/system/leaked-credentials`: UI
