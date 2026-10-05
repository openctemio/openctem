# Rotating APP_ENCRYPTION_KEY

`APP_ENCRYPTION_KEY` is used in two ways, and a rotation has to handle both:

1. **It encrypts stored secrets** (AES-256-GCM). `cmd/rekey` re-encrypts all
   of them with the new key in one transaction.
2. **It keys hashes.**
   - The leaked-credential fingerprint and the scanner-template signature can
     be recomputed from data the database holds, so `cmd/rekey` recomputes
     them too.
   - The hashes of `oct_` API keys, SCIM tokens and sensor keys are one-way
     and cannot be recomputed without the token. The server keeps verifying
     them with the old key while it is listed in
     `APP_ENCRYPTION_KEY_PREVIOUS`, and re-hashes each one with the new key
     the next time it is used.

## What is covered

The list lives in `internal/app/rekey/rekey.go`. It was enumerated from every
`EncryptString`, secret-store and keyed-HMAC call site in the code.

| Location | What it is |
|---|---|
| `integrations.credentials_encrypted` | integration credentials (Jira, SCM, notification channels, ...) |
| `integrations.metadata.webhook_secret_encrypted` | Jira webhook secret |
| `integration_scm_extensions.webhook_secret_encrypted` | SCM webhook secret |
| `tenant_identity_providers.client_secret_encrypted` | organization SSO client secret |
| `platform_identity_provider.client_secret_encrypted` | platform admin IdP client secret |
| `admin_idp_login_states.code_verifier_encrypted` | in-flight admin IdP logins |
| `admin_credentials.mfa_secret_encrypted` | admin console TOTP secret |
| `user_mfa.secret_encrypted`, `pending_secret_encrypted` | user TOTP secrets |
| `settings.value_json.access_key`, `secret_key` (`storage_config`) | tenant file-storage credentials |
| `tenants.settings.ai.api_key` (`enc:v1:`) | BYOK LLM key |
| `exposure_events.details.secret_value_enc` (+ `secret_fingerprint`) | leaked-credential secret |
| `credentials.encrypted_data` | secret store (template sources and other stored credentials) |
| `scanner_templates.signature_hash` | template signature (recomputed) |

Each value gets exactly one of these outcomes:

- **Re-encrypted**: the old key opens it, and it is rewritten under the new key.
- **Already new**: the new key already opens it. It is left alone, so the tool
  can safely be run again.
- **Not ciphertext**: the value is too short to be AES-GCM output, or is not
  base64. No key opens it, the server's included. It is listed and left
  unchanged.
- **Failed**: it looks like ciphertext, but neither key opens it. Any failure
  rolls the whole run back.

The run also sweeps every text, bytea and jsonb column for values the old key
still opens. If it finds any, the column is a location this list does not
cover, and the run fails and nothing is committed.

Plaintext values left over from before encryption was configured count as
failures. Run `cmd/encrypt-credentials` first if there are any.

Not re-keyed: `findings.type_details.secret.fingerprint`, the keyed fingerprint
of a secret finding. Its key is derived from `APP_ENCRYPTION_KEY`, and the
secret itself is never stored, so it cannot be recomputed. After a rotation a
secret seen again gets a fingerprint under the new key; findings fingerprinted
before the rotation keep the old value, and the two do not compare equal.

## Runbook

The keys are passed through the environment only. Never put them in
arguments, and never echo them. `rekey` reads the server's `DB_*` variables
when `DATABASE_URL` is unset, so it runs unchanged inside the API container.

1. **Back up the database** (`pg_dump -Fc`), and keep the old key somewhere
   safe until step 7.
2. **Generate the new key**: `openssl rand -hex 32`. Store it the way the
   other secrets are stored, for example a mode-600 `.env`.
3. **Build the tool** from a checkout that contains it:
   `cd api && CGO_ENABLED=0 go build -o /tmp/rekey ./cmd/rekey`. Then copy it
   into the API container: `docker cp /tmp/rekey <api-container>:/tmp/rekey`.
4. **Dry run.** It re-encrypts inside a transaction, prints the counts, and
   rolls back:

   ```sh
   export REKEY_OLD_KEY=...  REKEY_NEW_KEY=...     # in your shell, not in history
   docker exec -e REKEY_OLD_KEY -e REKEY_NEW_KEY <api-container> /tmp/rekey
   ```

   Check that every location shows the expected count and that `FAILED` and
   `UNLISTED` are empty. Exit status 0 means it would commit.
5. **Apply**: the same command with `-apply`.
6. **Switch the server.** Set `APP_ENCRYPTION_KEY=<new>` and
   `APP_ENCRYPTION_KEY_PREVIOUS=<old>`, then recreate the API container.
   - With the previous key listed, values the old key encrypted stay
     readable, and old API keys, SCIM tokens and sensor keys keep
     authenticating.
   - The server logs a warning while a previous key is configured.
   - Verify each item: integrations test-connect, admin console TOTP sign-in,
     user 2FA, SSO sign-in, stored credentials (template-source sync),
     leaked-credential reveal, a sensor heartbeat and an `oct_` API key.
7. **Let the tokens move over, then drop the old key.**
   - An API key, SCIM token or sensor key that authenticates through the
     previous key is **re-hashed with the current key on that request**.
     The write is a compare-and-swap on the old hash, so a concurrent
     regenerate or revoke wins. Each hash also records which key made it
     (`key_pepper_id`, migration 000264).
   - Sensors heartbeat constantly, so they move within seconds. API keys and
     SCIM tokens move on their next use.
   - Watch the count. The server logs it at start-up while a previous key is
     set, and `rekey -status` prints it any time (exit 3 while above zero):

     ```sh
     docker exec <api-container> /tmp/rekey -status
     ```

   - When the total is 0, remove `APP_ENCRYPTION_KEY_PREVIOUS` and recreate
     the API.
   - Tokens that are never used again cannot be moved: a hash is one-way, and
     re-hashing needs the token itself. Revoke them, or re-issue them to their
     owners (`rekey -status` counts only tokens that can still authenticate).
   - Until the previous key is removed, anyone holding both the old key and a
     database copy can brute-force the not-yet-moved hashes offline.

### Without a grace period

`APP_ENCRYPTION_KEY_PREVIOUS` is optional. Nothing requires it: without it,
the server simply knows only the new key. To switch with no grace period
(the path taken on the live deployment, 2026-10-02):

1. Run steps 1-6 as above, with the old key in `APP_ENCRYPTION_KEY_PREVIOUS`
   only for the next step.
2. Re-issue every sensor key you want to keep:
   - a sensor's own renewal (`POST /api/v2/sensor/keys`, which it can still
     reach because the previous key verifies it), or
   - an administrator's regenerate-key, followed by installing the new key on
     the sensor.

   Either way, the new key is hashed with the new pepper.
3. Remove `APP_ENCRYPTION_KEY_PREVIOUS` and recreate the API.
4. Every `oct_` API key and SCIM token issued under the old key, and every
   sensor key not re-issued in step 2, stops authenticating. Re-issue the ones
   still needed. Run `rekey -status` before step 3 to see what will be left
   behind.

The server may also run step 6 before step 5. Because it reads both keys,
nothing breaks while the rows are still under the old key. Run `rekey` before
removing the previous key.

`APP_ENCRYPTION_KEY_PREVIOUS` takes a comma-separated list. Each entry is
detected by length like the main key (64 hex, 44 base64, 32 raw). An entry
equal to `APP_ENCRYPTION_KEY` is refused at start-up.

Transient state that is not re-encrypted: SSO/OIDC `state` parameters are
encrypted with the key while a sign-in is in flight. A sign-in that started
before the restart in step 6 and finishes after it still works while the
previous key is listed.
