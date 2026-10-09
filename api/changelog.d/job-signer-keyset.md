### Security: signer keys can be rotated and revoked through a key set signed by an offline root

- An installation can now keep an **offline root key** that never touches
  the platform host: `openctem-signer root keygen -out root.key` creates it
  and prints its key id. Offline, `openctem-signer keyset sign -root root.key
  -version N -days D -key <online public key> [-key ...] -out keyset.json`
  signs a **key set**: the online signer keys sensors may accept, a version
  that only goes up, and an expiry at most 30 days out.
  `openctem-signer keyset show [-root <keyid>] keyset.json` checks one.
- The signer serves the key set given in `SIGNER_KEYSET_FILE` at
  `GET /v1/keyset` (read at start and on `SIGHUP`). It refuses a key set
  that is not signed by its root, has expired, does not list its own key,
  or is older than the one it serves, and warns 7 days before expiry.
- The API passes the key set on in hello (`signed_jobs.keyset`) and a new
  key set changes the doorbell's `config_version`, so sensors pick it up
  without a restart. The API never holds the root key.
- Sensors that pin the root (`SENSOR_JOB_SIGNING_ROOT`, or at pairing with
  the next sdk-go release) accept job signatures only from keys in the
  current key set: rotating or revoking a signer key no longer means pairing
  every sensor again. Format and ceremony:
  `docs/architecture/job-signing.md` ("Key sets and the offline root").
- **Upgrade note:** optional and off by default; nothing changes without
  `SIGNER_KEYSET_FILE`. Once sensors pin a root, a key set must always be
  deployed and renewed before its `not_after`: an expired key set makes
  those sensors refuse every job (fail closed). No migration.
