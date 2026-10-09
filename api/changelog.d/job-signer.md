### Security: jobs for sensors can be signed by a separate signer

- New `openctem-signer` process (in the API image, `/app/openctem-signer`): an
  Ed25519 key of its own (never derived from an API secret, refused if group
  or others can read it), a Unix socket only, a per-sensor sequence number
  stored before each signature, and a hash-chained signing log of every
  signature and refusal. It checks each job statement (ids, payload digest,
  targets, lease epoch, clock skew, at most one hour of validity, rate
  ceilings) before it signs.
- With `SIGNER_SOCKET` set on the API, every command a claim hands a sensor
  (v2 claim-N, v2 claim, v3 `ClaimCommands`) carries `signed_job`, a DSSE
  envelope binding the organization, the sensor, the command, the lease epoch
  and the exact payload bytes. A command the signer does not sign is not
  handed out. Hello lists the `signed_jobs` feature and the signer's key.
  Format: `docs/architecture/job-signing.md`.
- Off by default: without `SIGNER_SOCKET` nothing changes. No migration.
- **Upgrade note:** to turn it on, create the key with `openctem-signer keygen`
  and start the stack with `deploy/docker-compose.job-signer.yml` (steps in
  the file). Sensors do not verify the envelope yet; that comes with the next
  sdk-go release.
