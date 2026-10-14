### Security: a secret finding is keyed on the CI job's keyed hash of the raw secret

- The CI exchange hands the job `secret_key`, derived per organization and repository. The job sends `HMAC-SHA256(secret_key, raw secret)` as the CTIS partial fingerprint `secretHMAC/v1`; the raw value never leaves the job. The platform keys the secret on it (re-keyed with its server secret), so two different secrets with the same masked value are two findings, and a change of masking no longer forks a finding. A finding keyed on its masked value moves to the new key on its next sighting, keeping its triage.
- A former key is adopted only from the finding still stored under it, never through an alias, so a key one finding gave up cannot pull it onto another (applies to every recipe).
