### Added: offline verifier for signed licence files

- `pkg/licensekey` verifies a self-managed installation's licence file offline (two Ed25519 DSSE envelopes: a key set signed by a root compiled into the build, and the claims signed by a key of that set) and computes its state (`not_yet_valid`, `active`, `expiring`, `grace`, `expired`) from an effective time that a clock wound back cannot lower. RFC-145.
- A licence only adds grant keys from the new registry in `pkg/domain/limits/grants.go` (`asset_collector`, `ai_worker`); it can never name a limit, a Community feature, sign-in, SSO, MFA or audit.
- Nothing calls the verifier yet and the build embeds no root, so every installation keeps running as before.
