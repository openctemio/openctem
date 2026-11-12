### Security: the CI trust preview's unverified iat read is reviewed and guarded

- `pkg/oidc` reads a token's `iat` without verifying it only to pick the clock for the CI trust configuration preview (`IgnoreTimes`); the signature, issuer and audience are verified right after. The line now carries a reviewed security-gate waiver, and a test fails if any other code sets `IgnoreTimes` without the same review. No behaviour change.
