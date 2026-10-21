### Added: `refingerprint -reset-mask-secret-fingerprints` clears secret fingerprints that were derived from a mask

- One-off operator command for deployments that ingested secret findings before the rotation-group fix: it clears the secret fingerprints created before `-before` (the deploy time of the fix), removes stored `RE…ED` previews, and re-derives the remediation keys of the changed findings, so unrelated secrets leave the shared rotation group. A dry run (the default) and the output are counts per tenant only, including the rotation tasks that group several affected findings, for review.
- See "Secret fingerprints derived from a mask" in the encryption key rotation guide.
