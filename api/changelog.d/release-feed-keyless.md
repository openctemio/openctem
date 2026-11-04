### Security: the release feed is signed keyless (Sigstore), with no signing key to hold

- The release feed is signed by the `release-feed` workflow with its GitHub OIDC identity (`cosign sign-blob`, certificate and transparency log entry) instead of an Ed25519 key kept in the `RELEASE_FEED_SIGNING_KEY` secret. There is no secret to set up, lose or steal.
- An instance verifies the feed offline, with the Sigstore trusted root embedded in the release (`CONTENT_SIGSTORE_TRUSTED_ROOT` may name a newer one), and accepts only the `release-feed.yml` workflow of `openctemio/openctem` on `main` or a release tag, from the GitHub Actions issuer.
- The `id-token` permission exists only in the workflow's sign job, which runs nothing but cosign; a publish job verifies the file as an instance would before uploading it.

### Removed: pinned release feed keys

- `releasefeed.PinnedKeys`, the `release-feed keygen` command and the release feed key of `scripts/signing/init-keys.sh` are gone. The published file has a new format (`openctem.io/release-bundle/v2`); instances of an earlier release cannot read it and keep the sensor and SDK versions built into their release until they upgrade.
