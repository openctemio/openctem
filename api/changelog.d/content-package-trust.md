### Security: content package signatures, signed index and revocation list

- `pkg/contentpkg` verifies offline bundles of content packages (RFC-099): a catalog key set signed by an offline
  root pinned in the release, a catalog countersignature per package version, the publisher's keyless Sigstore
  signature over the artifact (checked offline against the bundled Sigstore trusted root, with the build identity
  and issuer matched exactly), a signed index with a sequence (no rollback) and an expiry (no freeze), and a
  signed revocation list (by package, version or digest) that works without network access.
- Unsigned, tampered, expired, rolled-back and revoked content is refused; there is no switch to accept it.
- Adds the `github.com/sigstore/sigstore-go` dependency. No behaviour change yet: the catalog that uses it follows.
