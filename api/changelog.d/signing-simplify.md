### Changed: the release feed is signed by one pinned online key

- The version-check release feed is signed directly by one online Ed25519 key whose public key is pinned in the binary (`releasefeed.PinnedKeys`, up to two entries for a rotation overlap); the offline root and the feed key set are gone. Rollback and sequence protection, the 45-day expiry, the link allowlist, https and the offline import are unchanged, and the check stays inert while no key is pinned. The release feed key signs only the feed and is never listed in the catalog key set.
- `cmd/release-feed`: `keyset` is removed, `build` no longer takes `-keyset`, `verify` takes `-key <public key hex>`. The migration drops the unused `version_check_state.keyset_version` column. The admin error code `no_root` is now `no_key`.
- The content catalog keeps root, key set and its own online key; its key set may be valid up to 365 days. The maximum key set validity is now per feed type (`feedsign.KeySetType.MaxValidity`): 365 days for the catalog, 180 days for the program feed and the vulnerability bundle (unchanged). `feedsign.MaxKeySetValidity` is removed.

### Added: signing key scripts

- `scripts/signing/init-keys.sh` creates the catalog root key, the release feed key and a separate catalog online key (private files, mode 0600), signs the catalog key set (listing the catalog online key only) and prints only public material and two `gh secret set` commands (`release-feed` and `content-catalog` environments); it refuses to overwrite keys. `scripts/signing/rotate-keyset.sh` re-signs the key set each year. See `docs/architecture/signing-keys.md`.
