### Changed: the release feed is signed by one pinned online key

- The version-check release feed is signed directly by one online Ed25519 key whose public key is pinned in the binary (`releasefeed.PinnedKeys`, up to two entries for a rotation overlap); the offline root and the feed key set are gone. Rollback and sequence protection, the 45-day expiry, the link allowlist, https and the offline import are unchanged, and the check stays inert while no key is pinned. The feed keeps its own payload type, so the same online key can also sign catalog content.
- `cmd/release-feed`: `keyset` is removed, `build` no longer takes `-keyset`, `verify` takes `-key <public key hex>`. The migration drops the unused `version_check_state.keyset_version` column. The admin error code `no_root` is now `no_key`.
- The content catalog keeps root, key set and online key; the maximum key set validity is now 365 days (this ceiling is shared by the other feeds that use the feed key set format).

### Added: signing key scripts

- `scripts/signing/init-keys.sh` creates the catalog root key and the online key (private files, mode 0600), signs the catalog key set and prints only public material and the `gh secret set` command; it refuses to overwrite keys. `scripts/signing/rotate-keyset.sh` re-signs the key set each year. See `docs/architecture/signing-keys.md`.
