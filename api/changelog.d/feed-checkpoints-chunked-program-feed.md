### Added: chunked program feed import with a resumable checkpoint

- The public program feed importer reads bundle format v2 (signed pointer, signed manifests, content-addressed chunks) through the sdk-go transfer layer when the source offers it: retries with back-off, Range resume, mirror fall-back, a verified chunk cache, and each chunk applied in its own transaction with a durable checkpoint, so a crash or a dropped connection resumes at the next chunk. The whole-bundle (v1) reader stays the fallback for this release. Every existing check is kept (pinned root, key-set version, sequence newer than applied, delta base, expiry, caps, per-record validation, local-only bundles only through the local path).
- New table `feed_checkpoints` (migration `feed_checkpoints`), platform-wide with no tenant data, backfilled from the applied sequences of `program_feed_state`.
- New optional settings: `PROGRAMFEED_URL`, `PROGRAMFEED_MIRRORS` (https only) and `FEED_CACHE_DIR`.
- The API now requires `github.com/openctemio/sdk-go`. **Dev note:** a local `sdk-go` checkout mounted at `/app/sdk-go` is used only when it builds with the API (sdk-go `main`); otherwise the go.mod pin is used.
