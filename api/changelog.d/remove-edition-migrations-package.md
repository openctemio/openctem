### Removed: the unused edition-aware migration loader

- `api/pkg/migrations` (an edition map of pre-baseline migration numbers,
  a loader and a runner) had no importer. Migrations run with
  golang-migrate from `api/migrations` from baseline 001146 on; nothing
  changes at runtime.
