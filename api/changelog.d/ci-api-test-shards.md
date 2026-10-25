### Changed: API test shards split the slow packages by test

- `Tests (Postgres + Redis)` and `Tests (least-privilege DB role)` split `tests/unit`, `tests/integration`, `internal/infra/http/routes` and `internal/infra/postgres` by top-level test name over every shard; the other packages go whole to one shard. Full tier 8 shards (was 4 + 4), fast tier 6 (was 2 + 2), least-privilege 6 (was 3 + 3). The slowest shard was `tests/integration` alone at about 20 minutes.
