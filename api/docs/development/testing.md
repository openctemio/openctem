# Testing Guide

## Test Structure

```
pkg/domain/<context>/*_test.go       # domain unit tests, next to the code
internal/app/<context>/*_test.go     # service tests, next to the code
internal/infra/**/*_db_test.go       # repository and route tests against PostgreSQL
tests/unit/                          # cross-cutting unit tests (route authz coverage,
                                     # permission catalog sync, scope classification, ...)
tests/integration/                   # integration tests (PostgreSQL, Redis)
```

## Run Tests

```bash
make test           # everything; DB-backed tests skip unless TEST_DATABASE_URL is set
make test-db TEST_DATABASE_URL=...   # everything against a *_test database; nothing skips
make test-coverage  # with a coverage report
make test-load      # load tests for the platform queue

go test ./internal/app/scan/...       # one package
go test -run TestScopeEntry ./tests/unit/
```

Run Go from `api/` with `GOWORK=off` (CI does the same).

## Mocking

Tests mostly use small hand-written fakes that implement the repository
interfaces in `pkg/domain/<context>/repository.go`. Mocks generated with
mockgen are produced by `make generate` (`go generate ./...`).

## DB-backed tests

DB-backed tests get their connection string from `internal/testdb`, never from
`os.Getenv("DATABASE_URL")` directly: `DATABASE_URL` is also what the running
API uses, and the tests write and delete rows.

```go
dsn := testdb.URL()
if dsn == "" {
    t.Skip("DATABASE_URL not set; skipping DB-backed test")
}
db, err := sql.Open("postgres", dsn)
if err != nil {
    t.Fatal(err)
}
if err := db.Ping(); err != nil {
    testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
}
```

| `DATABASE_URL` | `OPENCTEM_TEST_DB_REQUIRED` | Result |
|---|---|---|
| unset | unset | DB-backed tests skip (plain unit run, `make test`) |
| unset | `1` | panic: the DB tests were asked for but have no database |
| names a database ending in `_test` or `_compat` | any | DB-backed tests run; with `1`, `testdb.Skipf` and `PrivateDatabase` fail instead of skipping |
| names any other database (e.g. the live `openctem`) | any | panic with the reason; the tests never get the URL |

`OPENCTEM_TEST_DB_ALLOW=<name>` accepts one exactly named database that does
not follow the naming rule. Tests that reason about a whole table use
`testdb.PrivateDatabase`, and tests that run DDL use `testdb.LockForDDL`.

Locally, against a scratch database:

```bash
docker run -d --name pg-test -p 127.0.0.1:55432:5432 \
  -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=app_test postgres:17-alpine
migrate -path migrations -database "postgres://postgres@localhost:55432/app_test?sslmode=disable" up
make test-db TEST_DATABASE_URL="postgres://postgres@localhost:55432/app_test?sslmode=disable"
```

## Golden Files

For complex output validation:
```go
func TestRiskCalculator(t *testing.T) {
    result := calculator.Calculate(input)

    golden := filepath.Join("testdata", "golden", "risk_score_output.json")
    if *update {
        os.WriteFile(golden, result, 0644)
    }

    expected, _ := os.ReadFile(golden)
    assert.JSONEq(t, string(expected), string(result))
}
```

## CI Testing

API CI's `Tests (Postgres + Redis)` job runs the whole suite against Postgres
and Redis service containers on every PR that touches `api/`, in the merge
queue and on pushes, with `OPENCTEM_TEST_DB_REQUIRED=1`. See
[ci-cd.md](./ci-cd.md#what-the-api-jobs-check).

