# Testing Guide

## Test Structure

```
# Unit tests (inline)
pkg/domain/asset/entity_test.go
internal/app/asset_service_test.go

# Integration tests
tests/integration/asset_test.go

# E2E tests
tests/e2e/api_test.go

# Test fixtures
testdata/assets.json
testdata/golden/risk_score_output.json
```

## Run Tests

```bash
# All unit tests
make test
# or
go test ./internal/...

# With coverage
make test-coverage
# or
go test -coverprofile=coverage.out ./internal/...
go tool cover -html=coverage.out

# Integration tests (requires DB)
make test-integration
# or
go test -tags=integration ./tests/integration/...

# E2E tests
make test-e2e
# or
go test -tags=e2e ./tests/e2e/...
```

## Mocking

### Generate Mocks
```bash
make generate-mocks
# or
./scripts/generate-mocks.sh
```

Uses [mockgen](https://github.com/golang/mock):
```bash
mockgen -source=pkg/domain/asset/repository.go \
        -destination=internal/mocks/asset_repository.go
```

### Using Mocks
```go
func TestAssetService_Create(t *testing.T) {
    ctrl := gomock.NewController(t)
    defer ctrl.Finish()

    mockRepo := mocks.NewMockAssetRepository(ctrl)
    mockRepo.EXPECT().
        Create(gomock.Any(), gomock.Any()).
        Return(nil)

    service := app.NewAssetService(mockRepo)
    // ...
}
```

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

