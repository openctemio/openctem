# Testing Guide

## Test Structure

```
# Unit tests (inline)
internal/domain/asset/entity_test.go
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
mockgen -source=internal/domain/asset/repository.go \
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

## Integration Test Setup

```go
// tests/integration/testutil/database.go
func SetupTestDB(t *testing.T) *sql.DB {
    db, err := sql.Open("postgres", os.Getenv("TEST_DATABASE_URL"))
    require.NoError(t, err)

    t.Cleanup(func() {
        db.Exec("TRUNCATE assets, exposures CASCADE")
        db.Close()
    })

    return db
}
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

Tests run automatically on PR:
```yaml
# .github/workflows/ci.yml
- name: Run Tests
  run: make test

- name: Run Integration Tests
  run: make test-integration
  env:
    TEST_DATABASE_URL: ${{ secrets.TEST_DATABASE_URL }}
```
