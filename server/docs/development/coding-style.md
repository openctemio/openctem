# Coding Style Guide

## General

- Follow [Effective Go](https://go.dev/doc/effective_go)
- Use `gofmt` / `goimports` for formatting
- Run `golangci-lint` before commit

## Naming

| Type | Convention | Example |
|------|------------|---------|
| Package | lowercase, single word | `asset`, `user` |
| Interface | -er suffix or descriptive | `Repository`, `Handler` |
| Struct | PascalCase | `AssetService` |
| Function | PascalCase (exported) | `NewAssetService` |
| Variable | camelCase | `assetRepo` |
| Constant | PascalCase or ALL_CAPS | `MaxRetries` |

## Project Conventions

### Domain Layer
- No external dependencies
- Pure Go structs and interfaces

### App Layer
- Services end with `Service`
- Constructor pattern: `NewXxxService(deps)`

### Infra Layer
- Repo implements domain interface
- Handler handles HTTP concerns only

## Error Handling

```go
// Good
if err != nil {
    return fmt.Errorf("failed to create asset: %w", err)
}

// Bad
if err != nil {
    return err
}
```

## Comments

```go
// CreateAsset creates a new asset with the given parameters.
// Returns ErrAssetAlreadyExists if asset with same symbol exists.
func (s *AssetService) CreateAsset(...) error {
```
