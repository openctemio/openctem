# ADR-003: External Connector Pattern

## Status
Accepted

## Context
Need to integrate with multiple security tools (Wiz, Tenable, Snyk, CrowdStrike).

## Decision
Use **Adapter Pattern** with common interface:

```go
// internal/infra/connector/interface.go
type Connector interface {
    Name() string
    Fetch(ctx context.Context) ([]domain.Asset, []domain.Exposure, error)
    Sync(ctx context.Context) error
}
```

Each connector implements this interface:
```
connector/
├── interface.go
├── wiz/
├── tenable/
├── snyk/
└── crowdstrike/
```

## Rationale
- **Decoupling**: Domain doesn't know about specific tools
- **Extensibility**: Easy to add new connectors
- **Testability**: Mock connectors for testing
- **Consistency**: Same data model regardless of source

## Consequences
- Need mappers for each connector
- Handle API differences in adapter layer
- Common error handling pattern
