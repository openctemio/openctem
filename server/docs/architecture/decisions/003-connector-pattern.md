# ADR-003: External Connector Pattern

## Status
Accepted. The unified framework that extends it (platform-direct and
sensor-relayed connectors) is proposed in
[RFC-049](../../rfcs/RFC-049-unified-connector-framework.md).

## Context
OpenCTEM pulls assets and findings from external systems: cloud providers and
infrastructure (AWS, GCP, Azure, Kubernetes, git hosts), scanners and
vulnerability managers (for example Tenable.sc), and finding sources such as
DefectDojo. The domain must not depend on any one of them.

## Decision
Use the **adapter pattern** with one interface per kind of source.

Asset-inventory connectors implement `connector.Connector`
(`internal/app/connector/connector.go`):

```go
type Connector interface {
    Provider() Provider                                   // "aws", "gcp", "azure", "kubernetes", "git-host"
    Validate(ctx context.Context, creds Credentials) error // "Test connection": one auth call
    Discover(ctx context.Context, tenantID shared.ID, creds Credentials) (*DiscoveryResult, error)
}
```

Finding sources are importers and converters that map a third-party format
onto the CTIS model: `internal/app/findingimport` (file imports, see
[finding-import.md](../finding-import.md)) and `internal/infra/importer/<provider>`
(for example `defectdojo`). A connector that must run inside the customer's
network, such as the Tenable.sc connector, runs in the sensor and reports
through the sensor protocol ([tenable-sc-connector.md](../tenable-sc-connector.md)).

Status: the asset-inventory interface is in the code; the provider
implementations (AWS, GCP, Azure, Kubernetes, git host) are **Planned**.

## Rationale
- **Decoupling**: the domain does not know about specific tools.
- **Extensibility**: a new source is one adapter.
- **Isolation**: a provider outage or SDK upgrade affects only its adapter.
- **Testability**: connectors are mocked in tests.
- **Consistency**: the same data model regardless of source.

## Consequences
- Each source needs a mapper to the domain (or CTIS) model.
- API differences stay in the adapter layer.
- Credentials are per tenant and encrypted at rest (`APP_ENCRYPTION_KEY`).
