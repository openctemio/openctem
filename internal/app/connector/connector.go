// Package connector defines the common contract for cloud / infra
// asset-inventory connectors (AWS, GCP, Azure, Kubernetes, git-host).
//
// Q1/WS-A (invariant F1): the product claims to support discovering
// assets from cloud providers. This package is the seam — providers
// implement Connector; the discovery pipeline consumes them uniformly.
//
// Only the framework + the AWS scaffold land in this PR. Each
// provider-specific SDK wiring is its own follow-up (#339 GCP,
// #340 Azure, #349 K8s, #350 git-host). That way a provider outage or
// SDK upgrade affects only one adapter, not the inventory pipeline.
package connector

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// Provider is the short identifier for a connector. Value is used as
// a metric label and in the `assets.discovery_source` column.
type Provider string

const (
	ProviderAWS    Provider = "aws"
	ProviderGCP    Provider = "gcp"
	ProviderAzure  Provider = "azure"
	ProviderK8s    Provider = "kubernetes"
	ProviderGit    Provider = "git-host"
)

// Credentials is the tenant-supplied material a connector needs to
// enumerate assets. Providers pick the fields they understand; the
// orchestrator does not interpret any of them.
//
// All credential fields are treated as secrets — the caller MUST
// pass values decrypted via the platform encryptor, and the framework
// MUST NOT log them. Secret handling is the provider's responsibility
// once it receives this struct; leakage via provider SDK debug
// logging is the most common gotcha and individual connectors are
// expected to redact.
type Credentials struct {
	// AWS
	RoleARN    string
	ExternalID string
	Region     string

	// GCP
	ServiceAccountJSON string
	ProjectID          string

	// Azure
	TenantID       string
	ClientID       string
	ClientSecret   string
	SubscriptionID string

	// Kubernetes / git-host: provider-specific opaque tokens.
	Token     string
	APIURL    string
	Namespace string
}

// DiscoveredAsset is one asset produced by a connector. It is the
// connector's pre-persistence record — the ingest pipeline resolves
// it to an existing asset (dedup) or creates a new row.
type DiscoveredAsset struct {
	// ExternalID is the provider-native ID (EC2 instance id,
	// GCP resource name, k8s UID, etc). Used as the dedup key
	// alongside tenant + provider.
	ExternalID string
	Name       string
	Type       asset.AssetType
	// Properties carry everything provider-specific. Keys use
	// snake_case per the product's JSONB convention.
	Properties map[string]any
	// Tags from the provider (AWS tags, GCP labels, k8s labels).
	// Kept as a map so tag sources stay structured.
	Tags map[string]string
	// ObservedAt is the wall-clock time the connector read the
	// record. Used to compute inventory freshness.
	ObservedAt time.Time
}

// DiscoveryResult is returned by a single enumeration pass.
type DiscoveryResult struct {
	Provider  Provider
	TenantID  shared.ID
	Assets    []DiscoveredAsset
	StartedAt time.Time
	EndedAt   time.Time
	Errors    []error // partial-success tolerated; each error names a specific SDK call site
}

// Duration is the wall-clock time the pass took.
func (r *DiscoveryResult) Duration() time.Duration {
	return r.EndedAt.Sub(r.StartedAt)
}

// Connector is the provider-agnostic interface the inventory pipeline
// consumes. Implementations MUST be safe for concurrent Discover calls
// across different tenants.
type Connector interface {
	// Provider returns the constant identifying this connector.
	Provider() Provider

	// Validate checks credentials without enumerating. Cheap —
	// should be a single auth call. Used by the tenant-admin UI
	// "Test Connection" button.
	Validate(ctx context.Context, creds Credentials) error

	// Discover enumerates assets for the tenant. Implementations
	// MUST honour ctx cancellation; partial results + errors are
	// acceptable and preferred over "all or nothing".
	Discover(ctx context.Context, tenantID shared.ID, creds Credentials) (*DiscoveryResult, error)
}

// Registry holds the available connectors, keyed by Provider. Not
// thread-safe during registration (build once at startup); read-safe
// afterwards.
type Registry struct {
	connectors map[Provider]Connector
}

// NewRegistry constructs an empty registry. Callers register
// connectors via Register before handing the registry to the ingest
// pipeline.
func NewRegistry() *Registry {
	return &Registry{connectors: make(map[Provider]Connector)}
}

// Register adds or replaces a connector. Providers are registered
// exactly once per process; replacing is acceptable in tests.
func (r *Registry) Register(c Connector) {
	r.connectors[c.Provider()] = c
}

// Get returns the connector for a provider, or ok=false if none is
// registered.
func (r *Registry) Get(p Provider) (Connector, bool) {
	c, ok := r.connectors[p]
	return c, ok
}

// Providers returns the sorted list of registered provider IDs.
// Exposed for the tenant-admin "available connectors" dropdown.
func (r *Registry) Providers() []Provider {
	out := make([]Provider, 0, len(r.connectors))
	for p := range r.connectors {
		out = append(out, p)
	}
	return out
}

// ErrProviderNotRegistered is returned when a caller asks for a
// provider that wasn't registered at startup.
var ErrProviderNotRegistered = errors.New("connector provider not registered")

// Run looks up the connector and invokes Discover. Convenience wrapper
// so callers don't need to unpack (Connector, bool) every time.
func (r *Registry) Run(ctx context.Context, p Provider, tenantID shared.ID, creds Credentials) (*DiscoveryResult, error) {
	c, ok := r.Get(p)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotRegistered, p)
	}
	return c.Discover(ctx, tenantID, creds)
}
