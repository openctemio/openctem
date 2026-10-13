package assetfreshness

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Wildcard-only names (docs/rfcs/RFC-088-scope-aware-target-allocation.md,
// decision A4). The platform turns the wildcard-DNS filter on for every
// resolution job. A completed filtered resolution that was given a name and
// did not report it is the platform's evidence that the name resolves only
// through a wildcard record of its zone (or not at all): the name is marked.
// A later filtered resolution that reports the name clears the mark.

// WildcardDNSStore keeps the marks. Every call is tenant-scoped: an asset id
// of another tenant marks, clears and reports nothing.
type WildcardDNSStore interface {
	WildcardDNSReader
	// MarkWildcardOnly marks the tenant's assets (the resolution that
	// dropped them, when it happened).
	MarkWildcardOnly(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, commandID shared.ID, at time.Time) error
	// ClearWildcardOnly removes the marks of the tenant's assets.
	ClearWildcardOnly(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error
}

// WildcardDNSReader reports which of the tenant's assets are marked.
type WildcardDNSReader interface {
	WildcardOnly(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]bool, error)
}
