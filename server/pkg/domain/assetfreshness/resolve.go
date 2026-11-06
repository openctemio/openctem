package assetfreshness

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Resolve before active (docs/rfcs/RFC-088-scope-aware-target-allocation.md,
// decision A5): an active stage takes a host name only while the platform
// holds recent evidence that it resolves.

// ResolveTTL is how old the freshest resolution evidence of a name may be
// for an active stage to take it.
const ResolveTTL = 7 * 24 * time.Hour

// ResolveEvidenceClasses are the observations that prove a name resolved:
// a resolver answered for it (dns), or a tool reached it by name (http,
// tls, ports).
var ResolveEvidenceClasses = []Class{ClassDNS, ClassHTTP, ClassTLS, ClassPorts}

// NameEvidence is the freshest resolution evidence of one inventory name.
type NameEvidence struct {
	AssetID    shared.ID
	Name       string
	ObservedAt time.Time
}

// NameEvidenceReader reads the freshest evidence of the classes for the
// tenant's assets with these names (lower-case). A name without any
// observation of the classes is absent from the answer.
type NameEvidenceReader interface {
	FreshestByName(ctx context.Context, tenantID shared.ID, names []string, classes []Class) ([]NameEvidence, error)
}
