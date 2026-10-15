package scope

// A CI trust configuration adds the repositories it trusts to scope
// (docs/rfcs/RFC-054-scope-model.md, "Repository entries and CI trusts"):
// each namespace or repository it names is a repository entry linked to the
// trust. The trust keeps the entry in step and retires it; a person changes
// it through the trust, or keeps a repository out with an exclusion.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// OriginCITrust: the entry was created by a CI trust configuration.
const OriginCITrust Origin = "ci_trust"

// ErrCITrustManaged refuses a scope change to an entry a CI trust manages.
var ErrCITrustManaged = shared.NewDomainError("CI_TRUST_MANAGED",
	"a CI trust manages this entry; change the trust's owners or repositories, or add an exclusion to keep a repository out",
	shared.ErrConflict)

// CITrustLink is one repository pattern a trust claims and the scope entry
// that carries it (nil when a person deleted an existing entry the trust had
// linked; the next sync creates a managed one again). Seen* is the evidence
// of the first verified pipeline run under the pattern.
type CITrustLink struct {
	TenantID       shared.ID
	TrustConfigID  shared.ID
	TrustName      string
	Pattern        string
	TargetID       *shared.ID
	CreatedAt      time.Time
	SeenAt         *time.Time
	SeenRunID      *shared.ID
	SeenRepository string
	SeenOwnerID    string
}

// CITrustEvidence is a verified pipeline run under a trust: the run, the
// canonical repository and the owner id its token signed.
type CITrustEvidence struct {
	RunID      shared.ID
	Repository string
	OwnerID    string
	At         time.Time
}

// CITrustLinkRepository stores the links. Every method is tenant-scoped.
type CITrustLinkRepository interface {
	// ListByTrust lists a trust's links.
	ListByTrust(ctx context.Context, tenantID, trustID shared.ID) ([]CITrustLink, error)
	// ListByTargets lists the links of these entries, with the trust names.
	ListByTargets(ctx context.Context, tenantID shared.ID, targetIDs []shared.ID) ([]CITrustLink, error)
	// Put inserts a link or points an existing one at targetID.
	Put(ctx context.Context, tenantID, trustID shared.ID, pattern string, targetID shared.ID) error
	// Delete removes a link.
	Delete(ctx context.Context, tenantID, trustID shared.ID, pattern string) error
	// CountForTarget counts the links that point at an entry.
	CountForTarget(ctx context.Context, tenantID, targetID shared.ID) (int, error)
	// MarkSeen records the evidence on a link that has none; it reports
	// whether it did.
	MarkSeen(ctx context.Context, tenantID, trustID shared.ID, pattern string, ev CITrustEvidence) (bool, error)
}

// CITrustSyncOutcome is what a sync did with one pattern: created, linked
// (an equal entry existed), kept, retired, or refused (Err).
type CITrustSyncOutcome struct {
	Pattern  string
	Action   string
	TargetID *shared.ID
	Err      error
}

// Sync actions.
const (
	CITrustCreated = "created"
	CITrustLinked  = "linked"
	CITrustKept    = "kept"
	CITrustRetired = "retired"
	CITrustRefused = "refused"
)
