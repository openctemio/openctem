package exploration

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Candidate is one match of a rule's trigger: the subject asset, its stored
// type, and the records that justify the question (derived_from ends).
type Candidate struct {
	AssetID  shared.ID
	Type     asset.AssetType
	SubType  string
	Evidence []Link
}

// ReaskAfter is how long a closed question is not asked again by a rule.
const ReaskAfter = 30 * 24 * time.Hour

// TriggerStore reads the trigger states of the rules. Every read is bound to
// one tenant, returns at most limit candidates, and leaves out subjects that
// already have a live lead of the lead type, or one closed within
// ReaskAfter. The triggers read only states the platform derives itself
// (its DNS checks, its version matcher, its liveness ledger), never an
// imported or unsolicited report directly.
type TriggerStore interface {
	// DanglingAliases: domains and subdomains with an active dangling_cname
	// exposure from the platform's DNS check and no active takeover finding.
	DanglingAliases(ctx context.Context, tenantID shared.ID, leadType string, limit int) ([]Candidate, error)
	// UnconfirmedCriticalMatches: assets with an open version-match finding
	// that is in KEV or critical while the match is only "potential" (below
	// the likely threshold): the version itself needs confirming.
	UnconfirmedCriticalMatches(ctx context.Context, tenantID shared.ID, leadType string, limit int) ([]Candidate, error)
	// GoneWithOpenFindings: assets the liveness ledger holds gone while
	// findings stay open on them.
	GoneWithOpenFindings(ctx context.Context, tenantID shared.ID, leadType string, limit int) ([]Candidate, error)
}
