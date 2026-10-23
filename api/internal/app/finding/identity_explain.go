package finding

// Identity explanation of a finding (docs/architecture/deduplication.md,
// "Why a finding is one").

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// identityExplainer reads a finding's identity explanation
// (postgres.FindingRepository). scope filters the merged duplicates.
type identityExplainer interface {
	ExplainIdentity(ctx context.Context, tenantID, findingID shared.ID, scope *shared.DataScope) (*vulnerability.IdentityExplanation, error)
}

// ExplainFindingIdentity says why a finding is one finding: the recipe and
// field names of its key, the tools that reported it, and the duplicates
// merged into it that the caller may see. The finding passes the same check
// as GET /findings/{id} (not found otherwise); each merged duplicate is
// filtered by the caller's data scope, so nothing about a finding outside it
// (not even a count) is returned. Never a key, fingerprint or field value.
func (s *VulnerabilityService) ExplainFindingIdentity(ctx context.Context, tenantID, findingID, actingUserID string, isAdmin bool) (*vulnerability.IdentityExplanation, error) {
	f, err := s.GetFindingWithScope(ctx, tenantID, findingID, actingUserID, isAdmin)
	if err != nil {
		return nil, err
	}
	r, ok := s.findingRepo.(identityExplainer)
	if !ok {
		return nil, shared.ErrNotFound
	}
	var scope *shared.DataScope
	if s.dataScope != nil && actingUserID != "" {
		scope, err = s.dataScope.ResolveActing(ctx, f.TenantID(), actingUserID, isAdmin)
		if err != nil {
			// Fail closed, like the by-id check.
			return nil, fmt.Errorf("%w: resolve data scope", shared.ErrNotFound)
		}
	}
	return r.ExplainIdentity(ctx, f.TenantID(), f.ID(), scope)
}
