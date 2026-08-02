// Package remediation implements the application service for remediation groups
// (RFC-015): grouping findings by the fix that resolves them and resolving a
// whole group in one action.
package remediation

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/api/internal/app/finding"
	remediationdom "github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// BulkResolver is the slice of the finding service the group resolve needs.
type BulkResolver interface {
	BulkUpdateFindingsStatus(ctx context.Context, tenantID string, input finding.BulkUpdateStatusInput) (*finding.BulkUpdateResult, error)
}

// Guard is the abuse-guard slice (size ceiling + hourly budget) applied before a
// bulk resolve.
type Guard interface {
	CheckBulk(ctx context.Context, tenantID shared.ID, size int, operatorApproved bool) error
}

// GroupService lists remediation groups and resolves a whole group at once.
type GroupService struct {
	keys     remediationdom.KeyRepository
	resolver BulkResolver
	guard    Guard
	logger   *logger.Logger
}

// NewGroupService constructs the service. guard may be nil (no abuse gate).
func NewGroupService(keys remediationdom.KeyRepository, resolver BulkResolver, guard Guard, log *logger.Logger) *GroupService {
	return &GroupService{keys: keys, resolver: resolver, guard: guard, logger: log.With("service", "remediation_group")}
}

// ListGroups returns the tenant's remediation groups over its open findings.
func (s *GroupService) ListGroups(ctx context.Context, tenantID shared.ID) ([]remediationdom.Group, error) {
	return s.keys.ListGroups(ctx, tenantID, closedStatusStrings())
}

// ResolveGroupInput parameterizes a group resolve.
type ResolveGroupInput struct {
	Key        string
	Status     string // fix_applied (default) or resolved
	Resolution string
	ActorID    string
	// HasVerifyPermission mirrors the single-finding direct-resolve guard.
	HasVerifyPermission bool
	// OperatorApproved lets an over-ceiling bulk through the abuse guard.
	OperatorApproved bool
}

// ResolveGroup transitions every open, non-pentest finding in a group to the
// requested status, reusing the finding bulk path (and its Jira sync + activity)
// behind the bulk abuse-guard. Defaults to fix_applied ("patched, pending
// verification") so the next rescan can confirm and flip to resolved.
func (s *GroupService) ResolveGroup(ctx context.Context, tenantID shared.ID, in ResolveGroupInput) (*finding.BulkUpdateResult, error) {
	status := in.Status
	if status == "" {
		status = string(vulnerability.FindingStatusFixApplied)
	}
	if status != string(vulnerability.FindingStatusFixApplied) && status != string(vulnerability.FindingStatusResolved) {
		return nil, fmt.Errorf("%w: group resolve status must be fix_applied or resolved", shared.ErrValidation)
	}

	excl := closedStatusStrings()
	ids, err := s.keys.OpenFindingIDs(ctx, tenantID, in.Key, excl)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return &finding.BulkUpdateResult{}, nil
	}

	if s.guard != nil {
		if err := s.guard.CheckBulk(ctx, tenantID, len(ids), in.OperatorApproved); err != nil {
			return nil, err
		}
	}

	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}

	s.logger.Info("resolving remediation group", "tenant", tenantID.String(), "key", sanitizeLogValue(in.Key), "count", len(idStrs), "status", status)
	return s.resolver.BulkUpdateFindingsStatus(ctx, tenantID.String(), finding.BulkUpdateStatusInput{
		FindingIDs:          idStrs,
		Status:              status,
		Resolution:          in.Resolution,
		ActorID:             in.ActorID,
		HasVerifyPermission: in.HasVerifyPermission,
	})
}

// sanitizeLogValue strips CR/LF and other control characters from an
// attacker-influenceable value before it is logged, preventing log-forging when
// the logger runs in text mode. The remediation key comes from the request URL,
// so it is user-controlled. Also length-capped to bound log size.
func sanitizeLogValue(s string) string {
	const maxLen = 128
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r < 0x20 {
			return -1
		}
		return r
	}, s)
}

// closedStatusStrings returns the closed finding statuses as strings, to exclude
// already-closed findings from groups and resolves.
func closedStatusStrings() []string {
	cs := vulnerability.ClosedFindingStatuses()
	out := make([]string, 0, len(cs))
	for _, s := range cs {
		out = append(out, string(s))
	}
	return out
}
