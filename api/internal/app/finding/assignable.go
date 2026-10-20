package finding

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// ErrAssigneeCannotRead is the answer for an assignee who is a member but
// could not read the finding (outside their data scope, or not on the pentest
// campaign). It does not say which, so the refusal tells a caller nothing
// about another member's scope.
var ErrAssigneeCannotRead = fmt.Errorf("%w: this person cannot be assigned this finding", shared.ErrValidation)

// assignablePool is how many members one picker request examines; a search
// narrows it. assignableMaxResults caps what is returned.
const (
	assignablePool       = 200
	assignableMaxResults = 50
)

// MemberSearcher lists tenant members for the assignee picker
// (postgres.TenantRepository implements it).
type MemberSearcher interface {
	SearchMembersWithUserInfo(ctx context.Context, tenantID shared.ID, filters tenantdom.MemberSearchFilters) (*tenantdom.MemberSearchResult, error)
}

// SetMemberSearcher wires the member list behind ListAssignableMembers.
func (s *VulnerabilityService) SetMemberSearcher(m MemberSearcher) { s.memberSearcher = m }

// AssignableMember is a member who may be assigned a finding. It carries no
// email: a caller with findings:assign need not hold team:members:read.
type AssignableMember struct {
	UserID    shared.ID
	Name      string
	AvatarURL string
	Role      string
}

// userMayReadFinding reports whether userID could read the finding on their
// own account: the asset inside their data scope (being its assignee does not
// count, assignment is what is being decided), or, for a pentest finding, a
// campaign member who may see its status. Same rules as GetFindingWithScope.
// Without a data-scope enforcer nothing narrows (the service convention).
func (s *VulnerabilityService) userMayReadFinding(ctx context.Context, f *vulnerability.Finding, userID shared.ID) (bool, error) {
	ok, _, err := s.userFindingAccess(ctx, f, userID)
	return ok, err
}

// userFindingAccess is userMayReadFinding that also says whether the person
// reads the finding as a pentest campaign client.
func (s *VulnerabilityService) userFindingAccess(ctx context.Context, f *vulnerability.Finding, userID shared.ID) (ok, clientOnly bool, err error) {
	if s.dataScope == nil {
		return true, false, nil
	}
	tenantID := f.TenantID()
	isAdmin, err := s.dataScope.IsAdmin(ctx, tenantID, userID)
	if err != nil {
		return false, false, fmt.Errorf("resolve admin: %w", err)
	}
	if isPentest(f) {
		v, err := s.resolvePentestViewer(ctx, tenantID, f, userID.String(), isAdmin)
		if err != nil {
			return false, false, nil //nolint:nilerr // not on the campaign: cannot read
		}
		return true, v.clientOnly(), nil
	}
	scope, err := s.dataScope.ForUser(ctx, tenantID, userID)
	if err != nil {
		return false, false, err
	}
	ok, err = s.dataScope.InScope(ctx, scope, f.AssetID())
	return ok, false, err
}

// assertAssigneeMayRead refuses an assignee who cannot read the finding, so
// the assignment notice is never hidden from them and the SLA ladder never
// targets a person who cannot act.
func (s *VulnerabilityService) assertAssigneeMayRead(ctx context.Context, f *vulnerability.Finding, userID shared.ID) error {
	ok, err := s.userMayReadFinding(ctx, f, userID)
	if err != nil {
		return fmt.Errorf("check assignee access: %w", err)
	}
	if !ok {
		return ErrAssigneeCannotRead
	}
	return nil
}

// ListAssignableMembers returns the active members who may be assigned the
// finding, filtered by name. The caller must be able to read the finding
// (ErrNotFound otherwise). Without a member list wired it fails closed.
func (s *VulnerabilityService) ListAssignableMembers(ctx context.Context, tenantID, findingID, actingUserID string, isAdmin bool, query string, limit int) ([]AssignableMember, error) {
	f, err := s.GetFindingWithScope(ctx, tenantID, findingID, actingUserID, isAdmin)
	if err != nil {
		return nil, err
	}
	if s.memberSearcher == nil {
		return nil, fmt.Errorf("%w: member list not configured", shared.ErrValidation)
	}
	if limit <= 0 || limit > assignableMaxResults {
		limit = assignableMaxResults
	}
	res, err := s.memberSearcher.SearchMembersWithUserInfo(ctx, f.TenantID(), tenantdom.MemberSearchFilters{
		Search:         strings.TrimSpace(query),
		SearchNameOnly: true,
		Status:         "active",
		Limit:          assignablePool,
	})
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	out := make([]AssignableMember, 0, limit)
	for _, m := range res.Members {
		if len(out) >= limit {
			break
		}
		ok, err := s.userMayReadFinding(ctx, f, m.UserID)
		if err != nil {
			s.logger.Warn("assignable members: access check failed", "error", err)
			continue // fail closed: leave the member out
		}
		if ok {
			out = append(out, AssignableMember{UserID: m.UserID, Name: m.Name, AvatarURL: m.AvatarURL, Role: string(m.Role)})
		}
	}
	return out, nil
}
