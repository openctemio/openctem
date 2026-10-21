package finding

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/participation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// ParticipationAccess answers the access questions of watchers on findings
// (RFC-120): what the request's caller may read, and whether another person
// could read a finding. It reuses the read rules of the finding surface, so a
// watcher can never see more than a member could open.
type ParticipationAccess struct{ s *VulnerabilityService }

var _ participation.ItemAccess = ParticipationAccess{}

// ParticipationAccess returns the finding side of the watchers feature.
func (s *VulnerabilityService) ParticipationAccess() ParticipationAccess {
	return ParticipationAccess{s: s}
}

// CallerAccess checks that the caller can read the finding (ErrNotFound
// otherwise) and whether they are a pentest campaign client.
func (a ParticipationAccess) CallerAccess(ctx context.Context, tenantID, findingID shared.ID) (participation.Access, error) {
	s := a.s
	var userID string
	var isAdmin bool
	if s.dataScope != nil {
		c := s.dataScope.CallerOf(ctx)
		userID, isAdmin = c.UserID, c.IsAdmin
	}
	_, acc, err := s.AuthorizeFindingRead(ctx, tenantID.String(), findingID.String(), userID, isAdmin)
	if err != nil {
		return participation.Access{}, err
	}
	return participation.Access{ClientOnly: acc.ClientOnly}, nil
}

// UserAccess reports whether the person could read the finding on their own
// account (data scope, or the pentest campaign) and whether they are a
// campaign client (who never see team-only comments).
func (a ParticipationAccess) UserAccess(ctx context.Context, tenantID, findingID, userID shared.ID) (participation.Access, bool, error) {
	f, ok := loadedFinding(ctx, tenantID, findingID)
	if !ok {
		var err error
		if f, err = a.s.findingRepo.GetByID(ctx, tenantID, findingID); err != nil {
			return participation.Access{}, false, err
		}
	}
	ok, clientOnly, err := a.s.userFindingAccess(ctx, f, userID)
	return participation.Access{ClientOnly: clientOnly}, ok, err
}

type loadedFindingKey struct{}

// withLoadedFinding hands the finding an event is about to the per-recipient
// access checks, so a fan-out to many watchers reads it once. Only the finding
// itself is reused: membership and data-scope checks still run per person.
func withLoadedFinding(ctx context.Context, f *vulnerability.Finding) context.Context {
	return context.WithValue(ctx, loadedFindingKey{}, f)
}

func loadedFinding(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.Finding, bool) {
	f, _ := ctx.Value(loadedFindingKey{}).(*vulnerability.Finding)
	if f == nil || f.ID() != findingID || f.TenantID() != tenantID {
		return nil, false
	}
	return f, true
}
