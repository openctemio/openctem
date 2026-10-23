package finding

// Same-issue groups (pkg/domain/issuelink): read the group a finding is in,
// and take a finding out of it.
// https://github.com/openctemio/openctem/blob/develop/api/docs/architecture/deduplication.md
//
// A group is shown only through the caller's data scope: a member on an asset
// the caller cannot see is left out, and nothing (no count, no id) says it
// exists. A group with no other visible member is shown as none.

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/issuelink"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// IssueLinkStore is implemented by the postgres finding issue link
// repository.
type IssueLinkStore interface {
	IssueGroup(ctx context.Context, tenantID, findingID shared.ID) ([]issuelink.GroupMember, error)
	Unlink(ctx context.Context, tenantID, findingID, otherID shared.ID, actorID string) (primaryID, memberID string, err error)
}

// SetIssueLinkStore wires same-issue groups (nil: every finding is in none).
func (s *VulnerabilityService) SetIssueLinkStore(st IssueLinkStore) { s.issueLinks = st }

// IssueGroup returns the same-issue group of a finding the caller can see:
// the members on assets in the caller's data scope, the primary first. Empty
// when the finding is in no group, or no other member is visible.
func (s *VulnerabilityService) IssueGroup(ctx context.Context, tenantID, findingID, actingUserID string, isAdmin bool) ([]issuelink.GroupMember, error) {
	f, err := s.GetFindingWithScope(ctx, tenantID, findingID, actingUserID, isAdmin)
	if err != nil {
		return nil, err
	}
	if s.issueLinks == nil {
		return nil, nil
	}
	members, err := s.issueLinks.IssueGroup(ctx, f.TenantID(), f.ID())
	if err != nil {
		return nil, err
	}
	visible, err := s.visibleMembers(ctx, f.TenantID(), members)
	if err != nil {
		return nil, err
	}
	for _, m := range visible {
		if m.FindingID != f.ID().String() {
			return visible, nil
		}
	}
	return nil, nil
}

// visibleMembers keeps the members the caller may see (fail closed).
func (s *VulnerabilityService) visibleMembers(ctx context.Context, tenantID shared.ID, members []issuelink.GroupMember) ([]issuelink.GroupMember, error) {
	if len(members) == 0 || s.dataScope == nil {
		return members, nil
	}
	assets := make([]shared.ID, 0, len(members))
	for _, m := range members {
		if id, err := shared.IDFromString(m.AssetID); err == nil {
			assets = append(assets, id)
		}
	}
	allowed, err := s.dataScope.FindingFilterForCaller(ctx, tenantID, assets)
	if err != nil {
		s.logger.Warn("issue group scope check failed", "error", err)
		return nil, shared.ErrNotFound
	}
	out := make([]issuelink.GroupMember, 0, len(members))
	for _, m := range members {
		asset, _ := shared.IDFromString(m.AssetID)
		var to *shared.ID
		if m.AssignedTo != "" {
			if id, err := shared.IDFromString(m.AssignedTo); err == nil {
				to = &id
			}
		}
		if allowed(asset, to) {
			out = append(out, m)
		}
	}
	return out, nil
}

// UnlinkIssueInput takes OtherID out of FindingID's same-issue group (or
// FindingID out of it, when OtherID is the group's primary).
type UnlinkIssueInput struct {
	TenantID  string
	FindingID string
	OtherID   string
	ActorID   string
	IsAdmin   bool
	Audit     audit.AuditContext
}

// ErrIssueLinkNotFound: the two findings are not linked (or not visible).
var ErrIssueLinkNotFound = fmt.Errorf("%w: the findings are not linked as the same issue", shared.ErrNotFound)

// UnlinkIssue ends the link between two findings the caller can both see.
// The pair is never linked again automatically; both timelines and the
// audit log record it.
func (s *VulnerabilityService) UnlinkIssue(ctx context.Context, in UnlinkIssueInput) error {
	if s.issueLinks == nil {
		return ErrIssueLinkNotFound
	}
	a, err := s.GetFindingWithScope(ctx, in.TenantID, in.FindingID, in.ActorID, in.IsAdmin)
	if err != nil {
		return err
	}
	b, err := s.GetFindingWithScope(ctx, in.TenantID, in.OtherID, in.ActorID, in.IsAdmin)
	if err != nil {
		return err
	}
	primaryID, memberID, err := s.issueLinks.Unlink(ctx, a.TenantID(), a.ID(), b.ID(), in.ActorID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return ErrIssueLinkNotFound
		}
		return err
	}
	if s.auditService != nil {
		actx := in.Audit
		if actx.TenantID == "" {
			actx.TenantID = in.TenantID
		}
		if actx.ActorID == "" {
			actx.ActorID = in.ActorID
		}
		event := audit.NewSuccessEvent(auditdom.ActionFindingIssueUnlinked, auditdom.ResourceTypeFinding, memberID).
			WithMessage("Took a finding out of a same-issue group").
			WithMetadata("primary_id", primaryID).
			WithMetadata("member_id", memberID).
			WithSeverity(auditdom.SeverityLow)
		if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
			s.logger.Warn("failed to audit issue unlink", "error", err)
		}
	}
	return nil
}
