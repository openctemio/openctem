package ticketmap

import (
	"context"
	"fmt"
	"strings"

	appjira "github.com/openctemio/openctem/api/internal/app/jira"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	ticketmapdom "github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The ticket paths use published profiles through these methods (they
// implement jira.ProfileSource). They run on paths that already authorized
// the object (the create-ticket route's data-scope guard, a workflow of the
// tenant, the status-change hook), so they read the object without a second
// scope check; the tenant comes from the caller, never from the profile.

var _ appjira.ProfileSource = (*Service)(nil)

// published returns the published profile of a destination, or nil.
func (s *Service) published(ctx context.Context, tenantID, integrationID shared.ID, kind ticketmapdom.ObjectKind, projectKey, issueType string) (*ticketmapdom.Profile, *ticketmapdom.Version, error) {
	iid := integrationID
	res, err := s.repo.ListProfiles(ctx, tenantID, ticketmapdom.ProfileFilter{IntegrationID: &iid, ObjectKind: kind, ProjectKey: strings.ToUpper(projectKey)}, pagination.New(1, 50))
	if err != nil {
		return nil, nil, err
	}
	var pick *ticketmapdom.Profile
	for _, p := range res.Data {
		if p.PublishedVersion == 0 {
			continue
		}
		if issueType == "" || strings.EqualFold(p.IssueType, issueType) || p.IssueTypeID == issueType {
			pick = p
			break
		}
	}
	if pick == nil {
		return nil, nil, nil
	}
	v, err := s.repo.GetVersion(ctx, tenantID, pick.ID, pick.PublishedVersion)
	if err != nil {
		return nil, nil, err
	}
	return pick, v, nil
}

// RenderFindingCreate renders the published profile of a destination for a
// new issue of a finding. (nil, nil) without a published profile.
func (s *Service) RenderFindingCreate(ctx context.Context, tenantID, integrationID shared.ID, projectKey, issueType string, findingID shared.ID) (*appjira.ProfileCreate, error) {
	p, v, err := s.published(ctx, tenantID, integrationID, ticketmapdom.ObjectFinding, projectKey, issueType)
	if err != nil || p == nil {
		return nil, err
	}
	values, _, err := s.findingValues(ctx, tenantID, findingID)
	if err != nil {
		return nil, err
	}
	r := ticketmapdom.RenderOutbound(p.ObjectKind, v.Spec, values, v.Snapshot, renderOptions(true))
	if _, ok := r.Fields["summary"]; !ok {
		return nil, fmt.Errorf("%w: the mapping renders no summary for this finding", shared.ErrValidation)
	}
	out := &appjira.ProfileCreate{ProfileID: p.ID, Version: v.Version, IssueTypeID: p.IssueTypeID, Fields: r.Fields, DryRun: p.DryRun}
	for _, d := range r.Dropped {
		out.Dropped = append(out.Dropped, d.FieldID)
	}
	return out, nil
}

// FindingStatusTarget returns where the published profile of a project moves
// the issue of a finding in its current state. (nil, nil) without a
// published finding profile for the project.
func (s *Service) FindingStatusTarget(ctx context.Context, tenantID, integrationID shared.ID, projectKey string, findingID shared.ID) (*appjira.ProfileStatus, error) {
	p, v, err := s.published(ctx, tenantID, integrationID, ticketmapdom.ObjectFinding, projectKey, "")
	if err != nil || p == nil {
		return nil, err
	}
	f, err := s.objects.Finding(ctx, tenantID, findingID)
	if err != nil {
		return nil, err
	}
	out := &appjira.ProfileStatus{ProfileID: p.ID, State: findingState(f), DryRun: p.DryRun}
	if v.Snapshot != nil {
		out.Workflow = v.Snapshot.Workflow
	}
	if t, ok := v.Spec.Status.Outbound[out.State]; ok {
		out.Target = &t
	}
	return out, nil
}

// findingValues loads a finding's mapping values without the caller-scope
// check (see the file comment).
func (s *Service) findingValues(ctx context.Context, tenantID, findingID shared.ID) (ticketmapdom.Values, string, error) {
	f, err := s.objects.Finding(ctx, tenantID, findingID)
	if err != nil {
		return nil, "", err
	}
	var asset *AssetInfo
	if !f.AssetID().IsZero() {
		asset, _ = s.objects.Asset(ctx, tenantID, f.AssetID())
	}
	var user *UserInfo
	if a := f.AssignedTo(); a != nil {
		user, _ = s.objects.User(ctx, tenantID, *a)
	}
	return FindingValues(f, asset, user, s.webBase), findingState(f), nil
}

// ProjectKeys lists the Jira projects that have a mapping profile on an
// integration of the tenant (any object kind, published or not).
func (s *Service) ProjectKeys(ctx context.Context, tenantID, integrationID shared.ID) ([]string, error) {
	iid := integrationID
	res, err := s.repo.ListProfiles(ctx, tenantID, ticketmapdom.ProfileFilter{IntegrationID: &iid}, pagination.New(1, 200))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(res.Data))
	for _, p := range res.Data {
		out = append(out, p.ProjectKey)
	}
	return out, nil
}
