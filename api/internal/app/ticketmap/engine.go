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

// published returns the published profile of a destination, or nil. The
// issue type is matched by id (preferred) or by name. A caller that cannot
// name the type gets the project's published profile of the kind only when it
// is the single one: with several, which one applies is unknown, so none is
// returned and the caller falls back to its built-in safe mapping instead of
// whichever profile the list happened to return first.
func (s *Service) published(ctx context.Context, tenantID, integrationID shared.ID, kind ticketmapdom.ObjectKind, projectKey, issueType string) (*ticketmapdom.Profile, *ticketmapdom.Version, error) {
	iid := integrationID
	res, err := s.repo.ListProfiles(ctx, tenantID, ticketmapdom.ProfileFilter{IntegrationID: &iid, ObjectKind: kind, ProjectKey: strings.ToUpper(projectKey)}, pagination.New(1, 100))
	if err != nil {
		return nil, nil, err
	}
	var live []*ticketmapdom.Profile
	for _, p := range res.Data {
		if p.PublishedVersion > 0 {
			live = append(live, p)
		}
	}
	// A page that does not hold every profile cannot prove the choice is unique.
	complete := res.Total <= int64(len(res.Data))
	var pick *ticketmapdom.Profile
	switch {
	case issueType == "":
		if len(live) == 1 && complete {
			pick = live[0]
		}
	default:
		// Deterministic when two profiles match (an id match beats a name
		// match; then the lowest profile id).
		rank := func(p *ticketmapdom.Profile) int {
			if p.IssueTypeID == issueType {
				return 0
			}
			if strings.EqualFold(p.IssueType, issueType) {
				return 1
			}
			return 2
		}
		for _, p := range live {
			r := rank(p)
			if r == 2 {
				continue
			}
			if pick == nil || r < rank(pick) || (r == rank(pick) && p.ID.String() < pick.ID.String()) {
				pick = p
			}
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

// FindingStatusTarget returns where the published finding profile of a
// project and issue type moves the issue of a finding in its current state.
// (nil, nil) without one.
func (s *Service) FindingStatusTarget(ctx context.Context, tenantID, integrationID shared.ID, projectKey, issueTypeID string, findingID shared.ID) (*appjira.ProfileStatus, error) {
	p, v, err := s.published(ctx, tenantID, integrationID, ticketmapdom.ObjectFinding, projectKey, issueTypeID)
	if err != nil || p == nil {
		return nil, err
	}
	f, err := s.objects.Finding(ctx, tenantID, findingID)
	if err != nil {
		return nil, err
	}
	return statusTarget(p, v, findingState(f)), nil
}

// TaskStatusTarget returns where the published task profile of a project
// and issue type moves the issue of a task in its current state. (nil, nil)
// without one.
func (s *Service) TaskStatusTarget(ctx context.Context, tenantID, integrationID shared.ID, projectKey, issueTypeID string, taskID shared.ID) (*appjira.ProfileStatus, error) {
	p, v, err := s.published(ctx, tenantID, integrationID, ticketmapdom.ObjectTask, projectKey, issueTypeID)
	if err != nil || p == nil {
		return nil, err
	}
	t, err := s.objects.Task(ctx, tenantID, taskID)
	if err != nil {
		return nil, err
	}
	return statusTarget(p, v, TaskStateOf(t)), nil
}

func statusTarget(p *ticketmapdom.Profile, v *ticketmapdom.Version, state string) *appjira.ProfileStatus {
	out := &appjira.ProfileStatus{ProfileID: p.ID, State: state, DryRun: p.DryRun}
	if v.Snapshot != nil {
		out.Workflow = v.Snapshot.Workflow
	}
	if t, ok := v.Spec.Status.Outbound[state]; ok {
		out.Target = &t
	}
	return out
}

// RenderTaskCreate renders the published task profile of a destination for
// a new issue of a remediation task. (nil, nil) without one. The create path
// already required every member of the task in the caller's scope.
func (s *Service) RenderTaskCreate(ctx context.Context, tenantID, integrationID shared.ID, projectKey, issueType string, taskID shared.ID) (*appjira.ProfileCreate, error) {
	p, v, err := s.published(ctx, tenantID, integrationID, ticketmapdom.ObjectTask, projectKey, issueType)
	if err != nil || p == nil {
		return nil, err
	}
	task, err := s.objects.Task(ctx, tenantID, taskID)
	if err != nil {
		return nil, err
	}
	members, total, err := s.objects.TaskMembers(ctx, tenantID, taskID, maxTableRows)
	if err != nil {
		return nil, err
	}
	var user *UserInfo
	if a := task.AssigneeUserID; a != nil {
		user, _ = s.objects.User(ctx, tenantID, *a)
	}
	values := TaskValues(task, members, total, user, s.webBase)
	r := ticketmapdom.RenderOutbound(p.ObjectKind, v.Spec, values, v.Snapshot, renderOptions(true))
	if _, ok := r.Fields["summary"]; !ok {
		return nil, fmt.Errorf("%w: the mapping renders no summary for this task", shared.ErrValidation)
	}
	out := &appjira.ProfileCreate{ProfileID: p.ID, Version: v.Version, IssueTypeID: p.IssueTypeID, Fields: r.Fields, DryRun: p.DryRun}
	for _, d := range r.Dropped {
		out.Dropped = append(out.Dropped, d.FieldID)
	}
	return out, nil
}

// MarkDrifted flags a profile of the tenant whose issues the tracker refused.
func (s *Service) MarkDrifted(ctx context.Context, tenantID, profileID shared.ID) error {
	return s.repo.SetDrifted(ctx, tenantID, profileID, true)
}

// HasPublishedProfile reports whether a destination (kind, project, issue
// type id) has a published profile: its required fields are then covered
// (publishing checks them against the tracker).
func (s *Service) HasPublishedProfile(ctx context.Context, tenantID, integrationID shared.ID, kind ticketmapdom.ObjectKind, projectKey, issueTypeID string) (bool, error) {
	if issueTypeID == "" {
		return false, nil
	}
	p, _, err := s.published(ctx, tenantID, integrationID, kind, projectKey, issueTypeID)
	return p != nil, err
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

// InboundStatusMap returns the status map of the published profile of a
// project and issue type for an object kind, or nil without one.
func (s *Service) InboundStatusMap(ctx context.Context, tenantID, integrationID shared.ID, kind ticketmapdom.ObjectKind, projectKey, issueTypeID string) (*ticketmapdom.StatusMap, error) {
	p, v, err := s.published(ctx, tenantID, integrationID, kind, projectKey, issueTypeID)
	if err != nil || p == nil {
		return nil, err
	}
	sm := v.Spec.Status
	return &sm, nil
}
