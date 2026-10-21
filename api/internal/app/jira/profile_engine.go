package jira

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Published mapping profiles in the ticket paths
// (docs/rfcs/RFC-097-ticket-field-mapping.md): when the destination has a
// published profile, an issue is created from its rendered fields and a
// status change moves the issue along the profile's workflow path. Without a
// profile the built-in behavior is unchanged.

// ProfileCreate is a profile rendered for one new issue.
type ProfileCreate struct {
	ProfileID   shared.ID
	Version     int
	IssueTypeID string
	Fields      map[string]any
	DryRun      bool
	// Dropped names the rows that were not sent (empty value, data level).
	Dropped []string
}

// ProfileStatus is where a profile moves an issue for an object's state.
type ProfileStatus struct {
	ProfileID shared.ID
	State     string
	// Target is nil when the state does not move the issue.
	Target   *ticketmap.StatusTarget
	Workflow ticketmap.Workflow
	DryRun   bool
}

// ProfileSource renders published profiles (implemented by the ticket
// mapping service). A profile is found by its destination: the object kind,
// the project and the issue type (an id, or a name for a type chosen by
// name). Every method returns (nil, nil) when the destination has no
// published profile.
type ProfileSource interface {
	RenderFindingCreate(ctx context.Context, tenantID, integrationID shared.ID, projectKey, issueType string, findingID shared.ID) (*ProfileCreate, error)
	// RenderTaskCreate renders the published task profile for a new issue
	// of a remediation task.
	RenderTaskCreate(ctx context.Context, tenantID, integrationID shared.ID, projectKey, issueType string, taskID shared.ID) (*ProfileCreate, error)
	// FindingStatusTarget is where the finding profile of the issue's
	// project and issue type moves the issue for the finding's state.
	FindingStatusTarget(ctx context.Context, tenantID, integrationID shared.ID, projectKey, issueTypeID string, findingID shared.ID) (*ProfileStatus, error)
	// TaskStatusTarget is the same for a task's issue and the task's state.
	TaskStatusTarget(ctx context.Context, tenantID, integrationID shared.ID, projectKey, issueTypeID string, taskID shared.ID) (*ProfileStatus, error)
	// ProjectKeys lists the projects that have a mapping profile on the
	// integration; linking an existing issue is limited to configured projects.
	ProjectKeys(ctx context.Context, tenantID, integrationID shared.ID) ([]string, error)
	// InboundStatusMap returns the status map of the published profile of a
	// project and issue type for an object kind, or nil without one.
	InboundStatusMap(ctx context.Context, tenantID, integrationID shared.ID, kind ticketmap.ObjectKind, projectKey, issueTypeID string) (*ticketmap.StatusMap, error)
	// MarkDrifted flags a profile whose issues the tracker refused (a field
	// or the issue type changed under it).
	MarkDrifted(ctx context.Context, tenantID, profileID shared.ID) error
}

// ProfileClient is what the engine needs from a tracker client beyond Client.
type ProfileClient interface {
	IntegrationID() shared.ID
	CreateIssueFields(ctx context.Context, projectKey, issueTypeID string, fields map[string]any, marker *IssueMarker) (*CreateIssueResult, error)
	CurrentStatus(ctx context.Context, issueKey string) (ticketmap.WorkflowStatus, error)
	AvailableTransitions(ctx context.Context, issueKey string) ([]ticketmap.WorkflowTransition, error)
	Transition(ctx context.Context, issueKey, transitionID string, fields map[string]string, comment string) error
	// IssueTypeOf reads the issue's current issue type id (a person may
	// change the type in the tracker).
	IssueTypeOf(ctx context.Context, issueKey string) (string, error)
}

// RetryAfterError: the tracker asked to wait (429); the job retries after.
type RetryAfterError struct{ After time.Duration }

func (e *RetryAfterError) Error() string {
	return fmt.Sprintf("tracker rate limit: retry after %s", e.After)
}

// PermanentError: the tracker refused the request (4xx); retrying cannot help.
type PermanentError struct {
	Status int
	Err    error
}

func (e *PermanentError) Error() string {
	return fmt.Sprintf("tracker refused the request (HTTP %d)", e.Status)
}
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent marks the error as not worth a retry (the job runner skips it).
func (e *PermanentError) Permanent() bool { return true }

// pathError is a mapping or workflow problem: retrying cannot help.
type pathError struct{ err error }

func (e *pathError) Error() string   { return e.err.Error() }
func (e *pathError) Unwrap() error   { return e.err }
func (e *pathError) Permanent() bool { return true }

// SetProfileSource wires published mapping profiles into the ticket paths.
func (s *SyncService) SetProfileSource(p ProfileSource) { s.profiles = p }

// profileFor returns the profile client and its integration when profiles
// are wired and the client supports them.
func (s *SyncService) profileClient(c Client) (ProfileClient, bool) {
	if s.profiles == nil {
		return nil, false
	}
	pc, ok := c.(ProfileClient)
	return pc, ok
}

// createFromProfile creates the issue of a finding or a task from the
// published profile of its destination. handled is false when there is no
// profile (or it is in dry run): the caller then creates the issue the
// built-in way. A refusal naming fields marks the profile drifted, so the
// mapping page shows what to fix.
func (s *SyncService) createFromProfile(ctx context.Context, c Client, tenantID shared.ID, kind ticketmap.ObjectKind, objectID shared.ID, projectKey, issueType, parentKey string, marker *IssueMarker) (*CreateIssueResult, bool, error) {
	pc, ok := s.profileClient(c)
	if !ok {
		return nil, false, nil
	}
	var pr *ProfileCreate
	var err error
	if kind == ticketmap.ObjectTask {
		pr, err = s.profiles.RenderTaskCreate(ctx, tenantID, pc.IntegrationID(), projectKey, issueType, objectID)
	} else {
		pr, err = s.profiles.RenderFindingCreate(ctx, tenantID, pc.IntegrationID(), projectKey, issueType, objectID)
	}
	if err != nil {
		return nil, false, fmt.Errorf("render mapping profile: %w", err)
	}
	if pr == nil {
		return nil, false, nil
	}
	if pr.DryRun {
		s.logger.Info("ticket mapping dry run: would create the issue from the profile",
			"profile_id", pr.ProfileID.String(), "version", pr.Version, "project", logger.SanitizeValue(projectKey),
			"fields", logger.SanitizeValue(strings.Join(fieldNames(pr.Fields), ",")), "dropped", logger.SanitizeValue(strings.Join(pr.Dropped, ",")))
		return nil, false, nil
	}
	fields := pr.Fields
	if parentKey != "" {
		fields = cloneFields(fields)
		fields["parent"] = map[string]string{"key": parentKey}
	}
	res, err := pc.CreateIssueFields(ctx, projectKey, pr.IssueTypeID, fields, marker)
	if err != nil {
		var fr *FieldRejectedError
		if errors.As(err, &fr) {
			if derr := s.profiles.MarkDrifted(ctx, tenantID, pr.ProfileID); derr != nil {
				s.logger.Warn("ticket mapping: could not mark the profile drifted",
					"profile_id", pr.ProfileID.String(), "error", logger.SanitizeValue(derr.Error()))
			}
		}
		return nil, true, fmt.Errorf("create jira ticket from mapping profile: %w", err)
	}
	// A create through the mapping answers an earlier refusal of this kind
	// (publishing the mapping is how the refused fields get filled).
	s.noteCreate(ctx, tenantID, pc.IntegrationID(), string(kind), IssueTypeRef{}, nil)
	return res, true, nil
}

// profileStatusTarget finds where the published profile of the issue's
// project and current issue type moves the issue (nil without a profile).
func (s *SyncService) profileStatusTarget(ctx context.Context, pc ProfileClient, tenantID shared.ID, kind ticketmap.ObjectKind, objectID shared.ID, issueKey string) (*ProfileStatus, error) {
	typeID, err := pc.IssueTypeOf(ctx, issueKey)
	if err != nil {
		return nil, fmt.Errorf("read the issue's type: %w", err)
	}
	project := ticketlink.ProjectOf(issueKey)
	if kind == ticketmap.ObjectTask {
		return s.profiles.TaskStatusTarget(ctx, tenantID, pc.IntegrationID(), project, typeID, objectID)
	}
	return s.profiles.FindingStatusTarget(ctx, tenantID, pc.IntegrationID(), project, typeID, objectID)
}

// syncStatusFromProfile moves the issue along the published profile's
// workflow path for the finding's state. handled is false when there is no
// profile for the issue's project and issue type (the built-in status sync
// then applies).
func (s *SyncService) syncStatusFromProfile(ctx context.Context, c Client, tenantID, findingID shared.ID, issueKey string) (bool, error) {
	pc, ok := s.profileClient(c)
	if !ok {
		return false, nil
	}
	ps, err := s.profileStatusTarget(ctx, pc, tenantID, ticketmap.ObjectFinding, findingID, issueKey)
	if err != nil {
		return true, fmt.Errorf("mapping profile status: %w", err)
	}
	if ps == nil {
		return false, nil
	}
	if ps.Target == nil {
		return true, nil // this state does not move the issue
	}
	if ps.DryRun {
		s.logger.Info("ticket mapping dry run: would move the issue",
			"profile_id", ps.ProfileID.String(), "issue_key", logger.SanitizeValue(issueKey), "state", ps.State,
			"target", logger.SanitizeValue(ps.Target.StatusID))
		return true, nil
	}
	comment := ""
	if ps.Target.Comment {
		comment = fmt.Sprintf("OpenCTEM: the finding is now %s.", strings.ReplaceAll(ps.State, "_", " "))
	}
	if err := runStatusPath(ctx, pc, issueKey, *ps.Target, ps.Workflow, comment); err != nil {
		if errors.Is(err, ErrNoPath) {
			s.logger.Warn("ticket mapping: the issue cannot reach the mapped status",
				"profile_id", ps.ProfileID.String(), "issue_key", logger.SanitizeValue(issueKey), "state", ps.State,
				"error", logger.SanitizeValue(err.Error()))
			return true, &pathError{err: err}
		}
		return true, err
	}
	return true, nil
}

// ErrNoPath: the issue cannot reach the mapped status from where it is.
var ErrNoPath = errors.New("the issue cannot reach the mapped status from its current status")

// runStatusPath moves an issue to the target status one transition at a
// time. Each step re-reads the issue's available transitions (the workflow
// may have changed since the profile was published) and fills the step's
// required screen fields from the target. It never guesses: with a known
// workflow it follows the shortest path, without one it only takes a direct
// transition to the target. finalComment (when not empty) goes with the
// last transition.
func runStatusPath(ctx context.Context, pc ProfileClient, issueKey string, target ticketmap.StatusTarget, wf ticketmap.Workflow, finalComment string) error {
	for step := 0; step < ticketmap.MaxPathSteps; step++ {
		cur, err := pc.CurrentStatus(ctx, issueKey)
		if err != nil {
			return fmt.Errorf("read issue status: %w", err)
		}
		if cur.ID == target.StatusID {
			return nil
		}
		avail, err := pc.AvailableTransitions(ctx, issueKey)
		if err != nil {
			return fmt.Errorf("read transitions: %w", err)
		}
		next := target.StatusID
		if len(wf.Transitions) > 0 {
			path, perr := wf.Path(cur.ID, target.StatusID)
			if perr != nil {
				return fmt.Errorf("%w (%s → %s)", ErrNoPath, cur.Name, target.StatusID)
			}
			next = path[0].To
		}
		var chosen *ticketmap.WorkflowTransition
		for i := range avail {
			if avail[i].To == next {
				chosen = &avail[i]
				break
			}
		}
		if chosen == nil {
			return fmt.Errorf("%w (%s → %s)", ErrNoPath, cur.Name, next)
		}
		final := chosen.To == target.StatusID
		fields := map[string]string{}
		for _, f := range chosen.Fields {
			v, ok := target.Fields[f.ID]
			if f.ID == ticketmap.ResolutionFieldID && target.Resolution != "" && final {
				v, ok = target.Resolution, true
			}
			if !ok {
				if f.Required {
					return fmt.Errorf("%w: transition %q requires %q, which the mapping does not fill", ErrNoPath, chosen.Name, f.Name)
				}
				continue
			}
			fields[f.ID] = v
		}
		comment := ""
		if final {
			comment = finalComment
		}
		if err := pc.Transition(ctx, issueKey, chosen.ID, fields, comment); err != nil {
			return fmt.Errorf("transition %q: %w", chosen.Name, err)
		}
	}
	return fmt.Errorf("%w: more than %d steps", ErrNoPath, ticketmap.MaxPathSteps)
}

func fieldNames(f map[string]any) []string {
	out := make([]string, 0, len(f))
	for k := range f {
		out = append(out, k)
	}
	return out
}

func cloneFields(f map[string]any) map[string]any {
	out := make(map[string]any, len(f)+1)
	for k, v := range f {
		out[k] = v
	}
	return out
}
