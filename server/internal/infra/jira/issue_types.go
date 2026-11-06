package jira

import (
	"context"
	"fmt"
	"strings"
	"time"

	appjira "github.com/openctemio/openctem/api/internal/app/jira"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/safetext"
)

// The live check of an integration's issue types
// (docs/architecture/ticketing-integration.md, "Issue types") and the store
// of create refusals per kind.

// ProfileCoverage reports whether a destination has a published mapping
// profile (implemented by the ticket mapping service).
type ProfileCoverage func(ctx context.Context, tenantID, integrationID shared.ID, kind ticketmap.ObjectKind, projectKey, issueTypeID string) (bool, error)

// SetProfileCoverage wires the profile lookup of the issue type check.
func (r *IntegrationClientResolver) SetProfileCoverage(f ProfileCoverage) { r.coverage = f }

// builtinCreateFields are the fields the built-in create fills (or Jira
// fills itself): a required field outside this set needs a mapping profile.
var builtinCreateFields = map[string]bool{
	"summary": true, "description": true, "issuetype": true, "project": true,
	"reporter": true, "priority": true, "labels": true,
}

// issueKindLabels name a kind in the check's messages.
var issueKindLabels = map[string]string{
	appjira.IssueKindFinding: "finding",
	appjira.IssueKindTask:    "remediation task",
	appjira.IssueKindEpic:    "campaign epic",
}

// CheckTicketingIssueTypes checks the issue types chosen in an integration's
// ticketing config against Jira, with the integration's own base URL and
// credentials (intg is the state about to be saved, loaded tenant-scoped by
// the caller): each chosen type must exist in the default project, must not
// be a sub-task type, and its required fields must be filled by OpenCTEM —
// the built-in create, or a published mapping profile of that kind and type.
// Jira not answering refuses the choice: it cannot be verified.
func (r *IntegrationClientResolver) CheckTicketingIssueTypes(ctx context.Context, intg *integration.Integration) error {
	if intg.Provider() != integration.ProviderJira {
		return nil
	}
	cfg := appjira.ParseMappingConfig(intg.Config())
	if len(cfg.IssueTypes) == 0 {
		return nil
	}
	chosen := false
	for _, c := range cfg.IssueTypes {
		if c.ID != "" {
			chosen = true
		}
	}
	if !chosen {
		return nil // names only (kept from before ids): checked by the next create
	}
	project := cfg.DefaultProjectKey
	if project == "" {
		return fmt.Errorf("%w: choose a default project before choosing issue types", shared.ErrValidation)
	}
	c, err := r.buildRawClient(intg)
	if err != nil {
		return fmt.Errorf("%w: the issue types cannot be verified: %v", shared.ErrValidation, err)
	}
	types, err := c.ListIssueTypes(ctx, project)
	if err != nil {
		r.logger.Warn("issue type check: list issue types", "integration_id", intg.ID().String(), "error", err)
		return fmt.Errorf("%w: the issue types of project %s could not be read from Jira; check the connection and try again", shared.ErrValidation, project)
	}
	for _, kind := range appjira.IssueKinds() {
		choice, ok := cfg.IssueTypes[kind]
		if !ok || choice.ID == "" {
			continue
		}
		if err := r.checkIssueType(ctx, c, intg, kind, project, choice, types); err != nil {
			return err
		}
	}
	return nil
}

func (r *IntegrationClientResolver) checkIssueType(ctx context.Context, c *Client, intg *integration.Integration, kind, project string, choice appjira.IssueTypeChoice, types []IssueTypeRef) error {
	label := issueKindLabels[kind]
	var found *IssueTypeRef
	for i := range types {
		if types[i].ID == choice.ID {
			found = &types[i]
			break
		}
	}
	if found == nil {
		return fmt.Errorf("%w: the issue type chosen for %s issues (id %s) does not exist in project %s", shared.ErrValidation, label, choice.ID, project)
	}
	name := safetext.SingleLine(found.Name, 80)
	if found.Subtask {
		return fmt.Errorf("%w: %q is a sub-task type and cannot be used for %s issues (a sub-task needs a parent issue)", shared.ErrValidation, name, label)
	}
	fields, err := c.ListCreateFields(ctx, project, choice.ID)
	if err != nil {
		r.logger.Warn("issue type check: list create fields", "integration_id", intg.ID().String(), "error", err)
		return fmt.Errorf("%w: the fields of %q in project %s could not be read from Jira; check the connection and try again", shared.ErrValidation, name, project)
	}
	var missing []string
	for _, f := range fields {
		if f.Required && !f.HasDefault && !builtinCreateFields[f.ID] {
			missing = append(missing, safetext.SingleLine(f.Name, 60))
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if kind != appjira.IssueKindEpic && r.coverage != nil {
		covered, err := r.coverage(ctx, intg.TenantID(), intg.ID(), ticketmap.ObjectKind(kind), project, choice.ID)
		if err != nil {
			return fmt.Errorf("check the field mapping: %w", err)
		}
		if covered {
			return nil
		}
	}
	if len(missing) > 10 {
		missing = append(missing[:10], "…")
	}
	if kind == appjira.IssueKindEpic {
		return fmt.Errorf("%w: %q requires fields OpenCTEM does not fill for campaign epics (%s); choose another type", shared.ErrValidation, name, strings.Join(missing, ", "))
	}
	return fmt.Errorf("%w: %q requires fields OpenCTEM does not fill (%s); publish a ticket field mapping for %s issues of this type in project %s first",
		shared.ErrValidation, name, strings.Join(missing, ", "), label, project)
}

// buildRawClient builds the Jira client of an integration.
func (r *IntegrationClientResolver) buildRawClient(intg *integration.Integration) (*Client, error) {
	baseURL := siteOf(intg)
	if baseURL == "" {
		return nil, fmt.Errorf("integration %s has no base URL", intg.ID())
	}
	email, token, err := r.resolveCredentials(intg)
	if err != nil {
		return nil, err
	}
	if r.newClient != nil {
		return r.newClient(baseURL, email, token)
	}
	return NewClient(baseURL, email, token)
}

// HealthRecorder stores one kind's ticketing health on an integration
// (implemented by the integration repository).
type HealthRecorder interface {
	RecordTicketingHealth(ctx context.Context, tenantID, id shared.ID, kind string, problem any) error
}

// IssueTypeHealthStore implements the sync service's ticketing health on the
// integration's metadata.
type IssueTypeHealthStore struct{ Repo HealthRecorder }

// healthEntry is the stored problem of a kind.
type healthEntry struct {
	IssueType string    `json:"issue_type"`
	Fields    []string  `json:"fields"`
	At        time.Time `json:"at"`
}

// RecordIssueTypeProblem stores (or, with nil, clears) a kind's problem.
func (h IssueTypeHealthStore) RecordIssueTypeProblem(ctx context.Context, tenantID, integrationID shared.ID, kind string, problem *appjira.IssueTypeProblem) error {
	if problem == nil {
		return h.Repo.RecordTicketingHealth(ctx, tenantID, integrationID, kind, nil)
	}
	return h.Repo.RecordTicketingHealth(ctx, tenantID, integrationID, kind, healthEntry{
		IssueType: safetext.SingleLine(problem.IssueType, 120), Fields: problem.Fields, At: time.Now().UTC(),
	})
}
