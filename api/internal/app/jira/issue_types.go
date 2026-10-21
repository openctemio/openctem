package jira

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Issue type per kind of issue (docs/architecture/ticketing-integration.md,
// "Issue types"): an organization files findings, remediation tasks and
// campaign epics as different issue types, custom ones included, chosen in
// the console from the issue types of the integration's default project.
// The fields and the workflow of a type are mapped by a published mapping
// profile of that type (RFC-097); the choice here only says which type.

// The kinds of issue OpenCTEM creates.
const (
	IssueKindFinding = "finding"
	IssueKindTask    = "task"
	IssueKindEpic    = "epic"
)

// stockIssueTypes is the type of a kind nobody chose: a stock type that
// every Jira project template has.
var stockIssueTypes = map[string]string{
	IssueKindFinding: "Bug",
	IssueKindTask:    "Task",
	IssueKindEpic:    "Epic",
}

// IssueKinds lists the kinds in a stable order.
func IssueKinds() []string { return []string{IssueKindFinding, IssueKindTask, IssueKindEpic} }

// IssueTypeChoice is the issue type chosen for a kind: its id in the
// integration's default project (authoritative there, and unaffected by a
// rename) and its name (sent for any other project, where a team-managed
// project has its own ids).
type IssueTypeChoice struct {
	ID   string
	Name string
}

// IssueTypeRef names the issue type a create sends: by id when ID is set,
// by name otherwise.
type IssueTypeRef struct {
	ID   string
	Name string
}

// Lookup is what identifies the type to a mapping profile (an id or a name).
func (r IssueTypeRef) Lookup() string {
	if r.ID != "" {
		return r.ID
	}
	return r.Name
}

// Label is the type for messages: the name, else the id.
func (r IssueTypeRef) Label() string {
	if r.Name != "" {
		return r.Name
	}
	return r.ID
}

// IssueTypeFor returns the issue type of a kind for an issue in projectKey:
// the chosen type by id in the default project, by name in any other
// project, and the kind's stock type when nothing was chosen.
func (m MappingConfig) IssueTypeFor(kind, projectKey string) IssueTypeRef {
	c := m.IssueTypes[kind]
	name := strings.TrimSpace(c.Name)
	if c.ID != "" && m.DefaultProjectKey != "" && strings.EqualFold(strings.TrimSpace(projectKey), m.DefaultProjectKey) {
		return IssueTypeRef{ID: c.ID, Name: name}
	}
	if name != "" {
		return IssueTypeRef{Name: name}
	}
	return IssueTypeRef{Name: stockIssueTypes[kind]}
}

// issueTypeIDRe is the shape of a Jira issue type id (a number).
var issueTypeIDRe = regexp.MustCompile(`^[0-9]{1,20}$`)

// maxIssueTypeName bounds a stored issue type name.
const maxIssueTypeName = 255

// parseIssueTypes reads config.ticketing.issue_types; malformed entries are
// skipped (saving them is refused by ValidateTicketingConfig).
func parseIssueTypes(raw any) map[string]IssueTypeChoice {
	out := map[string]IssueTypeChoice{}
	obj, ok := raw.(map[string]any)
	if !ok {
		return out
	}
	for kind, v := range obj {
		if _, known := stockIssueTypes[kind]; !known {
			continue
		}
		e, ok := v.(map[string]any)
		if !ok {
			continue
		}
		id := strings.TrimSpace(stringFromAny(e["id"]))
		name := strings.TrimSpace(stringFromAny(e["name"]))
		if id != "" && !issueTypeIDRe.MatchString(id) {
			id = ""
		}
		if len(name) > maxIssueTypeName {
			name = ""
		}
		if id == "" && name == "" {
			continue
		}
		out[kind] = IssueTypeChoice{ID: id, Name: name}
	}
	return out
}

// validateIssueTypes checks the shape of config.ticketing.issue_types.
func validateIssueTypes(section map[string]any) error {
	raw, ok := section["issue_types"]
	if !ok || raw == nil {
		return nil
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: ticketing.issue_types must be an object of kind to issue type", shared.ErrValidation)
	}
	for kind, v := range obj {
		if _, known := stockIssueTypes[kind]; !known {
			return fmt.Errorf("%w: ticketing.issue_types: unknown kind %q (finding, task or epic)", shared.ErrValidation, kind)
		}
		e, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: ticketing.issue_types.%s must be an object with id and name", shared.ErrValidation, kind)
		}
		for k := range e {
			if k != "id" && k != "name" {
				return fmt.Errorf("%w: ticketing.issue_types.%s: unknown key %q", shared.ErrValidation, kind, k)
			}
		}
		id, idOK := e["id"].(string)
		name, nameOK := e["name"].(string)
		if (e["id"] != nil && !idOK) || (e["name"] != nil && !nameOK) {
			return fmt.Errorf("%w: ticketing.issue_types.%s: id and name must be strings", shared.ErrValidation, kind)
		}
		if id = strings.TrimSpace(id); id != "" && !issueTypeIDRe.MatchString(id) {
			return fmt.Errorf("%w: ticketing.issue_types.%s.id must be a Jira issue type id", shared.ErrValidation, kind)
		}
		if len(strings.TrimSpace(name)) > maxIssueTypeName {
			return fmt.Errorf("%w: ticketing.issue_types.%s.name is too long", shared.ErrValidation, kind)
		}
	}
	return nil
}

// IssueTypesChanged reports whether a config change touches what the live
// issue type check depends on: the default project or the issue types.
func IssueTypesChanged(before, after map[string]any) bool {
	b, a := ParseMappingConfig(before), ParseMappingConfig(after)
	if !strings.EqualFold(b.DefaultProjectKey, a.DefaultProjectKey) || len(b.IssueTypes) != len(a.IssueTypes) {
		return true
	}
	for k, v := range a.IssueTypes {
		if b.IssueTypes[k] != v {
			return true
		}
	}
	return false
}

// FieldRejectedError: the tracker refused an issue because of named fields
// (an issue type that no longer exists in the project, a field that became
// required, a removed option). Only field ids are kept: the tracker's own
// messages are not stored or echoed.
type FieldRejectedError struct {
	Fields []string
}

func (e *FieldRejectedError) Error() string {
	return fmt.Sprintf("the tracker refused the issue because of these fields: %s; check the issue type and the field mapping of this integration (Settings → Integrations → Ticketing)",
		strings.Join(e.Fields, ", "))
}

// Unwrap makes the refusal a validation error for the caller.
func (e *FieldRejectedError) Unwrap() error { return shared.ErrValidation }

// Permanent: retrying the same create cannot succeed.
func (e *FieldRejectedError) Permanent() bool { return true }

// fieldIDRe is the shape of a Jira field id kept from a refusal.
var fieldIDRe = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)

// maxRejectedFields bounds the field ids kept from one refusal.
const maxRejectedFields = 20

// NewFieldRejectedError keeps the well-formed field ids (sorted, capped).
// nil when none is well formed.
func NewFieldRejectedError(fields []string) *FieldRejectedError {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if fieldIDRe.MatchString(f) && len(out) < maxRejectedFields {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return &FieldRejectedError{Fields: out}
}

// IssueTypeHealth records why creates of a kind fail on an integration (the
// integration's ticketing health, shown on the ticketing page), or clears it.
type IssueTypeHealth interface {
	// RecordIssueTypeProblem stores the problem of a kind; nil clears it.
	RecordIssueTypeProblem(ctx context.Context, tenantID, integrationID shared.ID, kind string, problem *IssueTypeProblem) error
}

// IssueTypeProblem is a kind's create refusal: the type and the fields.
type IssueTypeProblem struct {
	IssueType string   `json:"issue_type"`
	Fields    []string `json:"fields"`
}

// SetIssueTypeHealth wires the ticketing health store.
func (s *SyncService) SetIssueTypeHealth(h IssueTypeHealth) { s.typeHealth = h }

// noteCreate records the outcome of a built-in create of a kind: a field
// refusal is stored as the integration's health for that kind, a success
// clears it. Best effort: the create's own result is what the caller gets.
func (s *SyncService) noteCreate(ctx context.Context, tenantID, integrationID shared.ID, kind string, typ IssueTypeRef, err error) {
	if s.typeHealth == nil || integrationID.IsZero() {
		return
	}
	var problem *IssueTypeProblem
	var fr *FieldRejectedError
	switch {
	case err == nil:
	case errors.As(err, &fr):
		problem = &IssueTypeProblem{IssueType: typ.Label(), Fields: fr.Fields}
	default:
		return // not a field problem: nothing to record or clear
	}
	if herr := s.typeHealth.RecordIssueTypeProblem(ctx, tenantID, integrationID, kind, problem); herr != nil {
		s.logger.Warn("record ticketing health", "integration_id", integrationID.String(), "kind", kind, "error", logger.SanitizeValue(herr.Error()))
	}
}
