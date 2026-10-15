// Package ticketmap is the application service for ticket field and status
// mapping profiles: create, edit (draft), validate against the tracker's live
// metadata, publish, roll back, preview and simulate.
//
// Design: docs/rfcs/RFC-097-ticket-field-mapping.md.
package ticketmap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	ticketmapdom "github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/safetext"
)

// IssueTypeRef is an issue type of a tracker project.
type IssueTypeRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Subtask bool   `json:"subtask"`
}

// IssueSnapshot is the current state of one tracker issue (inbound preview).
type IssueSnapshot struct {
	Key        string
	StatusID   string
	StatusName string
	Category   string
	Resolution string
	// Fields holds the mapped fields as display strings (account id for user
	// fields, YYYY-MM-DD for dates).
	Fields map[string]string
}

// Tracker is one integration's tracker, as the mapping service needs it.
type Tracker interface {
	IssueTypes(ctx context.Context, projectKey string) ([]IssueTypeRef, error)
	// ProjectMeta reads the create fields, workflow statuses, transitions
	// (when the tracker exposes them) and resolutions.
	ProjectMeta(ctx context.Context, projectKey, projectID, issueTypeID string) (*ticketmapdom.ProjectMeta, error)
	Issue(ctx context.Context, issueKey string, fieldIDs []string) (*IssueSnapshot, error)
}

// TrackerResolver opens the tracker of one integration of the tenant. It
// returns ErrNotFound for an integration of another tenant, and a
// validation error for an integration that is not a connected tracker.
type TrackerResolver interface {
	ForIntegration(ctx context.Context, tenantID, integrationID shared.ID) (Tracker, error)
}

// ScopeChecker enforces the caller's data scope on a finding (404 outside).
type ScopeChecker interface {
	AssertFinding(ctx context.Context, tenantID, findingID shared.ID) error
}

// ObjectSource loads the objects a preview renders. Task members are listed
// through the caller's data scope.
type ObjectSource interface {
	Finding(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.Finding, error)
	Asset(ctx context.Context, tenantID, assetID shared.ID) (*AssetInfo, error)
	User(ctx context.Context, tenantID, userID shared.ID) (*UserInfo, error)
	Task(ctx context.Context, tenantID, taskID shared.ID) (*remediation.Campaign, error)
	TaskMembers(ctx context.Context, tenantID, taskID shared.ID, limit int) ([]*vulnerability.Finding, int64, error)
}

// Service manages mapping profiles.
type Service struct {
	repo     ticketmapdom.Repository
	trackers TrackerResolver
	scope    ScopeChecker
	objects  ObjectSource
	webBase  string
	logger   *logger.Logger
}

// NewService builds the service.
func NewService(repo ticketmapdom.Repository, trackers TrackerResolver, scope ScopeChecker, objects ObjectSource, webBase string, log *logger.Logger) *Service {
	return &Service{repo: repo, trackers: trackers, scope: scope, objects: objects, webBase: webBase, logger: log.With("service", "ticket-mapping")}
}

// ProfileView is a profile with its published and draft versions.
type ProfileView struct {
	Profile   *ticketmapdom.Profile `json:"profile"`
	Published *ticketmapdom.Version `json:"published,omitempty"`
	Draft     *ticketmapdom.Version `json:"draft,omitempty"`
}

// CatalogView is everything the editor needs that does not depend on the
// tracker: attributes, filters, states, intents and presets.
type CatalogView struct {
	Attributes     []ticketmapdom.Attribute `json:"attributes"`
	Filters        []string                 `json:"filters"`
	States         []string                 `json:"states"`
	Intents        []IntentInfo             `json:"intents"`
	Presets        []ticketmapdom.Preset    `json:"presets"`
	Minimizations  []string                 `json:"minimizations"`
	TransformKinds []string                 `json:"transform_kinds"`
}

// IntentInfo describes an inbound intent for the editor.
type IntentInfo struct {
	Intent        ticketmapdom.Intent `json:"intent"`
	NeedsApproval bool                `json:"needs_approval"`
}

// Catalog returns the static editor data for an object kind.
func (s *Service) Catalog(kind ticketmapdom.ObjectKind) (*CatalogView, error) {
	if !kind.Valid() {
		return nil, fmt.Errorf("%w: object_kind must be finding or task", shared.ErrValidation)
	}
	intents := []ticketmapdom.Intent{
		ticketmapdom.IntentIgnore, ticketmapdom.IntentInProgress, ticketmapdom.IntentFixClaim, ticketmapdom.IntentReopen,
		ticketmapdom.IntentRequestAccept, ticketmapdom.IntentRequestFP, ticketmapdom.IntentSuggestDuplicate,
	}
	iv := make([]IntentInfo, 0, len(intents))
	for _, i := range intents {
		iv = append(iv, IntentInfo{Intent: i, NeedsApproval: i.NeedsApproval()})
	}
	return &CatalogView{
		Attributes:    ticketmapdom.Catalog(kind),
		Filters:       ticketmapdom.Filters,
		States:        ticketmapdom.OutboundStates(kind),
		Intents:       iv,
		Presets:       ticketmapdom.Presets(kind),
		Minimizations: []string{string(ticketmapdom.MinTitleOnly), string(ticketmapdom.MinSummary), string(ticketmapdom.MinFull)},
		TransformKinds: []string{"", string(ticketmapdom.TransformValueMap), string(ticketmapdom.TransformUser), string(ticketmapdom.TransformDate),
			string(ticketmapdom.TransformNumber), string(ticketmapdom.TransformList), string(ticketmapdom.TransformJoin)},
	}, nil
}

// IssueTypes lists a project's issue types through the integration.
func (s *Service) IssueTypes(ctx context.Context, tenantID, integrationID shared.ID, projectKey string) ([]IssueTypeRef, error) {
	t, err := s.trackers.ForIntegration(ctx, tenantID, integrationID)
	if err != nil {
		return nil, err
	}
	if !validProjectKey(projectKey) {
		return nil, fmt.Errorf("%w: invalid project key", shared.ErrValidation)
	}
	return t.IssueTypes(ctx, strings.ToUpper(projectKey))
}

// ProjectMeta reads a destination's live metadata.
func (s *Service) ProjectMeta(ctx context.Context, tenantID, integrationID shared.ID, projectKey, projectID, issueTypeID string) (*ticketmapdom.ProjectMeta, error) {
	t, err := s.trackers.ForIntegration(ctx, tenantID, integrationID)
	if err != nil {
		return nil, err
	}
	if !validProjectKey(projectKey) || issueTypeID == "" || len(issueTypeID) > 64 || len(projectID) > 64 {
		return nil, fmt.Errorf("%w: invalid project or issue type", shared.ErrValidation)
	}
	return t.ProjectMeta(ctx, strings.ToUpper(projectKey), projectID, issueTypeID)
}

func validProjectKey(k string) bool {
	if k == "" || len(k) > 32 {
		return false
	}
	for _, c := range k {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// liveMeta reads the destination's metadata, best-effort: nil when the
// tracker cannot be reached (validation then says what it could not check).
func (s *Service) liveMeta(ctx context.Context, p *ticketmapdom.Profile) *ticketmapdom.ProjectMeta {
	t, err := s.trackers.ForIntegration(ctx, p.TenantID, p.IntegrationID)
	if err != nil {
		s.logger.Warn("mapping: tracker unavailable", "profile_id", p.ID.String(), "error", err)
		return nil
	}
	m, err := t.ProjectMeta(ctx, p.ProjectKey, p.ProjectID, p.IssueTypeID)
	if err != nil {
		s.logger.Warn("mapping: metadata unavailable", "profile_id", p.ID.String(), "error", err)
		return nil
	}
	return m
}

// CreateProfileInput creates a profile for a destination.
type CreateProfileInput struct {
	TenantID      shared.ID
	IntegrationID shared.ID
	ObjectKind    ticketmapdom.ObjectKind
	ProjectKey    string
	ProjectID     string
	IssueTypeID   string
	IssueType     string
	Name          string
	// Preset seeds the first draft ("" = an empty mapping).
	Preset string
	By     *shared.ID
}

// CreateProfile creates a profile with a first draft (from a preset, with a
// status map proposed from the live workflow when it can be read).
func (s *Service) CreateProfile(ctx context.Context, in CreateProfileInput) (*ProfileView, []ticketmapdom.Issue, error) {
	if _, err := s.trackers.ForIntegration(ctx, in.TenantID, in.IntegrationID); err != nil {
		return nil, nil, err
	}
	p, err := ticketmapdom.NewProfile(in.TenantID, in.IntegrationID, in.ObjectKind, in.ProjectID, in.ProjectKey, in.IssueTypeID, in.IssueType, in.Name, in.By)
	if err != nil {
		return nil, nil, err
	}
	spec := ticketmapdom.Spec{Minimization: ticketmapdom.MinSummary, Fields: []ticketmapdom.Row{}}
	if in.Preset != "" {
		pr, ok := ticketmapdom.PresetByID(in.ObjectKind, in.Preset)
		if !ok {
			return nil, nil, fmt.Errorf("%w: unknown preset %q", shared.ErrValidation, in.Preset)
		}
		spec = pr.Spec
	}
	meta := s.liveMeta(ctx, p)
	if meta != nil && len(meta.Workflow.Statuses) > 0 {
		spec.Status = ticketmapdom.AutoMapStatus(in.ObjectKind, meta.Workflow)
	}
	v := &ticketmapdom.Version{ProfileID: p.ID, TenantID: p.TenantID, Version: 1, State: ticketmapdom.VersionDraft,
		Spec: spec, Snapshot: meta, Note: "created", CreatedBy: in.By, CreatedAt: p.CreatedAt}
	if err := s.repo.CreateProfile(ctx, p, v); err != nil {
		return nil, nil, err
	}
	return &ProfileView{Profile: p, Draft: v}, ticketmapdom.Validate(in.ObjectKind, spec, meta), nil
}

// GetProfile returns a profile with its published and draft versions.
func (s *Service) GetProfile(ctx context.Context, tenantID, id shared.ID) (*ProfileView, error) {
	p, err := s.repo.GetProfile(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	view := &ProfileView{Profile: p}
	if p.PublishedVersion > 0 {
		if view.Published, err = s.repo.GetVersion(ctx, tenantID, id, p.PublishedVersion); err != nil {
			return nil, err
		}
	}
	if p.DraftVersion > 0 {
		if view.Draft, err = s.repo.GetVersion(ctx, tenantID, id, p.DraftVersion); err != nil {
			return nil, err
		}
	}
	return view, nil
}

// ListProfiles lists the tenant's profiles.
func (s *Service) ListProfiles(ctx context.Context, tenantID shared.ID, f ticketmapdom.ProfileFilter, page pagination.Pagination) (pagination.Result[*ticketmapdom.Profile], error) {
	return s.repo.ListProfiles(ctx, tenantID, f, page)
}

// ListVersions lists a profile's versions.
func (s *Service) ListVersions(ctx context.Context, tenantID, id shared.ID) ([]*ticketmapdom.Version, error) {
	if _, err := s.repo.GetProfile(ctx, tenantID, id); err != nil {
		return nil, err
	}
	return s.repo.ListVersions(ctx, tenantID, id)
}

// SaveDraft stores a draft. A draft may carry validation errors; publishing
// may not. The returned issues come from the live metadata when reachable.
func (s *Service) SaveDraft(ctx context.Context, tenantID, id shared.ID, spec ticketmapdom.Spec, note string, expectedDraft int, by *shared.ID) (*ticketmapdom.Version, []ticketmapdom.Issue, error) {
	p, err := s.repo.GetProfile(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	if err := spec.CheckShape(p.ObjectKind); err != nil {
		return nil, nil, err
	}
	if len([]rune(note)) > 500 {
		return nil, nil, fmt.Errorf("%w: note is at most 500 characters", shared.ErrValidation)
	}
	meta := s.liveMeta(ctx, p)
	v, err := s.repo.SaveDraft(ctx, tenantID, id, spec, meta, note, by, expectedDraft)
	if err != nil {
		return nil, nil, err
	}
	return v, ticketmapdom.Validate(p.ObjectKind, spec, meta), nil
}

// ValidationError carries the issues that blocked a publish.
type ValidationError struct{ Issues []ticketmapdom.Issue }

func (e *ValidationError) Error() string { return "the mapping has errors" }

// Unwrap makes a ValidationError a shared validation error.
func (e *ValidationError) Unwrap() error { return shared.ErrValidation }

// Validate checks a version (0 = the open draft, else that version) against
// the live metadata.
func (s *Service) Validate(ctx context.Context, tenantID, id shared.ID, version int) ([]ticketmapdom.Issue, error) {
	p, v, err := s.version(ctx, tenantID, id, version)
	if err != nil {
		return nil, err
	}
	return ticketmapdom.Validate(p.ObjectKind, v.Spec, s.liveMeta(ctx, p)), nil
}

func (s *Service) version(ctx context.Context, tenantID, id shared.ID, version int) (*ticketmapdom.Profile, *ticketmapdom.Version, error) {
	p, err := s.repo.GetProfile(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	if version == 0 {
		version = p.DraftVersion
		if version == 0 {
			version = p.PublishedVersion
		}
	}
	if version == 0 {
		return nil, nil, fmt.Errorf("%w: the profile has no version", shared.ErrNotFound)
	}
	v, err := s.repo.GetVersion(ctx, tenantID, id, version)
	if err != nil {
		return nil, nil, err
	}
	return p, v, nil
}

// Publish publishes the open draft when it has no validation errors. The
// tracker must be reachable: a mapping is never published unchecked.
func (s *Service) Publish(ctx context.Context, tenantID, id shared.ID, draft int, by *shared.ID) (*ticketmapdom.Version, []ticketmapdom.Issue, error) {
	p, err := s.repo.GetProfile(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	if p.DraftVersion == 0 || p.DraftVersion != draft {
		return nil, nil, ticketmapdom.ErrDraftConflict
	}
	v, err := s.repo.GetVersion(ctx, tenantID, id, draft)
	if err != nil {
		return nil, nil, err
	}
	meta := s.liveMeta(ctx, p)
	if meta == nil {
		return nil, nil, fmt.Errorf("%w: the tracker could not be reached to check the mapping; try again", shared.ErrValidation)
	}
	issues := ticketmapdom.Validate(p.ObjectKind, v.Spec, meta)
	if ticketmapdom.HasErrors(issues) {
		return nil, issues, &ValidationError{Issues: issues}
	}
	// Keep the metadata the version was published against (drift baseline).
	if _, err := s.repo.SaveDraft(ctx, tenantID, id, v.Spec, meta, v.Note, v.CreatedBy, draft); err != nil {
		return nil, nil, err
	}
	pub, err := s.repo.Publish(ctx, tenantID, id, draft, by)
	if err != nil {
		return nil, nil, err
	}
	return pub, issues, nil
}

// Rollback copies an earlier version into the draft (replacing an open
// draft) so it can be reviewed and published. History is never rewritten.
func (s *Service) Rollback(ctx context.Context, tenantID, id shared.ID, version int, by *shared.ID) (*ticketmapdom.Version, []ticketmapdom.Issue, error) {
	p, err := s.repo.GetProfile(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	old, err := s.repo.GetVersion(ctx, tenantID, id, version)
	if err != nil {
		return nil, nil, err
	}
	return s.SaveDraft(ctx, tenantID, id, old.Spec, fmt.Sprintf("rollback to version %d", version), p.DraftVersion, by)
}

// DiscardDraft drops the open draft.
func (s *Service) DiscardDraft(ctx context.Context, tenantID, id shared.ID) error {
	return s.repo.DiscardDraft(ctx, tenantID, id)
}

// DeleteProfile deletes a profile (the destination falls back to the
// built-in mapping).
func (s *Service) DeleteProfile(ctx context.Context, tenantID, id shared.ID) error {
	return s.repo.DeleteProfile(ctx, tenantID, id)
}

// UpdateDryRun switches the published version between dry run and live.
func (s *Service) UpdateDryRun(ctx context.Context, tenantID, id shared.ID, dryRun bool) error {
	return s.repo.SetDryRun(ctx, tenantID, id, dryRun)
}

// Diff lists the changes between two versions of a profile.
func (s *Service) Diff(ctx context.Context, tenantID, id shared.ID, from, to int) ([]ticketmapdom.Change, error) {
	a, err := s.repo.GetVersion(ctx, tenantID, id, from)
	if err != nil {
		return nil, err
	}
	b, err := s.repo.GetVersion(ctx, tenantID, id, to)
	if err != nil {
		return nil, err
	}
	return ticketmapdom.DiffSpecs(a.Spec, b.Spec), nil
}

// CheckDrift compares the published version's metadata snapshot with the
// tracker now, and marks the profile drifted when something it uses changed.
func (s *Service) CheckDrift(ctx context.Context, tenantID, id shared.ID) ([]ticketmapdom.Issue, error) {
	p, err := s.repo.GetProfile(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if p.PublishedVersion == 0 {
		return nil, nil
	}
	v, err := s.repo.GetVersion(ctx, tenantID, id, p.PublishedVersion)
	if err != nil {
		return nil, err
	}
	live := s.liveMeta(ctx, p)
	if live == nil || v.Snapshot == nil {
		return []ticketmapdom.Issue{{Severity: ticketmapdom.IssueWarning, Code: "no_metadata", Message: "the tracker could not be reached"}}, nil
	}
	issues := ticketmapdom.Drift(*v.Snapshot, *live, v.Spec)
	issues = append(issues, ticketmapdom.Validate(p.ObjectKind, v.Spec, live)...)
	drifted := ticketmapdom.HasErrors(issues)
	if drifted != p.Drifted {
		if err := s.repo.SetDrifted(ctx, tenantID, id, drifted); err != nil {
			return nil, err
		}
	}
	return issues, nil
}

// Export renders a version as a document.
func (s *Service) Export(ctx context.Context, tenantID, id shared.ID, version int, format string) ([]byte, error) {
	p, v, err := s.version(ctx, tenantID, id, version)
	if err != nil {
		return nil, err
	}
	return ticketmapdom.Export(ticketmapdom.Document{ObjectKind: p.ObjectKind, Project: p.ProjectKey, IssueType: p.IssueType, Spec: v.Spec}, format)
}

// Import stores a document as the draft.
func (s *Service) Import(ctx context.Context, tenantID, id shared.ID, data []byte, expectedDraft int, by *shared.ID) (*ticketmapdom.Version, []ticketmapdom.Issue, error) {
	p, err := s.repo.GetProfile(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	d, err := ticketmapdom.Import(data, p.ObjectKind)
	if err != nil {
		return nil, nil, err
	}
	return s.SaveDraft(ctx, tenantID, id, d.Spec, "imported", expectedDraft, by)
}

// CopyTo copies a version to another destination's profile as its draft
// (creating the profile when needed), re-validated there.
func (s *Service) CopyTo(ctx context.Context, tenantID, id shared.ID, version int, dest CreateProfileInput) (*ProfileView, []ticketmapdom.Issue, error) {
	src, v, err := s.version(ctx, tenantID, id, version)
	if err != nil {
		return nil, nil, err
	}
	dest.TenantID = tenantID
	dest.ObjectKind = src.ObjectKind
	if dest.IntegrationID.IsZero() {
		dest.IntegrationID = src.IntegrationID
	}
	dest.Preset = ""
	view, _, err := s.CreateProfile(ctx, dest)
	if err != nil {
		return nil, nil, err
	}
	spec := v.Spec
	// The status map names workflow status ids of the source project: keep it
	// only when the destination has the same statuses, else propose afresh.
	meta := s.liveMeta(ctx, view.Profile)
	if meta != nil && view.Draft != nil && !statusIDsExist(spec.Status, meta.Workflow) {
		spec.Status = view.Draft.Spec.Status
	}
	dv, issues, err := s.SaveDraft(ctx, tenantID, view.Profile.ID, spec, fmt.Sprintf("copied from %s v%d", src.Name, v.Version), view.Profile.DraftVersion, dest.By)
	if err != nil {
		return nil, nil, err
	}
	view.Draft = dv
	return view, issues, nil
}

func statusIDsExist(m ticketmapdom.StatusMap, wf ticketmapdom.Workflow) bool {
	for _, t := range m.Outbound {
		if _, ok := wf.Status(t.StatusID); !ok {
			return false
		}
	}
	for _, r := range m.Inbound {
		if r.StatusID != "" {
			if _, ok := wf.Status(r.StatusID); !ok {
				return false
			}
		}
	}
	return true
}

// Suggest proposes rows for unmapped fields of the destination.
func (s *Service) Suggest(ctx context.Context, tenantID, id shared.ID) ([]ticketmapdom.Row, error) {
	p, v, err := s.version(ctx, tenantID, id, 0)
	if err != nil {
		return nil, err
	}
	meta := s.liveMeta(ctx, p)
	if meta == nil {
		return nil, fmt.Errorf("%w: the tracker could not be reached", shared.ErrValidation)
	}
	return ticketmapdom.SuggestRows(p.ObjectKind, v.Spec, *meta), nil
}

// ---------------------------------------------------------------------------
// Preview and simulation.

// OutboundPreview is what a version would send for one object.
type OutboundPreview struct {
	Fields  map[string]any            `json:"fields"`
	Dropped []ticketmapdom.Issue      `json:"dropped,omitempty"`
	Notes   []ticketmapdom.Issue      `json:"notes,omitempty"`
	Issues  []ticketmapdom.Issue      `json:"issues"`
	State   string                    `json:"state"`
	Status  *StatusPlan               `json:"status,omitempty"`
	Meta    *ticketmapdom.ProjectMeta `json:"-"`
}

// StatusPlan is the transition path an OpenCTEM state takes.
type StatusPlan struct {
	State  string                        `json:"state"`
	From   string                        `json:"from"`
	Target *ticketmapdom.StatusTarget    `json:"target,omitempty"`
	Steps  []ticketmapdom.TransitionStep `json:"steps,omitempty"`
	Error  string                        `json:"error,omitempty"`
}

// redactAndEncode are the platform-owned render options (redaction after
// rendering, wiki encoding).
func renderOptions(creating bool) ticketmapdom.RenderOptions {
	return ticketmapdom.RenderOptions{
		Redact:       safetext.RedactSecrets,
		EncodeBlock:  safetext.JiraWikiBlock,
		EncodeInline: safetext.JiraWikiInline,
		Table:        wikiTable,
		Creating:     creating,
	}
}

// wikiTable renders a table in wiki markup with every cell encoded.
func wikiTable(t ticketmapdom.Table) string {
	var b strings.Builder
	cell := func(s string) string {
		s = safetext.JiraWikiInline(safetext.RedactSecrets(s), safetext.MaxInlineRunes)
		return strings.ReplaceAll(s, "|", "\\|")
	}
	b.WriteString("||")
	for _, h := range t.Header {
		b.WriteString(cell(h) + "||")
	}
	for _, r := range t.Rows {
		b.WriteString("\n|")
		for _, c := range r {
			if c == "" {
				c = " "
			}
			b.WriteString(cell(c) + "|")
		}
	}
	if t.More > 0 {
		fmt.Fprintf(&b, "\n\n… and %d more findings: open the task in OpenCTEM.", t.More)
	}
	return b.String()
}

// PreviewOutbound renders a version (0 = draft, else that version) for one
// object the caller can see.
func (s *Service) PreviewOutbound(ctx context.Context, tenantID, id shared.ID, version int, objectID shared.ID, creating bool) (*OutboundPreview, error) {
	p, v, err := s.version(ctx, tenantID, id, version)
	if err != nil {
		return nil, err
	}
	values, state, err := s.values(ctx, p.ObjectKind, tenantID, objectID)
	if err != nil {
		return nil, err
	}
	meta := s.liveMeta(ctx, p)
	r := ticketmapdom.RenderOutbound(p.ObjectKind, v.Spec, values, meta, renderOptions(creating))
	out := &OutboundPreview{Fields: r.Fields, Dropped: r.Dropped, Notes: r.Notes, State: state,
		Issues: ticketmapdom.Validate(p.ObjectKind, v.Spec, meta)}
	if meta != nil {
		out.Status = planFor(v.Spec.Status, meta.Workflow, state, "")
	}
	return out, nil
}

// values loads one object's mapping values through the caller's scope.
func (s *Service) values(ctx context.Context, kind ticketmapdom.ObjectKind, tenantID, objectID shared.ID) (ticketmapdom.Values, string, error) {
	if kind == ticketmapdom.ObjectFinding {
		if err := s.scope.AssertFinding(ctx, tenantID, objectID); err != nil {
			return nil, "", err
		}
		f, err := s.objects.Finding(ctx, tenantID, objectID)
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
	c, err := s.objects.Task(ctx, tenantID, objectID)
	if err != nil {
		return nil, "", err
	}
	members, total, err := s.objects.TaskMembers(ctx, tenantID, objectID, maxTableRows)
	if err != nil {
		return nil, "", err
	}
	var user *UserInfo
	if a := c.AssignedTo(); a != nil {
		user, _ = s.objects.User(ctx, tenantID, *a)
	}
	return TaskValues(c, members, total, user, s.webBase), TaskStateOf(c), nil
}

func findingState(f *vulnerability.Finding) string {
	if f.Status() == vulnerability.FindingStatusResolved {
		return ticketmapdom.StateVerified
	}
	return string(f.Status())
}

// planFor plans the move for a state from a workflow status ("" = the first
// to-do status, where new issues start).
func planFor(m ticketmapdom.StatusMap, wf ticketmapdom.Workflow, state, from string) *StatusPlan {
	plan := &StatusPlan{State: state, From: from}
	t, ok := m.Outbound[state]
	if !ok {
		plan.Error = "this state does not move the issue"
		return plan
	}
	plan.Target = &t
	if plan.From == "" {
		for _, st := range wf.Statuses {
			if st.Category == ticketmapdom.CategoryNew {
				plan.From = st.ID
				break
			}
		}
	}
	if len(wf.Transitions) == 0 {
		plan.Error = "the tracker does not expose this workflow's transitions: the path is found on the issue when it moves"
		return plan
	}
	steps, err := wf.Plan(plan.From, t)
	if err != nil {
		plan.Error = err.Error()
		return plan
	}
	plan.Steps = steps
	return plan
}

// SimulateInput asks what happens on one move, either way.
type SimulateInput struct {
	// Outbound: the OpenCTEM state and the issue's current status.
	State      string `json:"state"`
	FromStatus string `json:"from_status_id"`
	// Inbound: the tracker status, resolution and the finding's status now.
	StatusID     string `json:"status_id"`
	Resolution   string `json:"resolution"`
	CurrentState string `json:"current_state"`
}

// Simulation is the answer of Simulate.
type Simulation struct {
	Outbound *StatusPlan            `json:"outbound,omitempty"`
	Intent   ticketmapdom.Intent    `json:"intent,omitempty"`
	Mapped   bool                   `json:"mapped"`
	Decision *ticketmapdom.Decision `json:"decision,omitempty"`
}

// Simulate answers "what would happen" for a version without touching
// anything: an outbound transition path, or an inbound intent and decision.
func (s *Service) Simulate(ctx context.Context, tenantID, id shared.ID, version int, in SimulateInput) (*Simulation, error) {
	p, v, err := s.version(ctx, tenantID, id, version)
	if err != nil {
		return nil, err
	}
	meta := s.liveMeta(ctx, p)
	out := &Simulation{}
	if in.State != "" {
		if meta == nil {
			return nil, fmt.Errorf("%w: the tracker could not be reached", shared.ErrValidation)
		}
		out.Outbound = planFor(v.Spec.Status, meta.Workflow, in.State, in.FromStatus)
	}
	if in.StatusID != "" {
		ev := ticketmapdom.StatusEvent{StatusID: in.StatusID, Resolution: in.Resolution}
		if meta != nil {
			if st, ok := meta.Workflow.Status(in.StatusID); ok {
				ev.Category = st.Category
			}
		}
		out.Intent, out.Mapped = v.Spec.Status.IntentFor(ev)
		if p.ObjectKind == ticketmapdom.ObjectFinding {
			d := ticketmapdom.DecideFinding(out.Intent, in.CurrentState)
			out.Decision = &d
		}
	}
	return out, nil
}

// InboundPreview is what a tracker issue's current state would do.
type InboundPreview struct {
	Issue    *IssueSnapshot         `json:"issue"`
	Intent   ticketmapdom.Intent    `json:"intent"`
	Mapped   bool                   `json:"mapped"`
	Decision *ticketmapdom.Decision `json:"decision,omitempty"`
	Commands []ticketmapdom.Command `json:"commands"`
}

// PreviewInbound reads an issue and shows the intent and field commands the
// version would produce for an object in currentState. It changes nothing.
func (s *Service) PreviewInbound(ctx context.Context, tenantID, id shared.ID, version int, issueKey, currentState string) (*InboundPreview, error) {
	p, v, err := s.version(ctx, tenantID, id, version)
	if err != nil {
		return nil, err
	}
	issueKey = strings.ToUpper(strings.TrimSpace(issueKey))
	if !validIssueKey(issueKey) {
		return nil, fmt.Errorf("%w: invalid issue key", shared.ErrValidation)
	}
	t, err := s.trackers.ForIntegration(ctx, tenantID, p.IntegrationID)
	if err != nil {
		return nil, err
	}
	var fields []string
	for _, r := range v.Spec.Fields {
		if r.Direction != ticketmapdom.DirOut {
			fields = append(fields, r.Target.FieldID)
		}
	}
	snap, err := t.Issue(ctx, issueKey, fields)
	if err != nil {
		return nil, err
	}
	out := &InboundPreview{Issue: snap}
	out.Intent, out.Mapped = v.Spec.Status.IntentFor(ticketmapdom.StatusEvent{StatusID: snap.StatusID, Category: snap.Category, Resolution: snap.Resolution})
	if p.ObjectKind == ticketmapdom.ObjectFinding {
		d := ticketmapdom.DecideFinding(out.Intent, currentState)
		out.Decision = &d
	}
	changes := make([]ticketmapdom.FieldChange, 0, len(snap.Fields))
	for id, val := range snap.Fields {
		changes = append(changes, ticketmapdom.FieldChange{FieldID: id, To: val})
	}
	out.Commands = ticketmapdom.EvaluateInbound(p.ObjectKind, v.Spec, changes)
	if out.Commands == nil {
		out.Commands = []ticketmapdom.Command{}
	}
	return out, nil
}

func validIssueKey(k string) bool {
	i := strings.LastIndex(k, "-")
	if i <= 0 || i == len(k)-1 || len(k) > 64 || !validProjectKey(k[:i]) {
		return false
	}
	for _, c := range k[i+1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// IsNotFound reports a missing profile, version or object.
func IsNotFound(err error) bool { return errors.Is(err, shared.ErrNotFound) }
