package integration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	appticketmap "github.com/openctemio/openctem/api/internal/app/ticketmap"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The ticket mapping profiles (docs/rfcs/RFC-097-ticket-field-mapping.md):
// tenant isolation of profiles, versions and integrations; the draft →
// publish → rollback flow; publishing refuses a mapping with errors; a
// preview never renders an object outside the caller's scope; an inbound
// mapping never escalates.

type tmFixture struct {
	db      *sql.DB
	repo    *postgres.TicketMappingRepository
	svc     *appticketmap.Service
	tenantA shared.ID
	tenantB shared.ID
	intgA   shared.ID
	intgB   shared.ID
	scope   *tmScope
	objects *tmObjects
}

type tmTracker struct{ meta *ticketmap.ProjectMeta }

func (t tmTracker) IssueTypes(context.Context, string) ([]appticketmap.IssueTypeRef, error) {
	return []appticketmap.IssueTypeRef{{ID: "10001", Name: "Bug"}}, nil
}

func (t tmTracker) ProjectMeta(context.Context, string, string, string) (*ticketmap.ProjectMeta, error) {
	m := *t.meta
	return &m, nil
}

func (t tmTracker) Issue(_ context.Context, key string, _ []string) (*appticketmap.IssueSnapshot, error) {
	return &appticketmap.IssueSnapshot{Key: key, StatusID: "10", Category: "done", Resolution: "Won't Do",
		Fields: map[string]string{"assignee": "acc-7", "duedate": "2027-01-01", "priority": "Highest"}}, nil
}

// tmTrackers resolves an integration only for its own tenant.
type tmTrackers struct {
	owner map[shared.ID]shared.ID // integration → tenant
	meta  *ticketmap.ProjectMeta
}

func (r tmTrackers) ForIntegration(_ context.Context, tenantID, integrationID shared.ID) (appticketmap.Tracker, error) {
	if r.owner[integrationID] != tenantID {
		return nil, shared.ErrNotFound
	}
	return tmTracker{meta: r.meta}, nil
}

type tmScope struct {
	hidden     map[shared.ID]bool
	restricted bool
}

func (s *tmScope) FilterFindings(_ context.Context, _ shared.ID, ids []shared.ID) (func(shared.ID) bool, bool, error) {
	return func(id shared.ID) bool { return !s.hidden[id] }, s.restricted, nil
}

func (s *tmScope) AssertFinding(_ context.Context, _ shared.ID, id shared.ID) error {
	if s.hidden[id] {
		return shared.ErrNotFound
	}
	return nil
}

type tmObjects struct {
	findings map[shared.ID]*vulnerability.Finding
	tasks    map[shared.ID]*remediation.Task
	members  map[shared.ID][]*vulnerability.Finding
}

func (o *tmObjects) Finding(_ context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error) {
	f, ok := o.findings[id]
	if !ok || f.TenantID() != tenantID {
		return nil, shared.ErrNotFound
	}
	return f, nil
}
func (o *tmObjects) Asset(context.Context, shared.ID, shared.ID) (*appticketmap.AssetInfo, error) {
	return &appticketmap.AssetInfo{Name: "api-payments", Type: "service", Criticality: "high"}, nil
}
func (o *tmObjects) User(context.Context, shared.ID, shared.ID) (*appticketmap.UserInfo, error) {
	return nil, shared.ErrNotFound
}
func (o *tmObjects) Task(_ context.Context, tenantID, id shared.ID) (*remediation.Task, error) {
	c, ok := o.tasks[id]
	if !ok || c.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return c, nil
}

// TaskMembers returns every member, unfiltered, so the test proves the
// service filters by scope itself.
func (o *tmObjects) TaskMembers(_ context.Context, _, id shared.ID, _ int) ([]*vulnerability.Finding, int64, error) {
	m := o.members[id]
	return m, int64(len(m)), nil
}

func tmMeta() *ticketmap.ProjectMeta {
	return &ticketmap.ProjectMeta{ProjectKey: "SEC", IssueTypeID: "10001", IssueType: "Bug",
		Fields: []ticketmap.FieldMeta{
			{ID: "summary", Name: "Summary", Required: true, Schema: ticketmap.FieldSchema{Type: "string"}},
			{ID: "description", Name: "Description", Schema: ticketmap.FieldSchema{Type: "string"}},
			{ID: "priority", Name: "Priority", Schema: ticketmap.FieldSchema{Type: "priority"}, AllowedValues: []ticketmap.AllowedValue{
				{ID: "1", Name: "Highest"}, {ID: "2", Name: "High"}, {ID: "3", Name: "Medium"}, {ID: "4", Name: "Low"}, {ID: "5", Name: "Lowest"}}},
			{ID: "labels", Name: "Labels", Schema: ticketmap.FieldSchema{Type: "array", Items: "string"}},
			{ID: "duedate", Name: "Due date", Schema: ticketmap.FieldSchema{Type: "date"}},
			{ID: "assignee", Name: "Assignee", Schema: ticketmap.FieldSchema{Type: "user"}},
		},
		Workflow: ticketmap.Workflow{
			Statuses: []ticketmap.WorkflowStatus{{ID: "1", Name: "To Do", Category: "new"}, {ID: "3", Name: "In Progress", Category: "indeterminate"}, {ID: "10", Name: "Done", Category: "done"}},
			Transitions: []ticketmap.WorkflowTransition{
				{ID: "11", Name: "Start", From: []string{"1"}, To: "3"},
				{ID: "21", Name: "Finish", From: []string{"3"}, To: "10", Fields: []ticketmap.TransitionField{{ID: "resolution", Name: "Resolution", Required: true}}},
				{ID: "31", Name: "Reopen", From: []string{"10"}, To: "1"},
			},
			Resolutions: []ticketmap.AllowedValue{{ID: "1", Name: "Done"}, {ID: "2", Name: "Won't Do"}},
		},
	}
}

func newTMFixture(t *testing.T) tmFixture {
	t.Helper()
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping ticket mapping DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		testdb.Skipf(t, "database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	f := tmFixture{db: db, tenantA: shared.NewID(), tenantB: shared.NewID(), intgA: shared.NewID(), intgB: shared.NewID()}
	for _, tn := range []struct{ tid, iid shared.ID }{{f.tenantA, f.intgA}, {f.tenantB, f.intgB}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'Mapping IT', $2)`,
			tn.tid.String(), "tm-it-"+strings.ReplaceAll(uuid.NewString()[:13], "-", "")); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO integrations (id, tenant_id, name, category, provider, status, base_url)
			VALUES ($1, $2, 'jira', 'ticketing', 'jira', 'connected', 'https://example.atlassian.net')`, tn.iid.String(), tn.tid.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tid := range []shared.ID{f.tenantA, f.tenantB} {
			_, _ = db.ExecContext(bg, `DELETE FROM ticket_mapping_profiles WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(bg, `DELETE FROM integrations WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tid.String())
		}
	})
	f.repo = postgres.NewTicketMappingRepository(&postgres.DB{DB: db})
	f.scope = &tmScope{hidden: map[shared.ID]bool{}}
	f.objects = &tmObjects{findings: map[shared.ID]*vulnerability.Finding{}, tasks: map[shared.ID]*remediation.Task{}, members: map[shared.ID][]*vulnerability.Finding{}}
	trackers := tmTrackers{owner: map[shared.ID]shared.ID{f.intgA: f.tenantA, f.intgB: f.tenantB}, meta: tmMeta()}
	f.svc = appticketmap.NewService(f.repo, trackers, f.scope, f.objects, "https://app.example.test", logger.NewNop())
	return f
}

func (f tmFixture) create(t *testing.T, tid, iid shared.ID, preset string) *appticketmap.ProfileView {
	t.Helper()
	v, _, err := f.svc.CreateProfile(context.Background(), appticketmap.CreateProfileInput{
		TenantID: tid, IntegrationID: iid, ObjectKind: ticketmap.ObjectFinding,
		ProjectKey: "sec", IssueTypeID: "10001", IssueType: "Bug", Preset: preset,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return v
}

func TestTicketMapping_TenantIsolation(t *testing.T) {
	f := newTMFixture(t)
	ctx := context.Background()

	// A tenant cannot create a profile on another tenant's integration.
	if _, _, err := f.svc.CreateProfile(ctx, appticketmap.CreateProfileInput{TenantID: f.tenantA, IntegrationID: f.intgB,
		ObjectKind: ticketmap.ObjectFinding, ProjectKey: "SEC", IssueTypeID: "10001"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant integration: want not found, got %v", err)
	}

	a := f.create(t, f.tenantA, f.intgA, "security_bug")
	if a.Profile.ProjectKey != "SEC" || a.Draft == nil || len(a.Draft.Spec.Status.Outbound) == 0 {
		t.Fatalf("profile: %+v", a)
	}
	// Tenant B sees nothing of tenant A: get, versions, draft save, publish, delete, list.
	if _, err := f.svc.GetProfile(ctx, f.tenantB, a.Profile.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("get: %v", err)
	}
	if _, err := f.svc.ListVersions(ctx, f.tenantB, a.Profile.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("versions: %v", err)
	}
	if _, _, err := f.svc.SaveDraft(ctx, f.tenantB, a.Profile.ID, a.Draft.Spec, "", a.Profile.DraftVersion, nil); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("save: %v", err)
	}
	if _, _, err := f.svc.Publish(ctx, f.tenantB, a.Profile.ID, a.Profile.DraftVersion, nil); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("publish: %v", err)
	}
	if err := f.svc.DeleteProfile(ctx, f.tenantB, a.Profile.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("delete: %v", err)
	}
	list, err := f.svc.ListProfiles(ctx, f.tenantB, ticketmap.ProfileFilter{}, pagination.New(1, 50))
	if err != nil || list.Total != 0 {
		t.Fatalf("list B: %v %d", err, list.Total)
	}
	if _, err := f.repo.GetVersion(ctx, f.tenantB, a.Profile.ID, 1); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("version read across tenants: %v", err)
	}
	// One profile per destination.
	if _, _, err := f.svc.CreateProfile(ctx, appticketmap.CreateProfileInput{TenantID: f.tenantA, IntegrationID: f.intgA,
		ObjectKind: ticketmap.ObjectFinding, ProjectKey: "SEC", IssueTypeID: "10001"}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate destination: %v", err)
	}
}

func TestTicketMapping_DraftPublishRollback(t *testing.T) {
	f := newTMFixture(t)
	ctx := context.Background()
	a := f.create(t, f.tenantA, f.intgA, "security_bug")
	id := a.Profile.ID

	// A draft with an error saves, but does not publish.
	bad := a.Draft.Spec
	bad.Fields = append([]ticketmap.Row{}, bad.Fields...)
	bad.Fields = append(bad.Fields, ticketmap.Row{ID: "sev-in", Source: ticketmap.Source{Kind: ticketmap.SourceAttr, Attr: "finding.severity"},
		Target: ticketmap.Target{FieldID: "priority"}, Direction: ticketmap.DirIn})
	v, issues, err := f.svc.SaveDraft(ctx, f.tenantA, id, bad, "bad", 1, nil)
	if err != nil || v.Version != 1 || !ticketmap.HasErrors(issues) {
		t.Fatalf("save bad draft: %v %+v", err, issues)
	}
	var ve *appticketmap.ValidationError
	if _, _, err := f.svc.Publish(ctx, f.tenantA, id, 1, nil); !errors.As(err, &ve) {
		t.Fatalf("publish with errors: want ValidationError, got %v", err)
	}
	// A stale editor is refused.
	if _, _, err := f.svc.SaveDraft(ctx, f.tenantA, id, a.Draft.Spec, "", 0, nil); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale draft: %v", err)
	}
	// Fix and publish v1.
	if _, _, err := f.svc.SaveDraft(ctx, f.tenantA, id, a.Draft.Spec, "good", 1, nil); err != nil {
		t.Fatal(err)
	}
	pub, _, err := f.svc.Publish(ctx, f.tenantA, id, 1, nil)
	if err != nil || pub.State != ticketmap.VersionPublished || pub.Snapshot == nil {
		t.Fatalf("publish v1: %v %+v", err, pub)
	}
	// v2: change the summary, publish; v1 becomes superseded.
	spec2 := a.Draft.Spec
	spec2.Fields = append([]ticketmap.Row{}, spec2.Fields...)
	spec2.Fields[0].Source.Template = "{{ finding.title }}"
	if v2, _, err := f.svc.SaveDraft(ctx, f.tenantA, id, spec2, "v2", 0, nil); err != nil || v2.Version != 2 {
		t.Fatalf("draft v2: %v %+v", err, v2)
	}
	if _, _, err := f.svc.Publish(ctx, f.tenantA, id, 2, nil); err != nil {
		t.Fatal(err)
	}
	vs, _ := f.svc.ListVersions(ctx, f.tenantA, id)
	if len(vs) != 2 || vs[0].State != ticketmap.VersionPublished || vs[1].State != ticketmap.VersionSuperseded {
		t.Fatalf("versions: %+v", vs)
	}
	changes, err := f.svc.Diff(ctx, f.tenantA, id, 1, 2)
	if err != nil || len(changes) != 1 || changes[0].Key != "summary" {
		t.Fatalf("diff: %v %+v", err, changes)
	}
	// Rollback to v1 → draft v3 with v1's spec; publish it.
	rb, _, err := f.svc.Rollback(ctx, f.tenantA, id, 1, nil)
	if err != nil || rb.Version != 3 || rb.Spec.Fields[0].Source.Template == "{{ finding.title }}" {
		t.Fatalf("rollback: %v %+v", err, rb)
	}
	if _, _, err := f.svc.Publish(ctx, f.tenantA, id, 3, nil); err != nil {
		t.Fatal(err)
	}
	view, _ := f.svc.GetProfile(ctx, f.tenantA, id)
	if view.Profile.PublishedVersion != 3 || view.Draft != nil {
		t.Fatalf("after rollback: %+v", view.Profile)
	}
	// Export → import round trip as a new draft.
	doc, err := f.svc.Export(ctx, f.tenantA, id, 3, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if iv, _, err := f.svc.Import(ctx, f.tenantA, id, doc, 0, nil); err != nil || iv.Version != 4 {
		t.Fatalf("import: %v", err)
	}
}

func TestTicketMapping_PreviewRespectsScopeAndRedacts(t *testing.T) {
	f := newTMFixture(t)
	ctx := context.Background()
	a := f.create(t, f.tenantA, f.intgA, "security_bug")

	mk := func(tid shared.ID, title string) *vulnerability.Finding {
		fd, err := vulnerability.NewFinding(tid, shared.NewID(), vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh, title)
		if err != nil {
			t.Fatal(err)
		}
		f.objects.findings[fd.ID()] = fd
		return fd
	}
	visible := mk(f.tenantA, "Hard-coded key AKIAABCDEFGHIJKLMNOP in config")
	hidden := mk(f.tenantA, "Hidden")
	f.scope.hidden[hidden.ID()] = true
	other := mk(f.tenantB, "Other tenant")

	p, err := f.svc.PreviewOutbound(ctx, f.tenantA, a.Profile.ID, 0, visible.ID(), true)
	if err != nil {
		t.Fatal(err)
	}
	summary, _ := p.Fields["summary"].(string)
	if strings.Contains(summary, "AKIA") || !strings.Contains(summary, "HIGH") {
		t.Fatalf("summary not redacted/rendered: %q", summary)
	}
	if pr, _ := p.Fields["priority"].(map[string]string); pr["id"] != "2" {
		t.Fatalf("priority: %v", p.Fields["priority"])
	}
	if _, err := f.svc.PreviewOutbound(ctx, f.tenantA, a.Profile.ID, 0, hidden.ID(), true); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("out-of-scope finding: %v", err)
	}
	if _, err := f.svc.PreviewOutbound(ctx, f.tenantA, a.Profile.ID, 0, other.ID(), true); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other tenant's finding: %v", err)
	}
}

func TestTicketMapping_InboundNeverEscalatesAndSimulates(t *testing.T) {
	f := newTMFixture(t)
	ctx := context.Background()
	a := f.create(t, f.tenantA, f.intgA, "security_bug")

	in, err := f.svc.PreviewInbound(ctx, f.tenantA, a.Profile.ID, 0, "sec-12", ticketmap.StateConfirmed)
	if err != nil {
		t.Fatal(err)
	}
	// Done + Won't Do → a risk-acceptance REQUEST, four-eyes.
	if in.Intent != ticketmap.IntentRequestAccept || in.Decision == nil || !in.Decision.NeedsApproval {
		t.Fatalf("intent: %+v %+v", in.Intent, in.Decision)
	}
	// Only assignee (assign) and due date (request) come in; priority never does.
	for _, c := range in.Commands {
		switch c.Attr {
		case "finding.assignee":
			if c.Capability != ticketmap.InboundAssign {
				t.Fatalf("assignee capability %s", c.Capability)
			}
		case "finding.sla_deadline":
			if !c.NeedsApproval {
				t.Fatal("a due date must become a request")
			}
		default:
			t.Fatalf("unexpected inbound command %+v", c)
		}
	}
	// Simulator: verified → To Do → In Progress → Done (resolution Done).
	sim, err := f.svc.Simulate(ctx, f.tenantA, a.Profile.ID, 0, appticketmap.SimulateInput{State: ticketmap.StateVerified})
	if err != nil || sim.Outbound == nil || len(sim.Outbound.Steps) != 2 || sim.Outbound.Steps[1].Fields["resolution"] != "Done" {
		t.Fatalf("simulate: %v %+v", err, sim.Outbound)
	}
	// Closed in Jira while OpenCTEM verifies: no ping-pong.
	sim, err = f.svc.Simulate(ctx, f.tenantA, a.Profile.ID, 0, appticketmap.SimulateInput{StatusID: "10", Resolution: "Done", CurrentState: ticketmap.StateFixApplied})
	if err != nil || sim.Decision == nil || sim.Decision.Command != "" {
		t.Fatalf("simulate inbound: %v %+v", err, sim.Decision)
	}
}

func TestTicketMapping_EngineUsesOnlyThePublishedProfileOfTheTenant(t *testing.T) {
	f := newTMFixture(t)
	ctx := context.Background()
	a := f.create(t, f.tenantA, f.intgA, "security_bug")
	fd, err := vulnerability.NewFinding(f.tenantA, shared.NewID(), vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh, "SQL injection")
	if err != nil {
		t.Fatal(err)
	}
	f.objects.findings[fd.ID()] = fd

	// Nothing published yet: the built-in path applies.
	if pc, err := f.svc.RenderFindingCreate(ctx, f.tenantA, f.intgA, "SEC", "Bug", fd.ID()); err != nil || pc != nil {
		t.Fatalf("draft only: %v %v", pc, err)
	}
	if _, _, err := f.svc.Publish(ctx, f.tenantA, a.Profile.ID, 1, nil); err != nil {
		t.Fatal(err)
	}
	pc, err := f.svc.RenderFindingCreate(ctx, f.tenantA, f.intgA, "sec", "bug", fd.ID())
	if err != nil || pc == nil || pc.IssueTypeID != "10001" || pc.Fields["summary"] == nil {
		t.Fatalf("published: %+v %v", pc, err)
	}
	// Another tenant (or another integration) never gets this profile.
	if pc, err := f.svc.RenderFindingCreate(ctx, f.tenantB, f.intgA, "SEC", "Bug", fd.ID()); err != nil || pc != nil {
		t.Fatalf("cross-tenant: %+v %v", pc, err)
	}
	if pc, err := f.svc.RenderFindingCreate(ctx, f.tenantA, f.intgB, "SEC", "Bug", fd.ID()); err != nil || pc != nil {
		t.Fatalf("other integration: %+v %v", pc, err)
	}
	// Status: a new finding is not mapped by the preset (no move); dry run is carried.
	st, err := f.svc.FindingStatusTarget(ctx, f.tenantA, f.intgA, "SEC", fd.ID())
	if err != nil || st == nil || st.State != "new" || st.Target != nil || len(st.Workflow.Statuses) == 0 {
		t.Fatalf("status: %+v %v", st, err)
	}
	if err := f.svc.UpdateDryRun(ctx, f.tenantA, a.Profile.ID, true); err != nil {
		t.Fatal(err)
	}
	if pc, _ := f.svc.RenderFindingCreate(ctx, f.tenantA, f.intgA, "SEC", "Bug", fd.ID()); pc == nil || !pc.DryRun {
		t.Fatalf("dry run not carried: %+v", pc)
	}
}

func TestTicketMapping_TaskPreviewIsScoped(t *testing.T) {
	f := newTMFixture(t)
	ctx := context.Background()
	v, _, err := f.svc.CreateProfile(ctx, appticketmap.CreateProfileInput{
		TenantID: f.tenantA, IntegrationID: f.intgA, ObjectKind: ticketmap.ObjectTask,
		ProjectKey: "PAY", IssueTypeID: "10001", IssueType: "Task", Preset: "security_task",
	})
	if err != nil {
		t.Fatal(err)
	}
	// A ticket-mapping "task" is a real remediation task.
	camp := &remediation.Task{ID: shared.NewID(), TenantID: f.tenantA, Title: "Upgrade django", State: remediation.TaskStateOpen}
	f.objects.tasks[camp.ID] = camp
	mk := func(title string) *vulnerability.Finding {
		fd, err := vulnerability.NewFinding(f.tenantA, shared.NewID(), vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, title)
		if err != nil {
			t.Fatal(err)
		}
		return fd
	}
	in, out := mk("visible-cve"), mk("hidden-cve")
	f.objects.members[camp.ID] = []*vulnerability.Finding{in, out}
	f.scope.hidden[out.ID()] = true
	f.scope.restricted = true

	p, err := f.svc.PreviewOutbound(ctx, f.tenantA, v.Profile.ID, 0, camp.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	desc := fmt.Sprint(p.Fields["description"])
	if !strings.Contains(desc, "visible\\-cve") && !strings.Contains(desc, "visible-cve") {
		t.Fatalf("visible member missing: %s", desc)
	}
	if strings.Contains(desc, "hidden") {
		t.Fatalf("out-of-scope member rendered: %s", desc)
	}
	// No member in scope: the task is not found for this caller.
	f.scope.hidden[in.ID()] = true
	if _, err := f.svc.PreviewOutbound(ctx, f.tenantA, v.Profile.ID, 0, camp.ID, true); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("task without visible members: want not found, got %v", err)
	}
	// An unrestricted caller sees the whole task.
	f.scope.restricted = false
	f.scope.hidden = map[shared.ID]bool{}
	if p, err := f.svc.PreviewOutbound(ctx, f.tenantA, v.Profile.ID, 0, camp.ID, true); err != nil || !strings.Contains(fmt.Sprint(p.Fields["description"]), "hidden") {
		t.Fatalf("unrestricted: %v", err)
	}
	// Another tenant's task id is not found.
	if _, err := f.svc.PreviewOutbound(ctx, f.tenantB, v.Profile.ID, 0, camp.ID, true); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant: %v", err)
	}
}

func TestTicketMapping_ProfileCannotNameAnotherTenantsIntegration(t *testing.T) {
	f := newTMFixture(t)
	p, err := ticketmap.NewProfile(f.tenantA, f.intgB, ticketmap.ObjectFinding, "", "SEC", "10001", "Bug", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.CreateProfile(context.Background(), p, nil); err == nil {
		t.Fatal("the database accepted a profile naming another tenant's integration")
	}
}
