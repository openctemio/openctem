package ticketmap

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	ticketmapdom "github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// memProfiles is a tenant-scoped profile store.
type memProfiles struct {
	ticketmapdom.Repository
	profiles []*ticketmapdom.Profile
	versions map[shared.ID]*ticketmapdom.Version
	drifted  []shared.ID
}

func (m *memProfiles) ListProfiles(_ context.Context, tenantID shared.ID, f ticketmapdom.ProfileFilter, _ pagination.Pagination) (pagination.Result[*ticketmapdom.Profile], error) {
	var out []*ticketmapdom.Profile
	for _, p := range m.profiles {
		if p.TenantID != tenantID || (f.IntegrationID != nil && p.IntegrationID != *f.IntegrationID) ||
			(f.ObjectKind != "" && p.ObjectKind != f.ObjectKind) || (f.ProjectKey != "" && p.ProjectKey != f.ProjectKey) {
			continue
		}
		out = append(out, p)
	}
	return pagination.Result[*ticketmapdom.Profile]{Data: out, Total: int64(len(out))}, nil
}

func (m *memProfiles) GetVersion(_ context.Context, tenantID, profileID shared.ID, _ int) (*ticketmapdom.Version, error) {
	v, ok := m.versions[profileID]
	if !ok || v.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return v, nil
}

func (m *memProfiles) SetDrifted(_ context.Context, tenantID, id shared.ID, drifted bool) error {
	for _, p := range m.profiles {
		if p.ID == id && p.TenantID == tenantID {
			p.Drifted = drifted
			m.drifted = append(m.drifted, id)
			return nil
		}
	}
	return shared.ErrNotFound
}

type taskObjects struct {
	ObjectSource
	task *remediation.Task
}

func (o taskObjects) Task(context.Context, shared.ID, shared.ID) (*remediation.Task, error) {
	return o.task, nil
}
func (o taskObjects) TaskMembers(context.Context, shared.ID, shared.ID, int) ([]*vulnerability.Finding, int64, error) {
	return nil, 0, nil
}
func (o taskObjects) User(context.Context, shared.ID, shared.ID) (*UserInfo, error) { return nil, nil }

func (m *memProfiles) add(tenant, intg shared.ID, kind ticketmapdom.ObjectKind, typeID, typeName, target string) *ticketmapdom.Profile {
	p := &ticketmapdom.Profile{ID: shared.NewID(), TenantID: tenant, IntegrationID: intg, ObjectKind: kind, ProjectKey: "SEC",
		IssueTypeID: typeID, IssueType: typeName, PublishedVersion: 1}
	m.profiles = append(m.profiles, p)
	spec := ticketmapdom.Spec{Status: ticketmapdom.StatusMap{
		Outbound: map[string]ticketmapdom.StatusTarget{"in_progress": {StatusID: target}, "open": {StatusID: target}},
		Inbound:  []ticketmapdom.InboundRule{{StatusID: target, Intent: ticketmapdom.IntentInProgress}},
	}}
	if kind == ticketmapdom.ObjectTask {
		spec.Minimization = ticketmapdom.MinSummary
		spec.Fields = []ticketmapdom.Row{{ID: "s", Source: ticketmapdom.Source{Kind: ticketmapdom.SourceTemplate, Template: "{{ task.title }}"},
			Target: ticketmapdom.Target{FieldID: "summary", Schema: ticketmapdom.FieldSchema{Type: "string", System: "summary"}}, Direction: ticketmapdom.DirOut, Sync: ticketmapdom.SyncCreate}}
	}
	m.versions[p.ID] = &ticketmapdom.Version{ProfileID: p.ID, TenantID: tenant, Version: 1, State: "published", Spec: spec}
	return p
}

func TestProfilesAreFoundByKindAndIssueType(t *testing.T) {
	ctx := context.Background()
	tenant, other, intg := shared.NewID(), shared.NewID(), shared.NewID()
	repo := &memProfiles{versions: map[shared.ID]*ticketmapdom.Version{}}
	findingSF := repo.add(tenant, intg, ticketmapdom.ObjectFinding, "10042", "Security Finding", "31")
	repo.add(tenant, intg, ticketmapdom.ObjectFinding, "10004", "Bug", "41")
	taskRT := repo.add(tenant, intg, ticketmapdom.ObjectTask, "10043", "Remediation Task", "51")
	repo.add(other, intg, ticketmapdom.ObjectTask, "10044", "Other tenant", "61")
	task := &remediation.Task{ID: shared.NewID(), Title: "Patch openssl", State: remediation.TaskStateInProgress}
	s := NewService(repo, nil, nil, taskObjects{task: task}, "https://console.example", logger.NewNop())

	// Inbound: each type has its own workflow map.
	for typeID, want := range map[string]string{"10042": "31", "10004": "41"} {
		sm, err := s.InboundStatusMap(ctx, tenant, intg, ticketmapdom.ObjectFinding, "SEC", typeID)
		if err != nil || sm == nil || sm.Inbound[0].StatusID != want {
			t.Fatalf("type %s: %+v %v", typeID, sm, err)
		}
	}
	if sm, err := s.InboundStatusMap(ctx, tenant, intg, ticketmapdom.ObjectFinding, "SEC", "99999"); sm != nil || err != nil {
		t.Fatalf("an unmapped type must have no map: %+v %v", sm, err)
	}
	// The task profile is never returned for a finding, nor the other way round.
	if sm, _ := s.InboundStatusMap(ctx, tenant, intg, ticketmapdom.ObjectFinding, "SEC", "10043"); sm != nil {
		t.Fatal("task profile returned for a finding")
	}
	if sm, _ := s.InboundStatusMap(ctx, tenant, intg, ticketmapdom.ObjectTask, "SEC", "10043"); sm == nil || sm.Inbound[0].StatusID != "51" {
		t.Fatal("task profile not found")
	}
	// Another tenant's profile is invisible.
	if sm, _ := s.InboundStatusMap(ctx, tenant, intg, ticketmapdom.ObjectTask, "SEC", "10044"); sm != nil {
		t.Fatal("cross-tenant profile returned")
	}

	// Task status: the task profile of the issue's type, the task's state.
	ps, err := s.TaskStatusTarget(ctx, tenant, intg, "SEC", "10043", task.ID)
	if err != nil || ps == nil || ps.ProfileID != taskRT.ID || ps.State != "in_progress" || ps.Target == nil || ps.Target.StatusID != "51" {
		t.Fatalf("task status %+v %v", ps, err)
	}
	if ps, _ := s.TaskStatusTarget(ctx, tenant, intg, "SEC", "10042", task.ID); ps != nil {
		t.Fatal("a finding profile must not move a task's issue")
	}

	// Task create: rendered from the task profile, by id or by name.
	for _, typ := range []string{"10043", "Remediation Task"} {
		pc, err := s.RenderTaskCreate(ctx, tenant, intg, "SEC", typ, task.ID)
		if err != nil || pc == nil || pc.IssueTypeID != "10043" || pc.Fields["summary"] != "Patch openssl" {
			t.Fatalf("render %q: %+v %v", typ, pc, err)
		}
	}
	if pc, err := s.RenderTaskCreate(ctx, tenant, intg, "SEC", "Task", task.ID); pc != nil || err != nil {
		t.Fatalf("no task profile for Task: %+v %v", pc, err)
	}

	// Coverage for the issue type check.
	for _, tc := range []struct {
		kind ticketmapdom.ObjectKind
		typ  string
		want bool
	}{{ticketmapdom.ObjectFinding, "10042", true}, {ticketmapdom.ObjectTask, "10042", false}, {ticketmapdom.ObjectFinding, "", false}} {
		if got, err := s.HasPublishedProfile(ctx, tenant, intg, tc.kind, "SEC", tc.typ); err != nil || got != tc.want {
			t.Errorf("%s/%s: %v %v", tc.kind, tc.typ, got, err)
		}
	}
	if got, _ := s.HasPublishedProfile(ctx, other, intg, ticketmapdom.ObjectFinding, "SEC", "10042"); got {
		t.Error("another tenant's coverage")
	}

	// Drift is marked only on the tenant's own profile.
	if err := s.MarkDrifted(ctx, other, findingSF.ID); err == nil || findingSF.Drifted {
		t.Fatal("another tenant marked the profile drifted")
	}
	if err := s.MarkDrifted(ctx, tenant, findingSF.ID); err != nil || !findingSF.Drifted {
		t.Fatalf("drift: %v", err)
	}
}

func TestPublishedWithoutAnIssueTypeNeedsASingleProfile(t *testing.T) {
	ctx := context.Background()
	tenant, intg := shared.NewID(), shared.NewID()
	repo := &memProfiles{versions: map[shared.ID]*ticketmapdom.Version{}}
	only := repo.add(tenant, intg, ticketmapdom.ObjectFinding, "10042", "Security Finding", "31")
	draft := repo.add(tenant, intg, ticketmapdom.ObjectFinding, "10005", "Draft only", "35")
	draft.PublishedVersion = 0 // never published: not a candidate
	s := NewService(repo, nil, nil, nil, "https://console.example", logger.NewNop())

	// One published profile: a caller that cannot name the type gets it.
	p, _, err := s.published(ctx, tenant, intg, ticketmapdom.ObjectFinding, "SEC", "")
	if err != nil || p == nil || p.ID != only.ID {
		t.Fatalf("single published profile: %+v %v", p, err)
	}

	// Two published profiles: which one applies is unknown, so none does
	// (the caller keeps its built-in safe mapping), whatever the list order.
	repo.add(tenant, intg, ticketmapdom.ObjectFinding, "10004", "Bug", "41")
	for range 2 {
		if p, _, err := s.published(ctx, tenant, intg, ticketmapdom.ObjectFinding, "SEC", ""); p != nil || err != nil {
			t.Fatalf("ambiguous published profiles must give none: %+v %v", p, err)
		}
		repo.profiles[0], repo.profiles[2] = repo.profiles[2], repo.profiles[0]
	}
	// An explicit type still finds its own profile.
	if p, _, err := s.published(ctx, tenant, intg, ticketmapdom.ObjectFinding, "SEC", "Bug"); err != nil || p == nil || p.IssueTypeID != "10004" {
		t.Fatalf("explicit type: %+v %v", p, err)
	}
	// And the render path falls back (nil) rather than using a guess.
	if pc, err := s.RenderFindingCreate(ctx, tenant, intg, "SEC", "", shared.NewID()); pc != nil || err != nil {
		t.Fatalf("render without a type among several profiles: %+v %v", pc, err)
	}
}
