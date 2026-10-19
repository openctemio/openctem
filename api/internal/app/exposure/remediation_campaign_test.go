package exposure

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// recordingAudit captures every audit event the campaign service writes.
type recordingAudit struct {
	events []auditapp.AuditEvent
	ctxs   []auditapp.AuditContext
	err    error
}

func (a *recordingAudit) LogEvent(_ context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.events = append(a.events, ev)
	a.ctxs = append(a.ctxs, actx)
	return a.err
}

func (a *recordingAudit) count(action auditdom.Action) int {
	n := 0
	for _, ev := range a.events {
		if ev.Action == action {
			n++
		}
	}
	return n
}

type campaignMembers map[shared.ID]bool

func (m campaignMembers) IsActiveTenantMember(_ context.Context, _, userID shared.ID) (bool, error) {
	return m[userID], nil
}

func (m campaignMembers) IsGroupInTenant(_ context.Context, _, groupID shared.ID) (bool, error) {
	return m[groupID], nil
}

type campaignFixture struct {
	svc   *RemediationCampaignService
	repo  *fakeCampaignRepo
	tasks *fakeTasks
	audit *recordingAudit
	c     *remediation.Campaign
	tid   string
}

func newCampaignFixture(t *testing.T) *campaignFixture {
	t.Helper()
	c := newCampaign(t)
	f := &campaignFixture{repo: newFakeCampaignRepo(c), tasks: &fakeTasks{notWritable: map[shared.ID]bool{}},
		audit: &recordingAudit{}, c: c, tid: c.TenantID().String()}
	f.svc = NewRemediationCampaignService(f.repo, logger.NewNop())
	f.svc.SetTasks(f.tasks)
	f.svc.SetAuditLogger(f.audit)
	return f
}

func TestCampaign_CreateValidatesAndAudits(t *testing.T) {
	f := newCampaignFixture(t)
	member, group, stranger := shared.NewID(), shared.NewID(), shared.NewID()
	f.svc.SetAssigneeChecker(campaignMembers{member: true, group: true})
	ctx := context.Background()

	for name, in := range map[string]CreateRemediationCampaignInput{
		"blank name":       {TenantID: f.tid, Name: "  "},
		"bad priority":     {TenantID: f.tid, Name: "x", Priority: "urgent"},
		"not a member":     {TenantID: f.tid, Name: "x", AssignedTo: stranger.String()},
		"not a group":      {TenantID: f.tid, Name: "x", AssignedTeam: stranger.String()},
		"garbage due date": {TenantID: f.tid, Name: "x", DueDate: "next friday"},
	} {
		if _, err := f.svc.CreateCampaign(ctx, in, auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want validation", name, err)
		}
	}
	if n := f.audit.count(auditdom.ActionRemediationCampaignCreated); n != 0 {
		t.Fatalf("refused creates wrote %d audit rows", n)
	}

	v, err := f.svc.CreateCampaign(ctx, CreateRemediationCampaignInput{TenantID: f.tid, Name: " Q4 TLS ", AssignedTo: member.String(),
		AssignedTeam: group.String(), DueDate: "2030-01-31"}, auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if v.Campaign.Name() != "Q4 TLS" || v.Campaign.Status() != remediation.CampaignStatusDraft || v.Campaign.DueDate() == nil || !v.CanEdit {
		t.Errorf("created %q %s due %v can_edit %v", v.Campaign.Name(), v.Campaign.Status(), v.Campaign.DueDate(), v.CanEdit)
	}
	if n := f.audit.count(auditdom.ActionRemediationCampaignCreated); n != 1 {
		t.Errorf("created audit rows = %d", n)
	}
}

func TestCampaign_CreateWithTasksChecksThemFirst(t *testing.T) {
	f := newCampaignFixture(t)
	ctx := context.Background()
	free, locked := shared.NewID(), shared.NewID()
	f.repo.refs[free], f.repo.refs[locked] = nil, nil
	f.tasks.notWritable[locked] = true

	before := len(f.repo.campaigns)
	if _, err := f.svc.CreateCampaign(ctx, CreateRemediationCampaignInput{TenantID: f.tid, Name: "x",
		TaskIDs: []string{free.String(), locked.String()}}, auditapp.AuditContext{}); !errors.Is(err, ErrCampaignTaskNotFound) {
		t.Fatalf("a task the caller may not change: err = %v", err)
	}
	if len(f.repo.campaigns) != before || len(f.repo.moved) != 0 {
		t.Fatal("a refused create stored a campaign or moved a task")
	}
	v, err := f.svc.CreateCampaign(ctx, CreateRemediationCampaignInput{TenantID: f.tid, Name: "x", TaskIDs: []string{free.String()}}, auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.repo.refs[free]; got == nil || *got != v.Campaign.ID() {
		t.Fatalf("task campaign = %v", got)
	}
	if len(f.tasks.recomputed) != 1 {
		t.Errorf("deadlines recomputed for %d tasks, want 1", len(f.tasks.recomputed))
	}
}

func TestCampaign_AddTasksInAnotherCampaignNeedsMove(t *testing.T) {
	f := newCampaignFixture(t)
	ctx := context.Background()
	other := newCampaign(t)
	other = remediation.ReconstituteCampaign(other.ID(), f.c.TenantID(), "Other", "", remediation.CampaignStatusActive,
		remediation.CampaignPriorityLow, nil, nil, nil, nil, nil, nil, nil, other.CreatedAt(), other.UpdatedAt(), 1)
	f.repo.campaigns[other.ID()] = other
	tk := shared.NewID()
	oid := other.ID()
	f.repo.refs[tk] = &oid

	_, err := f.svc.AddCampaignTasks(ctx, f.tid, f.c.ID().String(), []string{tk.String()}, false, "", auditapp.AuditContext{})
	var conflict *TasksInOtherCampaignError
	if !errors.As(err, &conflict) || len(conflict.Conflicts) != 1 || !conflict.Conflicts[0].CanMove ||
		conflict.Conflicts[0].CampaignName == nil || *conflict.Conflicts[0].CampaignName != "Other" {
		t.Fatalf("err = %v (%+v), want one movable conflict naming the campaign", err, conflict)
	}
	if !errors.Is(err, shared.ErrConflict) {
		t.Error("the conflict does not wrap ErrConflict")
	}
	if _, err := f.svc.AddCampaignTasks(ctx, f.tid, f.c.ID().String(), []string{tk.String()}, true, "", auditapp.AuditContext{}); err != nil {
		t.Fatalf("move: %v", err)
	}
	if got := f.repo.refs[tk]; got == nil || *got != f.c.ID() {
		t.Fatalf("task campaign after move = %v", got)
	}
	if f.audit.count(auditdom.ActionRemediationCampaignUpdated) != 1 {
		t.Error("the add was not audited")
	}
}

func TestCampaign_TerminalCampaignTakesNoTasks(t *testing.T) {
	f := newCampaignFixture(t)
	_ = f.c.Cancel()
	tk := shared.NewID()
	f.repo.refs[tk] = nil
	if _, err := f.svc.AddCampaignTasks(context.Background(), f.tid, f.c.ID().String(), []string{tk.String()}, false, "", auditapp.AuditContext{}); !errors.Is(err, remediation.ErrCampaignTakesNoTasks) {
		t.Fatalf("err = %v", err)
	}
	if err := f.svc.CheckTaskCampaignChange(context.Background(), f.c.TenantID(), nil, ptrID(f.c.ID())); !errors.Is(err, remediation.ErrCampaignTakesNoTasks) {
		t.Fatalf("task PATCH into a canceled campaign: err = %v", err)
	}
}

func TestCampaign_RemoveTaskOnlyFromItsCampaign(t *testing.T) {
	f := newCampaignFixture(t)
	ctx := context.Background()
	tk := shared.NewID()
	f.repo.refs[tk] = nil
	if _, err := f.svc.RemoveCampaignTask(ctx, f.tid, f.c.ID().String(), tk.String(), "", auditapp.AuditContext{}); !errors.Is(err, ErrCampaignTaskNotInCampaign) {
		t.Fatalf("task in no campaign: err = %v", err)
	}
	cid := f.c.ID()
	f.repo.refs[tk] = &cid
	if _, err := f.svc.RemoveCampaignTask(ctx, f.tid, f.c.ID().String(), tk.String(), "", auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if f.repo.refs[tk] != nil {
		t.Fatal("task still in the campaign")
	}
}

func TestCampaign_CompleteOnlyWhenDone(t *testing.T) {
	f := newCampaignFixture(t)
	ctx := context.Background()
	if _, err := f.svc.UpdateCampaignStatus(ctx, f.tid, f.c.ID().String(), "active", nil, auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	f.repo.whole = remediation.CampaignSummary{Tasks: 2, LiveTasks: 1, DoneTasks: 1}
	if _, err := f.svc.UpdateCampaignStatus(ctx, f.tid, f.c.ID().String(), "completed", nil, auditapp.AuditContext{}); !errors.Is(err, remediation.ErrCampaignNotDone) {
		t.Fatalf("complete with a live task: err = %v", err)
	}
	for _, st := range []string{"paused", "validating", "draft", "bogus"} {
		if _, err := f.svc.UpdateCampaignStatus(ctx, f.tid, f.c.ID().String(), st, nil, auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("status %q: err = %v", st, err)
		}
	}
	f.repo.whole = remediation.CampaignSummary{Tasks: 2, DoneTasks: 1}
	stale := f.c.Version() - 1
	if _, err := f.svc.UpdateCampaignStatus(ctx, f.tid, f.c.ID().String(), "completed", &stale, auditapp.AuditContext{}); !errors.Is(err, remediation.ErrCampaignVersionConflict) {
		t.Fatalf("stale version: err = %v", err)
	}
	if _, err := f.svc.UpdateCampaignStatus(ctx, f.tid, f.c.ID().String(), "completed", nil, auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if f.audit.count(auditdom.ActionRemediationCampaignStatusChanged) != 2 {
		t.Errorf("status audit rows = %d, want 2", f.audit.count(auditdom.ActionRemediationCampaignStatusChanged))
	}
}

func TestCampaign_ReconcileCompletesAndReopensAsSystem(t *testing.T) {
	f := newCampaignFixture(t)
	_ = f.c.Activate()
	f.repo.whole = remediation.CampaignSummary{Tasks: 1, DoneTasks: 1}
	if n, err := f.svc.ReconcileProgress(context.Background()); err != nil || n != 1 || f.c.Status() != remediation.CampaignStatusCompleted {
		t.Fatalf("reconcile = %d %v, status %s", n, err, f.c.Status())
	}
	if f.audit.ctxs[len(f.audit.ctxs)-1].ActorEmail != campaignAuditSystemActor {
		t.Error("auto-complete not attributed to the system")
	}
	f.repo.whole = remediation.CampaignSummary{Tasks: 2, LiveTasks: 1, DoneTasks: 1}
	if n, _ := f.svc.ReconcileProgress(context.Background()); n != 1 || f.c.Status() != remediation.CampaignStatusActive {
		t.Fatalf("reopen: n=%d status %s", n, f.c.Status())
	}
	if n, _ := f.svc.ReconcileProgress(context.Background()); n != 0 {
		t.Fatalf("a settled campaign changed again: %d", n)
	}
}

func TestCampaign_UpdateAuditsOnlyChanges(t *testing.T) {
	f := newCampaignFixture(t)
	ctx := context.Background()
	name := f.c.Name()
	if _, err := f.svc.UpdateCampaign(ctx, f.tid, f.c.ID().String(), UpdateRemediationCampaignInput{Name: &name}, auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if f.audit.count(auditdom.ActionRemediationCampaignUpdated) != 0 {
		t.Fatal("a no-op update was audited")
	}
	due := "2030-01-31"
	if _, err := f.svc.UpdateCampaign(ctx, f.tid, f.c.ID().String(), UpdateRemediationCampaignInput{DueDate: &due}, auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	later := "2030-02-28"
	if _, err := f.svc.UpdateCampaign(ctx, f.tid, f.c.ID().String(), UpdateRemediationCampaignInput{DueDate: &later}, auditapp.AuditContext{}); !errors.Is(err, remediation.ErrCampaignDeadlineOnlyTightens) {
		t.Fatalf("due date moved later: err = %v", err)
	}
	if f.audit.count(auditdom.ActionRemediationCampaignUpdated) != 1 {
		t.Errorf("updated audit rows = %d", f.audit.count(auditdom.ActionRemediationCampaignUpdated))
	}
}

func TestCampaign_AuditFailureDoesNotFailTheChange(t *testing.T) {
	f := newCampaignFixture(t)
	f.audit.err = errors.New("audit down")
	if _, err := f.svc.UpdateCampaignStatus(context.Background(), f.tid, f.c.ID().String(), "active", nil, auditapp.AuditContext{}); err != nil {
		t.Fatalf("status change failed because the audit write failed: %v", err)
	}
}

func TestCampaign_OtherTenantIsNotFound(t *testing.T) {
	f := newCampaignFixture(t)
	if _, err := f.svc.GetCampaign(context.Background(), shared.NewID().String(), f.c.ID().String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if err := f.svc.DeleteCampaign(context.Background(), shared.NewID().String(), f.c.ID().String(), auditapp.AuditContext{}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("delete: err = %v", err)
	}
}

func TestCampaignAudit_ActionsAreValid(t *testing.T) {
	for _, a := range []auditdom.Action{
		auditdom.ActionRemediationCampaignCreated, auditdom.ActionRemediationCampaignUpdated,
		auditdom.ActionRemediationCampaignStatusChanged, auditdom.ActionRemediationCampaignDeleted,
		auditdom.ActionRemediationCampaignMigrated,
	} {
		if !a.IsValid() {
			t.Errorf("%s is not a valid action: its rows would be dropped", a)
		}
		if a.Category() != "remediation_campaign" {
			t.Errorf("%s category = %q", a, a.Category())
		}
	}
}

func ptrID(id shared.ID) *shared.ID { return &id }
