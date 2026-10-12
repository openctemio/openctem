package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	lifecycledom "github.com/openctemio/openctem/api/pkg/domain/lifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeRepo struct {
	list       []lifecycledom.Workspace
	stages     map[shared.ID]lifecycledom.Stage
	exemptions map[shared.ID]lifecycledom.Exemption
	readOnly   map[shared.ID]bool
	roErr      error
	roCalls    int
	recipients []string
}

func (f *fakeRepo) FreeWorkspaces(context.Context) ([]lifecycledom.Workspace, error) {
	return f.list, nil
}
func (f *fakeRepo) SetStage(_ context.Context, id shared.ID, s lifecycledom.Stage, _ time.Time) error {
	if f.stages == nil {
		f.stages = map[shared.ID]lifecycledom.Stage{}
	}
	f.stages[id] = s
	return nil
}
func (f *fakeRepo) Status(context.Context, shared.ID) (*lifecycledom.Status, error) {
	return &lifecycledom.Status{Stage: lifecycledom.StageActive}, nil
}
func (f *fakeRepo) SetExemption(_ context.Context, id shared.ID, e lifecycledom.Exemption) error {
	if f.exemptions == nil {
		f.exemptions = map[shared.ID]lifecycledom.Exemption{}
	}
	f.exemptions[id] = e
	return nil
}
func (f *fakeRepo) ReadOnly(_ context.Context, id shared.ID) (bool, error) {
	f.roCalls++
	return f.readOnly[id], f.roErr
}
func (f *fakeRepo) Recipients(context.Context, shared.ID) ([]string, error) { return f.recipients, nil }

type fakeAudit struct{ actions []auditdom.Action }

func (a *fakeAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	a.actions = append(a.actions, e.Action)
	return nil
}

type fakeAdminAudit struct{ n int }

func (a *fakeAdminAudit) Create(context.Context, *admin.AuditLog) error { a.n++; return nil }

type fakeAdmins struct{ list []*admin.AdminUser }

func (a fakeAdmins) ListActive(context.Context) ([]*admin.AdminUser, error) { return a.list, nil }

type fakeNotifier struct{ notices []Notice }

func (n *fakeNotifier) NotifyIdle(_ context.Context, x Notice) error {
	n.notices = append(n.notices, x)
	return nil
}

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func TestSweep_AdvancesAuditsAndNotifies(t *testing.T) {
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	created := now.Add(-days(400))
	idle61 := lifecycledom.Workspace{TenantID: shared.NewID(), Name: "Idle", Stage: lifecycledom.StageActive, CreatedAt: created, LastSignIn: now.Add(-days(61))}
	busy := lifecycledom.Workspace{TenantID: shared.NewID(), Name: "Busy", Stage: lifecycledom.StageActive, CreatedAt: created, LastSignIn: now.Add(-days(2))}
	back := lifecycledom.Workspace{TenantID: shared.NewID(), Name: "Back", Stage: lifecycledom.StageReadOnly, StageChangedAt: now.Add(-days(5)), CreatedAt: created, LastSignIn: now.Add(-time.Hour)}
	due := lifecycledom.Workspace{TenantID: shared.NewID(), Name: "Due", Stage: lifecycledom.StageFinalWarning, StageChangedAt: now.Add(-days(8)), CreatedAt: created, LastSignIn: now.Add(-days(121))}
	exempt := lifecycledom.Workspace{TenantID: shared.NewID(), Name: "Exempt", Stage: lifecycledom.StageActive, CreatedAt: created, LastSignIn: now.Add(-days(300)), Exempt: true}

	repo := &fakeRepo{list: []lifecycledom.Workspace{idle61, busy, back, due, exempt}, recipients: []string{"owner@acme.test"}}
	audit := &fakeAudit{}
	notifier := &fakeNotifier{}
	op, _ := admin.NewAdminUser("op@platform.test", "Op", admin.AdminRoleSuperAdmin, nil)
	svc := NewService(repo, audit, nil, fakeAdmins{list: []*admin.AdminUser{op}}, notifier, nil)
	svc.now = func() time.Time { return now }

	n, err := svc.Sweep(context.Background())
	if err != nil || n != 3 {
		t.Fatalf("changed=%d err=%v", n, err)
	}
	if repo.stages[idle61.TenantID] != lifecycledom.StageReminded ||
		repo.stages[back.TenantID] != lifecycledom.StageActive ||
		repo.stages[due.TenantID] != lifecycledom.StageDeletionDue {
		t.Fatalf("stages: %v", repo.stages)
	}
	if _, touched := repo.stages[busy.TenantID]; touched {
		t.Fatal("an active organization must not be touched")
	}
	if _, touched := repo.stages[exempt.TenantID]; touched {
		t.Fatal("an exempt active organization must not be touched")
	}
	if len(audit.actions) != 3 {
		t.Fatalf("every stage change is audited: %v", audit.actions)
	}
	// Reminder to the owners; deletion due to the platform admins; no email
	// for a reactivation.
	if len(notifier.notices) != 2 {
		t.Fatalf("notices: %+v", notifier.notices)
	}
	for _, x := range notifier.notices {
		switch x.Stage {
		case lifecycledom.StageReminded:
			if x.Recipients[0] != "owner@acme.test" || x.Organization != "Idle" {
				t.Fatalf("reminder: %+v", x)
			}
		case lifecycledom.StageDeletionDue:
			if x.Recipients[0] != "op@platform.test" {
				t.Fatalf("deletion due goes to the platform admins: %+v", x)
			}
		default:
			t.Fatalf("unexpected notice %+v", x)
		}
	}
}

func TestReadOnly_CachedAndFailOpen(t *testing.T) {
	id := shared.NewID()
	repo := &fakeRepo{readOnly: map[shared.ID]bool{id: true}}
	svc := NewService(repo, nil, nil, nil, nil, nil)
	first := svc.ReadOnly(context.Background(), id)
	second := svc.ReadOnly(context.Background(), id)
	if !first || !second {
		t.Fatal("want read-only")
	}
	if repo.roCalls != 1 {
		t.Fatalf("cached: %d calls", repo.roCalls)
	}
	other := shared.NewID()
	repo.roErr = errors.New("db down")
	if svc.ReadOnly(context.Background(), other) {
		t.Fatal("a read error must not lock an organization")
	}
}

func TestSetExemption(t *testing.T) {
	id := shared.NewID()
	repo := &fakeRepo{}
	audit := &fakeAudit{}
	adminAudit := &fakeAdminAudit{}
	svc := NewService(repo, audit, adminAudit, nil, nil, nil)
	op, _ := admin.NewAdminUser("op@platform.test", "Op", admin.AdminRoleOpsAdmin, nil)

	if err := svc.ChangeExemption(context.Background(), nil, id, true, "x", "", ""); err == nil {
		t.Fatal("nil actor")
	}
	if err := svc.ChangeExemption(context.Background(), op, id, true, "  ", "", ""); !errors.Is(err, ErrInvalidExemption) {
		t.Fatalf("empty reason: %v", err)
	}
	long := make([]rune, 501)
	for i := range long {
		long[i] = 'x'
	}
	if err := svc.ChangeExemption(context.Background(), op, id, true, string(long), "", ""); !errors.Is(err, ErrInvalidExemption) {
		t.Fatalf("long reason: %v", err)
	}
	if len(repo.exemptions) != 0 {
		t.Fatal("refused exemptions must not be stored")
	}
	if err := svc.ChangeExemption(context.Background(), op, id, true, "design partner", "", ""); err != nil {
		t.Fatal(err)
	}
	if e := repo.exemptions[id]; !e.Exempt || e.Reason != "design partner" || e.By == nil {
		t.Fatalf("stored %+v", e)
	}
	if adminAudit.n != 1 || len(audit.actions) != 1 || audit.actions[0] != auditdom.ActionTenantIdleExemptionChanged {
		t.Fatalf("audit admin=%d tenant=%v", adminAudit.n, audit.actions)
	}
	// Lifting needs no reason.
	if err := svc.ChangeExemption(context.Background(), op, id, false, "", "", ""); err != nil || repo.exemptions[id].Exempt {
		t.Fatalf("lift: %v %+v", err, repo.exemptions[id])
	}
}
