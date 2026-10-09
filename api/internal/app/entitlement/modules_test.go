package entitlement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeModuleRepo struct {
	planModules plan.PlanModules
	version     int
	grants      map[shared.ID][]plan.ModuleGrant
	failGrants  bool
}

func (f *fakeModuleRepo) GetPlanModules(context.Context) (plan.PlanModules, int, error) {
	if f.planModules == nil {
		return nil, 0, shared.ErrNotFound
	}
	return f.planModules, f.version, nil
}

func (f *fakeModuleRepo) SavePlanModules(_ context.Context, m plan.PlanModules, expected int, _ shared.ID, _ time.Time) (int, error) {
	if expected != f.version {
		return 0, shared.ErrConflict
	}
	f.planModules, f.version = m, f.version+1
	return f.version, nil
}

func (f *fakeModuleRepo) ListModuleGrants(_ context.Context, id shared.ID) ([]plan.ModuleGrant, error) {
	if f.failGrants {
		return nil, errors.New("db down")
	}
	return f.grants[id], nil
}

func (f *fakeModuleRepo) SetModuleGrant(_ context.Context, g plan.ModuleGrant) error {
	if f.grants == nil {
		f.grants = map[shared.ID][]plan.ModuleGrant{}
	}
	list := f.grants[g.TenantID][:0]
	for _, x := range f.grants[g.TenantID] {
		if x.ModuleID != g.ModuleID {
			list = append(list, x)
		}
	}
	f.grants[g.TenantID] = append(list, g)
	return nil
}

func (f *fakeModuleRepo) DeleteModuleGrant(_ context.Context, id shared.ID, moduleID string) error {
	for i, g := range f.grants[id] {
		if g.ModuleID == moduleID {
			f.grants[id] = append(f.grants[id][:i], f.grants[id][i+1:]...)
			return nil
		}
	}
	return shared.ErrNotFound
}

func newModuleService(t *testing.T, mr *fakeModuleRepo) (*Service, *fakeRepo, *[]string) {
	t.Helper()
	repo := &fakeRepo{}
	svc := NewService(repo, nil, nil, nil, nil)
	svc.SetModuleRepository(mr)
	changed := &[]string{}
	svc.SetModulesChangeNotifier(func(id string) { *changed = append(*changed, id) })
	return svc, repo, changed
}

// Nothing stored: every plan includes every module, so turning entitlements
// on changes nothing for any organization.
func TestNotEntitled_BuiltinIncludesEverything(t *testing.T) {
	svc, repo, _ := newModuleService(t, &fakeModuleRepo{})
	id := freeTenant(repo)
	off, err := svc.NotEntitled(context.Background(), id.String())
	if err != nil || len(off) != 0 {
		t.Fatalf("NotEntitled = %v, %v; want nothing", off, err)
	}
}

func TestNotEntitled_PlanGrantDenyAndSubModules(t *testing.T) {
	mr := &fakeModuleRepo{planModules: plan.PlanModules{
		plan.Free:       {moduledom.ModuleAttackSurface, moduledom.ModuleCompliance},
		plan.Pro:        {plan.AllModules},
		plan.Enterprise: {plan.AllModules},
	}, version: 1}
	svc, repo, _ := newModuleService(t, mr)
	free := freeTenant(repo)
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	mr.grants = map[shared.ID][]plan.ModuleGrant{free: {
		{ModuleID: moduledom.ModulePentest, Kind: plan.GrantAdd, Reason: "trial", ExpiresAt: &future},
		{ModuleID: moduledom.ModuleCompliance, Kind: plan.GrantDeny, Reason: "contract"},
		{ModuleID: moduledom.ModuleWorkflows, Kind: plan.GrantAdd, Reason: "expired trial", ExpiresAt: &past},
	}}

	off, err := svc.NotEntitled(context.Background(), free.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{moduledom.ModuleCompliance, moduledom.ModuleWorkflows, moduledom.ModuleAITriage,
		moduledom.ModuleAITriageBulk /* follows its parent */} {
		if !off[id] {
			t.Errorf("%s should not be entitled", id)
		}
	}
	for _, id := range []string{moduledom.ModuleAttackSurface, moduledom.ModulePentest, moduledom.ModuleFindings, moduledom.ModuleSLA} {
		if off[id] {
			t.Errorf("%s should be entitled", id)
		}
	}

	// Another organization on Enterprise is unaffected by the first one's grants.
	other := shared.NewID()
	repo.plans[other] = plan.Enterprise
	off, err = svc.NotEntitled(context.Background(), other.String())
	if err != nil || len(off) != 0 {
		t.Fatalf("enterprise organization: %v, %v; want everything entitled", off, err)
	}
}

// Fail-closed: a read error is returned, never turned into "entitled".
func TestNotEntitled_ReadErrorIsReported(t *testing.T) {
	svc, repo, _ := newModuleService(t, &fakeModuleRepo{failGrants: true})
	if _, err := svc.NotEntitled(context.Background(), freeTenant(repo).String()); err == nil {
		t.Fatal("a grant read error must be reported")
	}
	repo.failPlan = true
	if _, err := svc.NotEntitled(context.Background(), shared.NewID().String()); err == nil {
		t.Fatal("a plan read error must be reported")
	}
}

func TestPutModuleGrant_ValidatesAndNotifies(t *testing.T) {
	svc, repo, changed := newModuleService(t, &fakeModuleRepo{})
	id := freeTenant(repo)
	a := newAdmin(t, "ops@example.test", admin.AdminRoleOpsAdmin)
	ctx := context.Background()
	past := time.Now().Add(-time.Minute)
	bad := []ModuleGrantInput{
		{Module: "nope", Kind: plan.GrantAdd, Reason: "r"},
		{Module: moduledom.ModuleFindings, Kind: plan.GrantDeny, Reason: "core"},
		{Module: moduledom.ModuleAITriageBulk, Kind: plan.GrantAdd, Reason: "sub-module"},
		{Module: moduledom.ModulePentest, Kind: "maybe", Reason: "r"},
		{Module: moduledom.ModulePentest, Kind: plan.GrantAdd, Reason: "  "},
		{Module: moduledom.ModulePentest, Kind: plan.GrantAdd, Reason: "r", ExpiresAt: &past},
	}
	for _, in := range bad {
		if err := svc.PutModuleGrant(ctx, a, id, in, "", ""); !errors.Is(err, plan.ErrInvalid) {
			t.Errorf("%+v: err = %v, want ErrInvalid", in, err)
		}
	}
	if len(*changed) != 0 {
		t.Fatalf("refused grants notified %v", *changed)
	}
	if err := svc.PutModuleGrant(ctx, a, id, ModuleGrantInput{Module: moduledom.ModulePentest, Kind: plan.GrantDeny, Reason: "contract"}, "", ""); err != nil {
		t.Fatal(err)
	}
	if len(*changed) != 1 || (*changed)[0] != id.String() {
		t.Fatalf("notified %v, want the organization", *changed)
	}
	if err := svc.DeleteModuleGrant(ctx, a, id, moduledom.ModulePentest, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteModuleGrant(ctx, a, id, moduledom.ModulePentest, "", ""); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("second delete: %v, want ErrNotFound", err)
	}
}

func TestUpdatePlanModules_ValidatesNormalizesAndNotifiesEveryone(t *testing.T) {
	mr := &fakeModuleRepo{}
	svc, _, changed := newModuleService(t, mr)
	a := newAdmin(t, "root@example.test", admin.AdminRoleSuperAdmin)
	ctx := context.Background()
	for _, m := range []plan.PlanModules{
		{plan.Free: {"nope"}},
		{plan.Free: {moduledom.ModuleFindings}},
		{plan.Free: {plan.AllModules, moduledom.ModulePentest}},
		{"gold": {plan.AllModules}},
	} {
		if _, err := svc.UpdatePlanModules(ctx, a, m, 0, "", ""); !errors.Is(err, plan.ErrInvalid) {
			t.Errorf("%v: err = %v, want ErrInvalid", m, err)
		}
	}
	v, err := svc.UpdatePlanModules(ctx, a, plan.PlanModules{plan.Free: {moduledom.ModulePentest, moduledom.ModuleCompliance, moduledom.ModulePentest}}, 0, "", "")
	if err != nil || v != 1 {
		t.Fatalf("save: %v, %v", v, err)
	}
	if got := mr.planModules[plan.Free]; len(got) != 2 || got[0] != moduledom.ModuleCompliance {
		t.Fatalf("stored %v, want sorted unique", got)
	}
	if got := mr.planModules[plan.Enterprise]; len(got) != 0 {
		t.Fatalf("a plan left out includes nothing, stored %v", got)
	}
	if len(*changed) != 1 || (*changed)[0] != "" {
		t.Fatalf("notified %v, want every organization", *changed)
	}
	if _, err := svc.UpdatePlanModules(ctx, a, plan.PlanModules{plan.Free: {plan.AllModules}}, 0, "", ""); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version: %v, want ErrConflict", err)
	}
}

// Changing an organization's plan refreshes its modules.
func TestChangeTenantPlan_NotifiesModules(t *testing.T) {
	svc, repo, changed := newModuleService(t, &fakeModuleRepo{})
	id := freeTenant(repo)
	if err := svc.ChangeTenantPlan(context.Background(), newAdmin(t, "ops@example.test", admin.AdminRoleOpsAdmin), id, plan.Pro, "", ""); err != nil {
		t.Fatal(err)
	}
	if len(*changed) != 1 || (*changed)[0] != id.String() {
		t.Fatalf("notified %v", *changed)
	}
}
