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
	grace       map[shared.ID]map[string]time.Time
	planGrace   map[plan.Plan][]string // lost modules started per plan
	planEnded   map[plan.Plan][]string
	failGrants  bool
}

func (f *fakeModuleRepo) ListModuleGrace(_ context.Context, id shared.ID) (map[string]time.Time, error) {
	return f.grace[id], nil
}

func (f *fakeModuleRepo) StartModuleGrace(_ context.Context, id shared.ID, ids []string, until time.Time) error {
	if f.grace == nil {
		f.grace = map[shared.ID]map[string]time.Time{}
	}
	if f.grace[id] == nil {
		f.grace[id] = map[string]time.Time{}
	}
	for _, m := range ids {
		if _, ok := f.grace[id][m]; !ok {
			f.grace[id][m] = until
		}
	}
	return nil
}

func (f *fakeModuleRepo) EndModuleGrace(_ context.Context, id shared.ID, ids []string) error {
	for _, m := range ids {
		delete(f.grace[id], m)
	}
	return nil
}

func (f *fakeModuleRepo) StartPlanModuleGrace(_ context.Context, p plan.Plan, ids []string, _ time.Time) error {
	if f.planGrace == nil {
		f.planGrace = map[plan.Plan][]string{}
	}
	f.planGrace[p] = append(f.planGrace[p], ids...)
	return nil
}

func (f *fakeModuleRepo) EndPlanModuleGrace(_ context.Context, p plan.Plan, ids []string) error {
	if f.planEnded == nil {
		f.planEnded = map[plan.Plan][]string{}
	}
	f.planEnded[p] = append(f.planEnded[p], ids...)
	return nil
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
		if _, ok := off[id]; !ok {
			t.Errorf("%s should not be entitled", id)
		}
	}
	for _, id := range []string{moduledom.ModuleAttackSurface, moduledom.ModulePentest, moduledom.ModuleFindings, moduledom.ModuleSLA} {
		if _, ok := off[id]; ok {
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
	if err := svc.DeleteModuleGrant(ctx, a, id, moduledom.ModulePentest, "contract ended", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteModuleGrant(ctx, a, id, moduledom.ModulePentest, "contract ended", "", ""); !errors.Is(err, shared.ErrNotFound) {
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

// Losing a module starts its read-only grace; getting it back ends it.
func TestGrace_StartsOnLossAndEndsOnRegain(t *testing.T) {
	mr := &fakeModuleRepo{}
	svc, repo, _ := newModuleService(t, mr)
	id := freeTenant(repo)
	a := newAdmin(t, "ops@example.test", admin.AdminRoleOpsAdmin)
	ctx := context.Background()

	if err := svc.PutModuleGrant(ctx, a, id, ModuleGrantInput{Module: moduledom.ModulePentest, Kind: plan.GrantDeny, Reason: "contract"}, "", ""); err != nil {
		t.Fatal(err)
	}
	until, ok := mr.grace[id][moduledom.ModulePentest]
	if !ok || until.Before(time.Now().Add(plan.GracePeriod-time.Minute)) {
		t.Fatalf("grace after a deny: %v %v, want about 30 days", until, ok)
	}
	off, err := svc.NotEntitled(ctx, id.String())
	if err != nil {
		t.Fatal(err)
	}
	if u := off[moduledom.ModulePentest]; u == nil {
		t.Fatal("a module in grace must carry its read-only end")
	}
	_, list, _ := svc.ModuleEntitlements(ctx, id)
	for _, e := range list {
		if e.Module == moduledom.ModulePentest && (e.Source != SourceGrace || e.ReadOnlyUntil == nil || e.Entitled) {
			t.Fatalf("pentest entitlement %+v, want grace", e)
		}
	}

	if err := svc.DeleteModuleGrant(ctx, a, id, moduledom.ModulePentest, "plan decides", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, still := mr.grace[id][moduledom.ModulePentest]; still {
		t.Fatal("grace must end when the module comes back")
	}
}

// After the grace, the module is simply not entitled.
func TestGrace_Expires(t *testing.T) {
	mr := &fakeModuleRepo{}
	svc, repo, _ := newModuleService(t, mr)
	id := freeTenant(repo)
	mr.grants = map[shared.ID][]plan.ModuleGrant{id: {{ModuleID: moduledom.ModulePentest, Kind: plan.GrantDeny, Reason: "r"}}}
	mr.grace = map[shared.ID]map[string]time.Time{id: {moduledom.ModulePentest: time.Now().Add(-time.Minute)}}
	off, err := svc.NotEntitled(context.Background(), id.String())
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := off[moduledom.ModulePentest]; !ok || u != nil {
		t.Fatalf("expired grace: %v %v, want not entitled with no read access", u, ok)
	}
}

// A trial grant that expired gives the same read-only grace from its expiry.
func TestGrace_ExpiredTrial(t *testing.T) {
	mr := &fakeModuleRepo{planModules: plan.PlanModules{plan.Free: {}, plan.Pro: {plan.AllModules}, plan.Enterprise: {plan.AllModules}}, version: 1}
	svc, repo, _ := newModuleService(t, mr)
	id := freeTenant(repo)
	ended := time.Now().Add(-24 * time.Hour)
	mr.grants = map[shared.ID][]plan.ModuleGrant{id: {{ModuleID: moduledom.ModulePentest, Kind: plan.GrantAdd, Reason: "trial", ExpiresAt: &ended}}}
	off, err := svc.NotEntitled(context.Background(), id.String())
	if err != nil {
		t.Fatal(err)
	}
	u := off[moduledom.ModulePentest]
	if u == nil || !u.Equal(ended.Add(plan.GracePeriod)) {
		t.Fatalf("expired trial: read-only until %v, want %v", u, ended.Add(plan.GracePeriod))
	}
}

// A plan mapping change starts grace for what each plan lost and ends it
// for what it regained.
func TestGrace_PlanMappingChange(t *testing.T) {
	mr := &fakeModuleRepo{planModules: plan.PlanModules{
		plan.Free: {moduledom.ModuleCompliance}, plan.Pro: {plan.AllModules}, plan.Enterprise: {plan.AllModules},
	}, version: 1}
	svc, _, _ := newModuleService(t, mr)
	a := newAdmin(t, "root@example.test", admin.AdminRoleSuperAdmin)
	if _, err := svc.UpdatePlanModules(context.Background(), a, plan.PlanModules{
		plan.Free: {moduledom.ModulePentest}, plan.Pro: {moduledom.ModuleCompliance}, plan.Enterprise: {plan.AllModules},
	}, 1, "", ""); err != nil {
		t.Fatal(err)
	}
	if got := mr.planGrace[plan.Free]; len(got) != 1 || got[0] != moduledom.ModuleCompliance {
		t.Fatalf("free lost %v, want compliance", got)
	}
	if got := mr.planEnded[plan.Free]; len(got) != 1 || got[0] != moduledom.ModulePentest {
		t.Fatalf("free regained %v, want pentest", got)
	}
	if got := mr.planGrace[plan.Pro]; len(got) == 0 {
		t.Fatal("pro lost every module but compliance: grace must start")
	}
	if got := mr.planGrace[plan.Enterprise]; len(got) != 0 {
		t.Fatalf("enterprise lost nothing, got %v", got)
	}
}
