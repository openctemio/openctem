package entitlement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func someModules(t *testing.T) (core, nonCore string) {
	t.Helper()
	for _, d := range moduledom.Registry {
		if d.Parent != "" {
			continue
		}
		if d.Core && core == "" {
			core = d.ID
		}
		if !d.Core && nonCore == "" {
			nonCore = d.ID
		}
	}
	if core == "" || nonCore == "" {
		t.Fatal("registry needs a core and a non-core module")
	}
	return core, nonCore
}

// Every module is available by default; a deny starts read-only grace, a
// lifted deny ends it, both audited; core modules can never be denied.
func TestFeatureDenyAndGrace(t *testing.T) {
	core, mod := someModules(t)
	repo := &memRepo{}
	audit := &memAudit{}
	svc := NewService(repo, audit, nil)
	changed := []string{}
	svc.SetModulesChangeNotifier(func(id string) { changed = append(changed, id) })
	ctx := context.Background()
	tid, other := shared.NewID(), shared.NewID()

	off, err := svc.NotEntitled(ctx, tid.String())
	if err != nil || len(off) != 0 {
		t.Fatalf("everything available by default: %v %v", off, err)
	}
	if err := svc.PutDeny(ctx, operator(t), tid, DenyInput{Feature: core, Reason: "x"}, "", ""); !errors.Is(err, limits.ErrInvalid) {
		t.Fatalf("a core module can never be denied: %v", err)
	}
	if err := svc.PutDeny(ctx, operator(t), tid, DenyInput{Feature: mod, Reason: " "}, "", ""); !errors.Is(err, limits.ErrInvalid) {
		t.Fatalf("reason required: %v", err)
	}
	if err := svc.PutDeny(ctx, operator(t), tid, DenyInput{Feature: mod, Reason: "contract"}, "", ""); err != nil {
		t.Fatal(err)
	}
	off, err = svc.NotEntitled(ctx, tid.String())
	if err != nil || off[mod] == nil || !off[mod].After(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("denied with ~30 days of read-only grace: %v %v", off, err)
	}
	if off2, _ := svc.NotEntitled(ctx, other.String()); len(off2) != 0 {
		t.Fatalf("another organization is untouched: %v", off2)
	}
	list, _ := svc.ModuleEntitlements(ctx, tid)
	for _, e := range list {
		if e.Module == mod && (e.Entitled || e.State != StateGrace || e.Reason != "contract" || e.Origin != limits.OriginOperator) {
			t.Fatalf("module state: %+v", e)
		}
		if e.Module == core && (!e.Entitled || e.State != StateCore) {
			t.Fatalf("core state: %+v", e)
		}
	}
	sum, _ := svc.Effective(ctx, tid)
	if !sum.Applies || len(sum.Denied) != 1 || sum.Denied[0].Feature != mod {
		t.Fatalf("summary: %+v", sum)
	}

	if err := svc.DeleteDeny(ctx, operator(t), tid, mod, "", "", ""); !errors.Is(err, limits.ErrInvalid) {
		t.Fatalf("lifting needs a reason: %v", err)
	}
	if err := svc.DeleteDeny(ctx, operator(t), tid, mod, "renewed", "", ""); err != nil {
		t.Fatal(err)
	}
	if off, _ = svc.NotEntitled(ctx, tid.String()); len(off) != 0 {
		t.Fatalf("allowed again: %v", off)
	}
	if len(repo.grace[tid]) != 0 {
		t.Fatalf("grace ended: %v", repo.grace[tid])
	}
	if len(audit.actions) != 2 || audit.actions[0] != ActionFeatureDenySet || audit.actions[1] != ActionFeatureDenyRemoved {
		t.Fatalf("audit: %v", audit.actions)
	}
	if len(changed) != 2 || changed[0] != tid.String() {
		t.Fatalf("module caches refreshed for the organization only: %v", changed)
	}
}

// A control-plane deny applies through its source and is merged with the
// operator's denies.
func TestControlPlaneDeny(t *testing.T) {
	_, mod := someModules(t)
	tid := shared.NewID()
	repo := &memRepo{denies: []limits.FeatureDeny{{TenantID: tid, Feature: mod, Origin: limits.OriginControlPlane, Reason: "cp"}}}
	svc := NewService(repo, nil, nil)
	if off, _ := svc.NotEntitled(context.Background(), tid.String()); len(off) != 0 {
		t.Fatal("without the control-plane source its rows are not read (self-hosted default)")
	}
	svc.SetSources(NewControlPlaneSource(repo))
	off, err := svc.NotEntitled(context.Background(), tid.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := off[mod]; !ok {
		t.Fatalf("control-plane deny applies: %v", off)
	}
}

func TestAllowedNamedFeatures(t *testing.T) {
	svc := NewService(&memRepo{}, nil, nil)
	if _, err := svc.Allowed(context.Background(), shared.NewID(), "not.a.feature"); !errors.Is(err, limits.ErrInvalid) {
		t.Fatalf("unknown feature: %v", err)
	}
}
