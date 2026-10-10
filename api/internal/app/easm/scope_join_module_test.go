package easm

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// pendingRecorder records which tenants the join read pending records for.
type pendingRecorder struct {
	ScopeJoinStore
	tenants []shared.ID
	read    []shared.ID
}

func (p *pendingRecorder) TenantsWithPendingAutomatic(context.Context) ([]shared.ID, error) {
	return p.tenants, nil
}

func (p *pendingRecorder) PendingAutomatic(_ context.Context, t shared.ID, _ int) ([]JoinItem, error) {
	p.read = append(p.read, t)
	return nil, nil
}

type attackSurfaceOff map[string]bool

func (m attackSurfaceOff) TenantDisabledModules(_ context.Context, tenantID string) map[string]bool {
	return map[string]bool{"attack_surface": m[tenantID]}
}

// The background re-evaluation leaves a tenant with attack_surface off alone:
// its pending records stay pending. Another tenant is re-evaluated.
func TestScopeJoinReevaluateAll_SkipsAttackSurfaceOff(t *testing.T) {
	off, on := shared.NewID(), shared.NewID()
	store := &pendingRecorder{tenants: []shared.ID{off, on}}
	j := NewScopeJoin(ScopeJoinTargets(nil), ScopeJoinExclusions(nil), store, ActiveGateAssets(nil), logger.NewNop())
	// ready() needs every source; the stubs are never called with no pending records.
	j.targets, j.exclusions, j.assets = stubTargets{}, stubExclusions{}, stubAssets{}
	j.SetModuleGuard(attackSurfaceOff{off.String(): true})

	if _, err := j.ReevaluateAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.read) != 1 || store.read[0] != on {
		t.Fatalf("re-evaluated %v, want only %v", store.read, on)
	}
}

type stubTargets struct{ ScopeJoinTargets }
type stubExclusions struct{ ScopeJoinExclusions }
type stubAssets struct{ ActiveGateAssets }
