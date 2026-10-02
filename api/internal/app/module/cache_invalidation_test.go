package module

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/logger"
)

type fakeInvalidator struct {
	calls []string
}

func (f *fakeInvalidator) Invalidate(tenantID string) {
	f.calls = append(f.calls, tenantID)
}

// A module-config change must invalidate the route-gate cache for that tenant so
// the toggle enforces immediately instead of after the gate TTL.
func TestNotifyModuleChange_InvalidatesGateCache(t *testing.T) {
	s := NewModuleService(nil, logger.NewNop())
	inv := &fakeInvalidator{}
	s.SetModuleCacheInvalidator(inv)

	s.notifyModuleChange(context.Background(), "tenant-1")

	if len(inv.calls) != 1 || inv.calls[0] != "tenant-1" {
		t.Errorf("expected Invalidate(tenant-1) exactly once, got %v", inv.calls)
	}
}

// Without an invalidator wired, notifyModuleChange is a safe no-op.
func TestNotifyModuleChange_NilInvalidatorSafe(t *testing.T) {
	s := NewModuleService(nil, logger.NewNop())
	// Must not panic.
	s.notifyModuleChange(context.Background(), "tenant-1")
}
