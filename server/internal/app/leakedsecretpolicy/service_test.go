package leakedsecretpolicy

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/consolesetting"
	cst "github.com/openctemio/openctem/server/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func newSvc(managed bool) (*Service, *cst.Audit) {
	audit := &cst.Audit{}
	return NewService(cst.NewRepo(), cst.Recorder(audit, &cst.Notifier{}), managed, logger.NewNop()), audit
}

// Defaults: kept on a self-managed install (the behavior before the
// setting), not kept on a managed service; a stored value wins at once.
func TestPlatformDefaultAndChange(t *testing.T) {
	ctx := context.Background()
	if svc, _ := newSvc(false); !svc.PlatformDefault(ctx) {
		t.Fatal("self-managed default must keep values")
	}
	svc, audit := newSvc(true)
	if svc.PlatformDefault(ctx) {
		t.Fatal("managed default must not keep values")
	}
	s, err := svc.Update(ctx, cst.SuperAdmin(t), true, "single-customer cell", 0, "", "")
	if err != nil || !s.StoreByDefault || s.Source != SourceConsole || s.Default {
		t.Fatalf("update: %+v %v", s, err)
	}
	if !svc.PlatformDefault(ctx) {
		t.Fatal("the stored value must apply at once")
	}
	if len(audit.Entries) != 1 || audit.Entries[0].Action != ActionChanged {
		t.Fatalf("audit entries = %d", len(audit.Entries))
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), false, "x", 0, "", ""); err == nil {
		t.Fatal("a stale version must be refused")
	}
}

func TestUpdateRefusals(t *testing.T) {
	ctx := context.Background()
	svc, _ := newSvc(false)
	if _, err := svc.Update(ctx, nil, true, "r", 0, "", ""); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), false, "  ", 0, "", ""); !errors.Is(err, consolesetting.ErrReasonRequired) {
		t.Fatalf("no reason: %v", err)
	}
}

type fakeTenants map[shared.ID]*tenant.Tenant

func (f fakeTenants) GetByID(_ context.Context, id shared.ID) (*tenant.Tenant, error) {
	if t, ok := f[id]; ok {
		return t, nil
	}
	return nil, shared.ErrNotFound
}

func newTenant(t *testing.T, store *bool) *tenant.Tenant {
	t.Helper()
	tn, err := tenant.NewTenant("Org "+shared.NewID().String()[:8], "org-"+shared.NewID().String()[:8], shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := tn.UpdateCredentialSettings(tenant.CredentialSettings{StoreSecretValues: store}); err != nil {
		t.Fatal(err)
	}
	return tn
}

// Each organization's choice is its own: one organization turning storage
// on or off never changes what another keeps; an organization without a
// choice follows the platform default; an unreadable organization keeps
// nothing (fail closed).
func TestResolver_PerOrganization(t *testing.T) {
	ctx := context.Background()
	on, off := true, false
	a, b, c := newTenant(t, &on), newTenant(t, &off), newTenant(t, nil)
	tenants := fakeTenants{a.ID(): a, b.ID(): b, c.ID(): c}

	managed, _ := newSvc(true)
	r := NewResolver(managed, tenants, logger.NewNop())
	if !r.StoresSecretValues(ctx, a.ID()) || r.StoresSecretValues(ctx, b.ID()) || r.StoresSecretValues(ctx, c.ID()) {
		t.Fatal("managed: a on, b off, c follows default off")
	}
	selfManaged, _ := newSvc(false)
	r = NewResolver(selfManaged, tenants, logger.NewNop())
	if !r.StoresSecretValues(ctx, a.ID()) || r.StoresSecretValues(ctx, b.ID()) || !r.StoresSecretValues(ctx, c.ID()) {
		t.Fatal("self-managed: a on, b off, c follows default on")
	}
	if r.StoresSecretValues(ctx, shared.NewID()) {
		t.Fatal("unknown organization must fail closed")
	}
	var nilResolver *Resolver
	if nilResolver.StoresSecretValues(ctx, a.ID()) {
		t.Fatal("nil resolver keeps nothing")
	}
}
