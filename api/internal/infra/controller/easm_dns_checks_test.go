package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/easmdns"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeDNSChecker struct {
	dangling, email []shared.ID
	failFor         shared.ID
}

func (f *fakeDNSChecker) MonitorTenant(_ context.Context, id shared.ID) (easmdns.RunResult, error) {
	f.dangling = append(f.dangling, id)
	if id == f.failFor {
		return easmdns.RunResult{}, errors.New("resolver down")
	}
	return easmdns.RunResult{}, nil
}

func (f *fakeDNSChecker) MonitorEmail(_ context.Context, id shared.ID) (easmdns.RunResult, error) {
	f.email = append(f.email, id)
	return easmdns.RunResult{}, nil
}

type disabledFor struct{ tenant string }

func (d disabledFor) TenantDisabledModules(_ context.Context, tenantID string) map[string]bool {
	if tenantID == d.tenant {
		return map[string]bool{moduledom.ModuleAttackSurface: true}
	}
	return nil
}

// Tenants without the attack-surface module are skipped; one tenant's
// failure does not stop the others (fail-open); both checks run per tenant.
func TestEASMDNSController_Reconcile(t *testing.T) {
	ids := mkTenantIDs(3)
	checker := &fakeDNSChecker{failFor: ids[0]}
	c := NewEASMDNSController(checker, &tenantListerMock{ids: ids},
		&EASMDNSControllerConfig{ModuleGuard: disabledFor{tenant: ids[1].String()}})
	if c.Interval().Hours() != 24 {
		t.Fatalf("default interval = %s", c.Interval())
	}
	n, err := c.Reconcile(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("reconcile = %d %v", n, err)
	}
	if len(checker.dangling) != 2 || len(checker.email) != 2 {
		t.Fatalf("dangling=%v email=%v", checker.dangling, checker.email)
	}
	for _, id := range append(checker.dangling, checker.email...) {
		if id == ids[1] {
			t.Fatal("tenant with attack_surface disabled was checked")
		}
	}
	if _, err := NewEASMDNSController(checker, &tenantListerMock{err: errors.New("db")}, nil).Reconcile(context.Background()); err == nil {
		t.Fatal("tenant-list failure must be returned")
	}
}
