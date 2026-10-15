package tenant

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/plan"
)

// An organization with no stored plan reports plan.Unassigned, the value the
// repository and the entitlement service resolve a missing row to; a stored
// plan is reported as stored.
func TestTenantPlan(t *testing.T) {
	org, err := NewTenant("Acme", "acme", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := org.Plan(); got != plan.Unassigned {
		t.Fatalf("no stored plan: got %q", got)
	}
	if _, ok := org.StoredPlan(); ok {
		t.Fatal("a new organization has no stored plan")
	}
	if err := org.SetPlan(plan.Free); err != nil {
		t.Fatal(err)
	}
	if p, ok := org.StoredPlan(); !ok || p != plan.Free || org.Plan() != plan.Free {
		t.Fatalf("stored Free: got %q %v", p, ok)
	}
	if err := org.SetPlan("gold"); !errors.Is(err, plan.ErrInvalid) {
		t.Fatalf("unknown plan: %v", err)
	}
	if org.Plan() != plan.Free {
		t.Fatal("a refused plan must not replace the stored one")
	}
}
