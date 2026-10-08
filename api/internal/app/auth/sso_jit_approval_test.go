package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type fakeApprovalNotifier struct{ calls int }

func (f *fakeApprovalNotifier) NotifyAdmins(_ context.Context, _ shared.ID, _, _, _ string) {
	f.calls++
}

func requireApproval(t *testing.T, tn *tenantdom.Tenant) {
	t.Helper()
	st := tn.TypedSettings()
	st.Security.JITRequiresApproval = true
	if err := tn.UpdateSettings(st); err != nil {
		t.Fatal(err)
	}
}

// Approval-required JIT (RFC-058): the newcomer gets a membership that waits,
// suspended, and no session; the administrators are told.
func TestJITApproval_HoldsNewcomer(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	requireApproval(t, tenant)
	n := &fakeApprovalNotifier{}
	svc.SetJITApprovalNotifier(n)
	rp := &resolvedProvider{autoProvision: true, defaultRole: "member"}

	err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com")
	if !errors.Is(err, ErrSSOAwaitingApproval) {
		t.Fatalf("want ErrSSOAwaitingApproval, got %v", err)
	}
	if mr.created == nil || !mr.created.AwaitsApproval() || mr.created.IsActive() {
		t.Fatalf("membership must be created suspended, awaiting approval: %+v", mr.created)
	}
	if n.calls != 1 {
		t.Fatalf("administrators notified %d times, want 1", n.calls)
	}

	// The next sign-in, still waiting: refused again, nothing created.
	mr.existing, mr.created = mr.created, nil
	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); !errors.Is(err, ErrSSOAwaitingApproval) {
		t.Fatalf("waiting member: want ErrSSOAwaitingApproval, got %v", err)
	}
	if mr.created != nil {
		t.Fatal("no second membership")
	}
}

func TestJITApproval_OffAdmitsDirectly(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	rp := &resolvedProvider{autoProvision: true, defaultRole: "viewer"}
	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); err != nil {
		t.Fatal(err)
	}
	if mr.created == nil || !mr.created.IsActive() || mr.created.Role() != tenantdom.RoleViewer {
		t.Fatalf("membership must be active viewer: %+v", mr.created)
	}
}

func TestJITRaises(t *testing.T) {
	for _, tc := range []struct {
		oldOn   bool
		oldRole string
		on      bool
		role    string
		raises  bool
	}{
		{false, "", true, "viewer", true},
		{true, "viewer", true, "member", true},
		{true, "viewer", true, "", true},
		{true, "", true, "member", true},
		{true, "member", true, "viewer", false},
		{true, "member", false, "", false},
		{true, "member", true, "", false},
		{true, "viewer", true, "viewer", false},
	} {
		if got := JITRaises(tc.oldOn, tc.oldRole, tc.on, tc.role); got != tc.raises {
			t.Errorf("%v/%q -> %v/%q: raises=%v, want %v", tc.oldOn, tc.oldRole, tc.on, tc.role, got, tc.raises)
		}
	}
}
