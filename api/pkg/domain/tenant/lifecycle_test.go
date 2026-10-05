package tenant

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func memberWith(role Role, status MemberStatus) *Membership {
	return ReconstituteMembershipWithStatus(shared.NewID(), shared.NewID(), shared.NewID(), role, nil, time.Now(), status, nil, nil)
}

func TestMembership_IsActiveIsPositive(t *testing.T) {
	for status, want := range map[MemberStatus]bool{
		MemberStatusActive:     true,
		MemberStatusSuspended:  false,
		MemberStatusOffboarded: false,
		MemberStatus("later"):  false,
	} {
		if got := memberWith(RoleMember, status).IsActive(); got != want {
			t.Errorf("IsActive(%s) = %v, want %v", status, got, want)
		}
	}
}

func TestMembership_OffboardAndRejoin(t *testing.T) {
	if err := memberWith(RoleOwner, MemberStatusActive).Offboard(); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("offboarding the owner: want validation error, got %v", err)
	}
	m := memberWith(RoleAdmin, MemberStatusSuspended)
	if err := m.Offboard(); err != nil {
		t.Fatalf("offboard a suspended member: %v", err)
	}
	if !m.IsOffboarded() || m.IsActive() {
		t.Fatal("offboarded membership must be offboarded and not active")
	}
	if err := m.Offboard(); err == nil {
		t.Error("offboarding twice must fail")
	}
	if err := m.Suspend(shared.NewID()); err == nil {
		t.Error("suspending a tombstone must fail")
	}
	if err := m.Reactivate(); err == nil {
		t.Error("reactivating a tombstone must fail (a re-join starts from zero)")
	}
	if err := m.Rejoin(RoleOwner, nil); err == nil {
		t.Error("a re-join can never grant owner")
	}
	if err := m.Rejoin(RoleViewer, nil); err != nil {
		t.Fatalf("rejoin: %v", err)
	}
	if !m.IsActive() || m.Role() != RoleViewer {
		t.Errorf("after rejoin: active=%v role=%s", m.IsActive(), m.Role())
	}
	if err := m.Rejoin(RoleViewer, nil); err == nil {
		t.Error("rejoin of an active membership must fail")
	}
}

func TestOffboardPlan_Missing(t *testing.T) {
	to := shared.NewID()
	full := &AccessReport{
		OwnedScans:       []LifecycleRef{{ID: "s"}},
		AssignedFindings: 2,
		OwnedAssets:      1,
	}
	if got := (OffboardPlan{}).Missing(full); len(got) != 3 {
		t.Errorf("empty plan missing = %v, want 3 categories", got)
	}
	if got := (OffboardPlan{SchedulesTo: &to, UnassignFindings: true, AssetsTo: &to}).Missing(full); len(got) != 0 {
		t.Errorf("complete plan missing = %v", got)
	}
	if got := (OffboardPlan{}).Missing(&AccessReport{}); len(got) != 0 {
		t.Errorf("nothing owned needs nothing, got %v", got)
	}
	if got := (OffboardPlan{SchedulesTo: &to, FindingsTo: &to, AssetsTo: &to}).Targets(); len(got) != 1 {
		t.Errorf("Targets dedupes, got %v", got)
	}
}
