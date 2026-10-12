package apikey

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

type fixedMembership struct{ m *tenantdom.Membership }

func (f fixedMembership) GetMembership(context.Context, shared.ID, shared.ID) (*tenantdom.Membership, error) {
	return f.m, nil
}

type fixedUser struct{ u *userdom.User }

func (f fixedUser) GetByID(context.Context, shared.ID) (*userdom.User, error) { return f.u, nil }

// A user-bound key works only while its holder is an ACTIVE member with an
// active account: a disabled or offboarded holder's key is refused at
// authentication (member lifecycle).
func TestMembershipChecker_ActiveHolderOnly(t *testing.T) {
	u, err := userdom.New("holder@example.com", "Holder")
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	for status, want := range map[tenantdom.MemberStatus]bool{
		tenantdom.MemberStatusActive:     true,
		tenantdom.MemberStatusSuspended:  false,
		tenantdom.MemberStatusOffboarded: false,
	} {
		m := tenantdom.ReconstituteMembershipWithStatus(shared.NewID(), u.ID(), shared.NewID(), tenantdom.RoleMember,
			nil, time.Now(), status, nil, nil)
		got, err := NewMembershipChecker(fixedMembership{m}, fixedUser{u}).IsActiveMember(context.Background(), m.TenantID(), u.ID())
		if err != nil || got != want {
			t.Errorf("holder %s: active=%v err=%v, want %v", status, got, err, want)
		}
	}
}
