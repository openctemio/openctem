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
		got, err := NewMembershipChecker(fixedMembership{m}, fixedUser{u}, nil).IsActiveMember(context.Background(), m.TenantID(), u.ID())
		if err != nil || got != want {
			t.Errorf("holder %s: active=%v err=%v, want %v", status, got, err, want)
		}
	}
}

// An expired membership end date counts at once: the minute sweeper that
// suspends the membership must not leave a window for keys and MCP tokens.
func TestMembershipChecker_ExpiredMembershipRefused(t *testing.T) {
	u, err := userdom.New("ext@example.com", "External")
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	for name, tc := range map[string]struct {
		expires *time.Time
		want    bool
	}{"no end date": {nil, true}, "ends later": {&future, true}, "ended": {&past, false}} {
		m := tenantdom.ReconstituteMembershipWithStatus(shared.NewID(), u.ID(), shared.NewID(), tenantdom.RoleMember,
			nil, time.Now(), tenantdom.MemberStatusActive, nil, nil).
			WithAccessState("", nil, "", tc.expires, "", "")
		got, err := NewMembershipChecker(fixedMembership{m}, fixedUser{u}, nil).IsActiveMember(context.Background(), m.TenantID(), u.ID())
		if err != nil || got != tc.want {
			t.Errorf("%s: active=%v err=%v, want %v", name, got, err, tc.want)
		}
	}
}
