package findingimport

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type fakeMembers struct {
	m   *tenant.Membership
	err error
}

func (f fakeMembers) GetMembership(context.Context, shared.ID, shared.ID) (*tenant.Membership, error) {
	return f.m, f.err
}

// The worker narrows the uploader recorded at accept time to the current
// membership: gone or suspended is refused, a demoted administrator loses
// the unrestricted scope, and a current role never widens the record.
func TestCurrentCaller_NarrowsToTheMembershipNow(t *testing.T) {
	ctx := context.Background()
	tid, uid := shared.NewID(), shared.NewID()
	member := func(role tenant.Role) *tenant.Membership {
		m, err := tenant.NewMembership(uid, tid, role, nil)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	suspended := member(tenant.RoleAdmin)
	if err := suspended.Suspend(shared.NewID()); err != nil {
		t.Fatal(err)
	}
	admin := Caller{UserID: uid.String(), IsAdmin: true}
	cases := []struct {
		name      string
		members   fakeMembers
		recorded  Caller
		wantErr   error
		wantAdmin bool
		wantOwner bool
	}{
		{"removed", fakeMembers{err: shared.ErrNotFound}, admin, shared.ErrNotFound, false, false},
		{"suspended", fakeMembers{m: suspended}, admin, shared.ErrNotFound, false, false},
		{"demoted admin", fakeMembers{m: member(tenant.RoleMember)}, admin, nil, false, false},
		{"still admin", fakeMembers{m: member(tenant.RoleAdmin)}, admin, nil, true, false},
		{"demoted owner", fakeMembers{m: member(tenant.RoleAdmin)}, Caller{UserID: uid.String(), IsAdmin: true, IsOwner: true}, nil, true, false},
		{"promoted member is not widened", fakeMembers{m: member(tenant.RoleOwner)}, Caller{UserID: uid.String()}, nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{}
			s.SetMembers(tc.members)
			env := Envelope{Caller: tc.recorded}
			err := s.currentCaller(ctx, tid, &env)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if env.Caller.IsAdmin != tc.wantAdmin || env.Caller.IsOwner != tc.wantOwner {
				t.Fatalf("caller = %+v", env.Caller)
			}
		})
	}

	// A lookup error is retried, never treated as gone or as allowed.
	s := &Service{}
	s.SetMembers(fakeMembers{err: errors.New("db down")})
	env := Envelope{Caller: admin}
	if err := s.currentCaller(ctx, tid, &env); err == nil || errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("lookup error = %v", err)
	}
	// An API key with no user has no membership to re-read.
	env = Envelope{Caller: Caller{APIKey: true}}
	if err := s.currentCaller(ctx, tid, &env); err != nil {
		t.Fatal(err)
	}
}
