package platformuser

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeBlocker struct{ blocked map[shared.ID]bool }

func (f *fakeBlocker) SetBlocked(_ context.Context, id shared.ID, blocked bool, _ *shared.ID, _ string) (bool, error) {
	if f.blocked[id] == blocked {
		return false, nil
	}
	f.blocked[id] = blocked
	return true, nil
}

type auditRows struct{ rows []*admin.AuditLog }

func (a *auditRows) Create(_ context.Context, l *admin.AuditLog) error {
	a.rows = append(a.rows, l)
	return nil
}

func opsAdmin() *admin.AdminUser {
	now := time.Now()
	return admin.Reconstitute(shared.NewID(), "ops@example.com", "Ops", admin.AdminRoleOpsAdmin, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now)
}

func TestBlockAndUnblock(t *testing.T) {
	ctx := context.Background()
	u := localUser(t, true)
	rev := &fakeRevoker{}
	b := &fakeBlocker{blocked: map[shared.ID]bool{}}
	audit := &auditRows{}
	s := NewService(&fakeUsers{u: u}, rev, nil, nil, &fakeStates{}, Durations{})
	s.SetBlocking(b, audit, nil)
	actor := opsAdmin()

	if err := s.Block(ctx, actor, u.ID(), "spam campaign", Client{IP: "203.0.113.1"}); err != nil {
		t.Fatalf("block: %v", err)
	}
	if !b.blocked[u.ID()] || rev.userID != u.ID().String() {
		t.Fatalf("blocked=%v sessions revoked for %q", b.blocked[u.ID()], rev.userID)
	}
	if len(audit.rows) != 1 || audit.rows[0].Action != ActionUserBlocked || audit.rows[0].Severity != admin.SeverityCritical {
		t.Fatalf("audit = %+v", audit.rows)
	}
	if err := s.Block(ctx, actor, u.ID(), "second attempt", Client{}); !errors.Is(err, ErrAlreadyBlocked) {
		t.Fatalf("second block: %v", err)
	}
	if err := s.Unblock(ctx, actor, u.ID(), "resolved with the user", Client{}); err != nil || b.blocked[u.ID()] {
		t.Fatalf("unblock: %v blocked=%v", err, b.blocked[u.ID()])
	}
	if last := audit.rows[len(audit.rows)-1]; last.Action != ActionUserUnblocked || last.Severity != admin.SeverityCritical {
		t.Fatalf("unblock audit = %+v", last)
	}
	if err := s.Unblock(ctx, actor, u.ID(), "second attempt", Client{}); !errors.Is(err, ErrNotBlocked) {
		t.Fatalf("second unblock: %v", err)
	}
}

func TestBlockRefusals(t *testing.T) {
	ctx := context.Background()
	u := localUser(t, true)
	b := &fakeBlocker{blocked: map[shared.ID]bool{}}
	for _, r := range []string{"", "  ", "too short", strings.Repeat("x", MaxBlockReasonRunes+1)} {
		s := NewService(&fakeUsers{u: u}, nil, nil, nil, &fakeStates{}, Durations{})
		s.SetBlocking(b, nil, nil)
		if err := s.Block(ctx, opsAdmin(), u.ID(), r, Client{}); !errors.Is(err, ErrBlockReasonRequired) {
			t.Fatalf("reason %q: %v", r, err)
		}
	}
	// Platform administrator and erased accounts are refused, as for every
	// support action.
	for _, st := range []*fakeStates{{admin: true}, {erased: true}} {
		s := NewService(&fakeUsers{u: u}, nil, nil, nil, st, Durations{})
		s.SetBlocking(b, nil, nil)
		if err := s.Block(ctx, opsAdmin(), u.ID(), "abuse report 42", Client{}); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("%+v: %v", st, err)
		}
	}
	if b.blocked[u.ID()] {
		t.Fatal("a refused block changed the account")
	}
	s := NewService(&fakeUsers{u: u}, nil, nil, nil, &fakeStates{}, Durations{})
	if err := s.Block(ctx, opsAdmin(), u.ID(), "abuse report 42", Client{}); err == nil {
		t.Fatal("block without a blocker must be refused")
	}
	if err := s.Block(ctx, nil, u.ID(), "abuse report 42", Client{}); err == nil {
		t.Fatal("block without an administrator must be refused")
	}
}
