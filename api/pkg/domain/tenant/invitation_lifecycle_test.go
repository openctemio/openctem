package tenant

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestInvitation_MarkResentCooldownAndCap(t *testing.T) {
	inv, err := NewInvitation(shared.NewID(), "a@example.com", RoleMember, shared.NewID(), []string{"00000000-0000-0000-0000-000000000003"})
	if err != nil {
		t.Fatal(err)
	}
	now := inv.CreatedAt()
	if err := inv.MarkResent(now.Add(time.Minute)); !errors.Is(err, ErrInvitationResendTooSoon) {
		t.Fatalf("resend a minute after creation: %v", err)
	}
	at := now
	for i := 0; i < MaxInvitationResends; i++ {
		at = at.Add(ResendCooldown)
		if err := inv.MarkResent(at); err != nil {
			t.Fatalf("resend %d: %v", i+1, err)
		}
	}
	if inv.ResendCount() != MaxInvitationResends || !inv.LastSentAt().Equal(at.UTC()) {
		t.Fatalf("count=%d last=%v", inv.ResendCount(), inv.LastSentAt())
	}
	if err := inv.MarkResent(at.Add(24 * time.Hour)); !errors.Is(err, ErrInvitationResendTooSoon) {
		t.Fatalf("resend beyond the cap: %v", err)
	}
}

func TestInvitation_InviteeInfo(t *testing.T) {
	inv, _ := NewInvitation(shared.NewID(), "a@example.com", RoleMember, shared.NewID(), []string{"00000000-0000-0000-0000-000000000003"})
	if inv.InviteeInfo().Kind != MemberKindInternal {
		t.Fatal("unknown kind must read as internal")
	}
	if err := inv.SetInviteeInfo(InviteeInfo{Kind: "alien"}); err == nil {
		t.Fatal("an unknown kind was accepted")
	}
	if err := inv.SetInviteeInfo(InviteeInfo{Kind: MemberKindExternal, Privileged: true}); err != nil || !inv.InviteeInfo().Privileged {
		t.Fatalf("set: %v", err)
	}
}
