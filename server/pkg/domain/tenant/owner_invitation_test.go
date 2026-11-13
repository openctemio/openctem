package tenant

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestOwnerInvitation_Lifecycle(t *testing.T) {
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	if _, err := NewOwnerInvitation(shared.NewID(), shared.ID{}, "a@example.com", shared.ID{}, now); err == nil {
		t.Fatal("an invitation needs an account")
	}
	inv, err := NewOwnerInvitation(shared.NewID(), shared.NewID(), " Owner@Example.com ", shared.ID{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if inv.InviteeEmail != "owner@example.com" || inv.SendCount != 1 || !inv.ExpiresAt.Equal(now.Add(OwnerInvitationTTL)) {
		t.Fatalf("invitation = %+v", inv)
	}
	if !inv.IsOpen(now) || inv.EffectiveStatus(now) != OwnerInvitationPending {
		t.Fatal("new invitation should be open")
	}
	later := inv.ExpiresAt
	if inv.IsOpen(later) || inv.EffectiveStatus(later) != OwnerInvitationExpired {
		t.Fatal("invitation open at its expiry")
	}
	if err := inv.CheckResend(now.Add(time.Minute)); !errors.Is(err, ErrOwnerInvitationResendTooSoon) {
		t.Fatalf("resend too soon: %v", err)
	}
	if err := inv.CheckResend(now.Add(OwnerInvitationResendInterval)); err != nil {
		t.Fatalf("resend after the interval: %v", err)
	}
	inv.SendCount = OwnerInvitationMaxSends
	if err := inv.CheckResend(now.Add(time.Hour)); !errors.Is(err, ErrOwnerInvitationResendLimit) {
		t.Fatalf("resend over the cap: %v", err)
	}
	inv.Status = OwnerInvitationAccepted
	if inv.IsOpen(now) || inv.CheckResend(now.Add(time.Hour)) == nil {
		t.Fatal("an accepted invitation is closed")
	}
}
