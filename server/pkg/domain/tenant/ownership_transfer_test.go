package tenant

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestCheckOwnershipCandidate(t *testing.T) {
	ok := OwnershipCandidate{Active: true, MFAEnabled: true}
	for _, tc := range []struct {
		name    string
		c       OwnershipCandidate
		confirm bool
		want    error
	}{
		{"internal with 2FA", ok, false, nil},
		{"inactive", OwnershipCandidate{MFAEnabled: true}, false, ErrOwnershipTargetInactive},
		{"service account", OwnershipCandidate{Active: true, MFAEnabled: true, Service: true}, false, ErrOwnershipTargetService},
		{"no 2FA", OwnershipCandidate{Active: true}, false, ErrOwnershipTargetNoMFA},
		{"managed outsider", OwnershipCandidate{Active: true, MFAEnabled: true, External: true, Managed: true}, true, ErrOwnershipTargetManaged},
		{"unmanaged outsider, not confirmed", OwnershipCandidate{Active: true, MFAEnabled: true, External: true}, false, ErrOwnershipTargetNeedsInternal},
		{"unmanaged outsider, confirmed", OwnershipCandidate{Active: true, MFAEnabled: true, External: true}, true, nil},
	} {
		if err := CheckOwnershipCandidate(tc.c, tc.confirm); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestNewOwnershipTransfer(t *testing.T) {
	a, b, org := shared.NewID(), shared.NewID(), shared.NewID()
	now := time.Now()
	tr, err := NewOwnershipTransfer(org, a, b, "", false, now)
	if err != nil || tr.PreviousOwnerRole != RoleAdmin || !tr.ExpiresAt.Equal(now.Add(72*time.Hour)) || tr.Status != OwnershipTransferPending {
		t.Fatalf("default transfer = %+v, %v", tr, err)
	}
	if tr.IsExpired(now.Add(71*time.Hour)) || !tr.IsExpired(now.Add(72*time.Hour)) {
		t.Fatal("expiry boundary")
	}
	if _, err := NewOwnershipTransfer(org, a, a, "", false, now); !errors.Is(err, ErrOwnershipTargetSelf) {
		t.Fatalf("self: %v", err)
	}
	if _, err := NewOwnershipTransfer(org, a, b, RoleOwner, false, now); !errors.Is(err, ErrOwnershipPreviousRole) {
		t.Fatalf("owner as previous role: %v", err)
	}
	if !IsOwnershipTransferError(ErrOwnershipTargetNoMFA) || IsOwnershipTransferError(shared.ErrNotFound) {
		t.Fatal("IsOwnershipTransferError")
	}
}
