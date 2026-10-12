package scope

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// approved_at is set only once an entry is approved: at creation when it
// needs no approval, at the last approval otherwise; never while pending.
func TestEntryApprovedAtOnlyWhenApproved(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	tenant := shared.NewID()

	pending, err := NewEntry(tenant, TargetTypeDomain, "*.example.com", "", "requester", EntryOptions{
		MaxTier: TierActive, ApprovalsRequired: 1, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pending.IsPending() || pending.ApprovedAt() != nil {
		t.Fatalf("pending entry: pending=%v approved_at=%v, want pending and no approval time", pending.IsPending(), pending.ApprovedAt())
	}
	later := now.Add(time.Hour)
	if _, err := pending.Approve("approver", later); err != nil {
		t.Fatal(err)
	}
	if got := pending.ApprovedAt(); got == nil || !got.Equal(later) {
		t.Fatalf("approved entry: approved_at = %v, want %v", got, later)
	}

	rejected, err := NewEntry(tenant, TargetTypeDomain, "*.example.org", "", "requester", EntryOptions{
		MaxTier: TierActive, ApprovalsRequired: 1, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rejected.Reject("approver", later); err != nil {
		t.Fatal(err)
	}
	if rejected.ApprovedAt() != nil {
		t.Fatalf("rejected entry: approved_at = %v, want none", rejected.ApprovedAt())
	}

	active, err := NewEntry(tenant, TargetTypeDomain, "*.example.net", "", "owner", EntryOptions{
		MaxTier: TierActive, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := active.ApprovedAt(); got == nil || !got.Equal(now) {
		t.Fatalf("entry needing no approval: approved_at = %v, want %v", got, now)
	}
}
