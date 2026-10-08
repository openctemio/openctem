package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/accessrequest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Access requests (migration 001376) as the application role: round trip,
// the conditional decision update, counts, listing and retention.
// Requires DATABASE_URL.
func TestAccessRequestRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewAccessRequestRepository(&DB{DB: sqlDB})
	domain := "ar-" + shared.NewID().String()[:8] + ".example.com"
	ip := "iphash-" + shared.NewID().String()
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM access_requests WHERE domain = $1`, domain)
	})

	now := time.Now().UTC().Truncate(time.Microsecond)
	a := &accessrequest.Request{
		ID: shared.NewID(), Company: "Acme", Email: "owner@" + domain, Domain: domain, Note: "n",
		Status: accessrequest.StatusUnconfirmed, IPHash: ip, ConfirmHash: "h-" + shared.NewID().String(), CreatedAt: now,
	}
	if err := r.Create(ctx, a); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := r.GetByConfirmHash(ctx, a.ConfirmHash)
	if err != nil || got.ID != a.ID || got.Status != accessrequest.StatusUnconfirmed {
		t.Fatalf("by hash: %+v %v", got, err)
	}

	// Confirm, then a second confirm with the stale expected status fails.
	got.Status, got.ConfirmHash, got.ConfirmedAt = accessrequest.StatusPending, "", &now
	if err := r.Update(ctx, got, accessrequest.StatusUnconfirmed); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if err := r.Update(ctx, got, accessrequest.StatusUnconfirmed); !errors.Is(err, accessrequest.ErrNotDecidable) {
		t.Fatalf("a stale expected status must be refused, got %v", err)
	}
	if _, err := r.GetByConfirmHash(ctx, a.ConfirmHash); !errors.Is(err, accessrequest.ErrNotFound) {
		t.Fatalf("a used token must not be found, got %v", err)
	}

	if n, _ := r.CountByIPSince(ctx, ip, now.Add(-time.Hour)); n != 1 {
		t.Fatalf("ip count = %d", n)
	}
	if n, _ := r.CountByDomainSince(ctx, domain, now.Add(-time.Hour)); n != 1 {
		t.Fatalf("domain count = %d", n)
	}
	open, total, err := r.List(ctx, accessrequest.Filter{})
	if err != nil || total < 1 {
		t.Fatalf("list: %v %d", err, total)
	}
	found := false
	for _, x := range open {
		found = found || x.ID == a.ID
	}
	if !found {
		t.Fatal("the pending request must be listed as open")
	}

	// Decided long ago: purged; a fresh unconfirmed one is kept.
	old := now.Add(-accessrequest.DecidedRetention - time.Hour)
	by := shared.NewID()
	got.Status, got.DecidedAt, got.DecidedBy = accessrequest.StatusRejected, &old, &by
	if err := r.Update(ctx, got, accessrequest.StatusPending); err != nil {
		t.Fatalf("decide: %v", err)
	}
	fresh := &accessrequest.Request{ID: shared.NewID(), Company: "B", Email: "b@" + domain, Domain: domain,
		Status: accessrequest.StatusUnconfirmed, CreatedAt: now}
	if err := r.Create(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Purge(ctx, now.Add(-accessrequest.UnconfirmedTTL), now.Add(-accessrequest.DecidedRetention)); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if _, err := r.GetByID(ctx, a.ID); !errors.Is(err, accessrequest.ErrNotFound) {
		t.Fatalf("the old decided request must be purged, got %v", err)
	}
	if _, err := r.GetByID(ctx, fresh.ID); err != nil {
		t.Fatalf("the fresh request must stay, got %v", err)
	}
}
