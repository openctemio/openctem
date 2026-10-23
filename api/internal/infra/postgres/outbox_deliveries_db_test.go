package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/outbox"
)

// The per-channel delivery state survives a write and every read path: a
// worker that picks the entry up again must see which channel already got
// the event, or it would send it twice.
func TestOutboxRepository_DeliveriesRoundTrip(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewOutboxRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)

	entry := outbox.NewOutbox(outbox.OutboxParams{TenantID: tenantID, EventType: "new_finding", Title: "t", Severity: outbox.SeverityHigh})
	if err := repo.Create(ctx, entry); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM notification_outbox WHERE id = $1`, entry.ID().String())
	})

	got, err := repo.GetByID(ctx, entry.ID())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.HasDeliveries() {
		t.Fatalf("new entry has deliveries %+v", got.Deliveries())
	}

	now := time.Now()
	ok := outbox.NewChannelDelivery("11111111-1111-1111-1111-111111111111", "ops", "slack")
	ok.RecordSuccess(now, "m-1")
	bad := outbox.NewChannelDelivery("22222222-2222-2222-2222-222222222222", "siem", "webhook")
	bad.RecordFailure(now, "webhook returned status 503")
	entry.SetDeliveries([]outbox.ChannelDelivery{ok, bad})
	if entry.SettleDeliveries(now) {
		t.Fatal("pending channel settled the entry")
	}
	// Past the first backoff step, so the batch fetch picks it up.
	ds := entry.Deliveries()
	past := now.Add(-time.Hour)
	ds[1].NextAttemptAt = &past
	entry.SetDeliveries(ds)
	entry.SettleDeliveries(now)
	if err := repo.Update(ctx, entry); err != nil {
		t.Fatalf("update: %v", err)
	}

	check := func(where string, o *outbox.Outbox) {
		t.Helper()
		d := o.Deliveries()
		if len(d) != 2 || d[0].Status != outbox.DeliverySucceeded || d[0].MessageID != "m-1" ||
			d[1].Status != outbox.DeliveryPending || d[1].Attempts != 1 || d[1].LastError != "webhook returned status 503" {
			t.Fatalf("%s: deliveries %+v", where, d)
		}
		if o.MaxRetries() != len(outbox.DeliveryBackoff) {
			t.Fatalf("%s: max_retries %d", where, o.MaxRetries())
		}
	}
	got, err = repo.GetByID(ctx, entry.ID())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	check("GetByID", got)

	batch, err := repo.FetchPendingBatch(ctx, "w-test", 100)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	found := false
	for _, o := range batch {
		if o.ID() == entry.ID() {
			found = true
			check("FetchPendingBatch", o)
		}
	}
	if !found {
		t.Fatal("due entry not fetched")
	}
}
