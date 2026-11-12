package outbox

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestChannelDelivery_BackoffScheduleThenDead(t *testing.T) {
	now := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	d := NewChannelDelivery("i1", "ops", "webhook")
	if !d.Due(now) {
		t.Fatal("a new delivery is due at once")
	}
	want := []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour}
	for i, w := range want {
		d.RecordFailure(now, "boom")
		if d.Status != DeliveryPending || d.NextAttemptAt == nil || !d.NextAttemptAt.Equal(now.Add(w)) {
			t.Fatalf("after failure %d: status %s next %v, want pending at +%s", i+1, d.Status, d.NextAttemptAt, w)
		}
		if d.Due(now) {
			t.Fatalf("after failure %d the channel must wait", i+1)
		}
	}
	d.RecordFailure(now, "boom")
	if d.Status != DeliveryDead || d.Attempts != MaxDeliveryAttempts() || d.NextAttemptAt != nil {
		t.Fatalf("after %d attempts: status %s attempts %d", MaxDeliveryAttempts(), d.Status, d.Attempts)
	}
}

func TestSettleDeliveries_PendingChannelKeepsEntry(t *testing.T) {
	now := time.Now()
	o := NewOutbox(OutboxParams{TenantID: shared.NewID(), EventType: "new_finding", Title: "t"})
	ok := NewChannelDelivery("a", "A", "slack")
	ok.RecordSuccess(now, "m1")
	bad := NewChannelDelivery("b", "B", "webhook")
	bad.RecordFailure(now, "503")
	o.SetDeliveries([]ChannelDelivery{ok, bad})

	if o.SettleDeliveries(now) {
		t.Fatal("an entry with a pending channel must not settle")
	}
	if o.Status() != OutboxStatusPending || !o.ScheduledAt().Equal(now.Add(time.Minute)) {
		t.Fatalf("status %s scheduled %v, want pending at +1m", o.Status(), o.ScheduledAt())
	}
	if o.RetryCount() > o.MaxRetries()+1 {
		t.Fatalf("retry_count %d breaks the column check (max_retries %d)", o.RetryCount(), o.MaxRetries())
	}

	ds := o.Deliveries()
	for ds[1].Status == DeliveryPending {
		ds[1].RecordFailure(now, "503")
	}
	o.SetDeliveries(ds)
	if !o.SettleDeliveries(now) || o.Status() != OutboxStatusCompleted {
		t.Fatalf("all channels terminal: status %s", o.Status())
	}
	if o.RetryCount() != MaxDeliveryAttempts()-1 || o.RetryCount() > o.MaxRetries()+1 {
		t.Fatalf("retry_count %d max_retries %d", o.RetryCount(), o.MaxRetries())
	}
	succeeded, failed, results := o.DeliveryResults()
	if succeeded != 1 || failed != 1 || len(results) != 2 {
		t.Fatalf("results %d/%d/%d", succeeded, failed, len(results))
	}
	if results[1].Attempts != MaxDeliveryAttempts() || results[1].Error != "503" {
		t.Fatalf("dead channel result %+v", results[1])
	}
}

func TestResetForRetry_RevivesOnlyDeadChannels(t *testing.T) {
	now := time.Now()
	o := NewOutbox(OutboxParams{TenantID: shared.NewID(), EventType: "new_finding", Title: "t"})
	ok := NewChannelDelivery("a", "A", "slack")
	ok.RecordSuccess(now, "")
	dead := NewChannelDelivery("b", "B", "webhook")
	dead.Abandon(now, "gone")
	o.SetDeliveries([]ChannelDelivery{ok, dead})
	o.ResetForRetry()
	ds := o.Deliveries()
	if ds[0].Status != DeliverySucceeded {
		t.Fatal("a delivered channel must not be sent the event again")
	}
	if ds[1].Status != DeliveryPending || ds[1].Attempts != 0 || !ds[1].Due(now) {
		t.Fatalf("dead channel not revived: %+v", ds[1])
	}
}
