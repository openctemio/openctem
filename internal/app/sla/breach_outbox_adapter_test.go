package sla

import (
	"github.com/openctemio/api/internal/app/outbox"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/infra/controller"
	"github.com/openctemio/api/pkg/domain/shared"
)

// B4 wire tests. The adapter is the wire; tests cover its translation
// from SLABreachEvent → outbox notification, plus nil-safety. The
// underlying OutboxService.Enqueue is covered by its own
// unit tests.

type fakeEnqueuer struct {
	calls  int
	err    error
	last   outbox.EnqueueParams
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, params outbox.EnqueueParams) error {
	f.calls++
	f.last = params
	return f.err
}

func newEvent() controller.SLABreachEvent {
	return controller.SLABreachEvent{
		TenantID:        shared.NewID(),
		FindingID:       shared.NewID(),
		SLADeadline:     time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		OverdueDuration: 2*time.Hour + 30*time.Minute,
		At:              time.Date(2026, 1, 1, 14, 30, 0, 0, time.UTC),
	}
}

func TestOutboxAdapter_Publish_EnqueuesNotification(t *testing.T) {
	enq := &fakeEnqueuer{}
	adapter := NewBreachOutboxAdapter(enq)

	ev := newEvent()
	if err := adapter.Publish(context.Background(), ev); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if enq.calls != 1 {
		t.Fatalf("enqueue calls = %d, want 1", enq.calls)
	}
	if enq.last.EventType != "sla_breach" {
		t.Fatalf("event type = %q, want sla_breach", enq.last.EventType)
	}
	if enq.last.AggregateType != "finding" {
		t.Fatalf("aggregate type = %q, want finding", enq.last.AggregateType)
	}
	if enq.last.Severity != "high" {
		t.Fatalf("severity = %q, want high", enq.last.Severity)
	}
	if enq.last.TenantID != ev.TenantID {
		t.Fatalf("tenant id mismatch")
	}
	if enq.last.AggregateID == nil {
		t.Fatalf("aggregate id should be set")
	}
	if enq.last.AggregateID.String() != ev.FindingID.String() {
		t.Fatalf("aggregate id mismatch: got %s want %s", enq.last.AggregateID, ev.FindingID)
	}
}

func TestOutboxAdapter_Publish_TitleAndBodyContainFindingID(t *testing.T) {
	enq := &fakeEnqueuer{}
	adapter := NewBreachOutboxAdapter(enq)
	ev := newEvent()
	_ = adapter.Publish(context.Background(), ev)

	if !containsString(enq.last.Title, ev.FindingID.String()) {
		t.Fatalf("title missing finding id: %q", enq.last.Title)
	}
	if !containsString(enq.last.Body, ev.FindingID.String()) {
		t.Fatalf("body missing finding id: %q", enq.last.Body)
	}
}

func TestOutboxAdapter_Publish_MetadataCarriesBreachContext(t *testing.T) {
	enq := &fakeEnqueuer{}
	adapter := NewBreachOutboxAdapter(enq)
	ev := newEvent()
	_ = adapter.Publish(context.Background(), ev)

	md := enq.last.Metadata
	if md == nil {
		t.Fatal("metadata nil")
	}
	if md["finding_id"] != ev.FindingID.String() {
		t.Fatalf("metadata finding_id mismatch")
	}
	if md["escalation_source"] != "sla_escalation_controller" {
		t.Fatalf("metadata escalation_source mismatch")
	}
	if md["overdue_seconds"] == nil {
		t.Fatal("metadata overdue_seconds missing")
	}
}

func TestOutboxAdapter_Publish_EnqueueError_Propagates(t *testing.T) {
	boom := errors.New("outbox offline")
	adapter := NewBreachOutboxAdapter(&fakeEnqueuer{err: boom})
	err := adapter.Publish(context.Background(), newEvent())
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
}

func TestOutboxAdapter_Publish_NilEnqueuer_NoOp(t *testing.T) {
	adapter := NewBreachOutboxAdapter(nil)
	if err := adapter.Publish(context.Background(), newEvent()); err != nil {
		t.Fatalf("nil enqueuer should be safe: %v", err)
	}
}

func TestOutboxAdapter_Publish_NilAdapter_NoOp(t *testing.T) {
	var adapter *BreachOutboxAdapter
	if err := adapter.Publish(context.Background(), newEvent()); err != nil {
		t.Fatalf("nil adapter should be safe: %v", err)
	}
}

func containsString(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
