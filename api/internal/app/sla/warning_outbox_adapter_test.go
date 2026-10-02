package sla

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Warning-adapter tests mirror the breach ones: translation from
// SLAWarningEvent → outbox notification, severity, and nil-safety.

func newWarningEvent() controller.SLAWarningEvent {
	return controller.SLAWarningEvent{
		TenantID:      shared.NewID(),
		FindingID:     shared.NewID(),
		SLADeadline:   time.Date(2026, 1, 4, 12, 0, 0, 0, time.UTC),
		TimeRemaining: 2*24*time.Hour + 3*time.Hour,
		At:            time.Date(2026, 1, 2, 9, 0, 0, 0, time.UTC),
	}
}

func TestWarningAdapter_PublishWarning_EnqueuesMediumNotification(t *testing.T) {
	enq := &fakeEnqueuer{}
	adapter := NewWarningOutboxAdapter(enq)

	ev := newWarningEvent()
	if err := adapter.PublishWarning(context.Background(), ev); err != nil {
		t.Fatalf("publish warning: %v", err)
	}
	if enq.calls != 1 {
		t.Fatalf("enqueue calls = %d, want 1", enq.calls)
	}
	if enq.last.EventType != "sla_warning" {
		t.Fatalf("event type = %q, want sla_warning", enq.last.EventType)
	}
	if enq.last.Severity != "medium" {
		t.Fatalf("severity = %q, want medium (approaching, not missed)", enq.last.Severity)
	}
	if enq.last.Metadata["finding_id"] != ev.FindingID.String() {
		t.Fatalf("metadata finding_id = %v, want %s", enq.last.Metadata["finding_id"], ev.FindingID.String())
	}
}

func TestWarningAdapter_PublishWarning_NilEnqueuer_NoOp(t *testing.T) {
	var adapter *WarningOutboxAdapter
	if err := adapter.PublishWarning(context.Background(), newWarningEvent()); err != nil {
		t.Fatalf("nil adapter should no-op, got %v", err)
	}
	adapter2 := NewWarningOutboxAdapter(nil)
	if err := adapter2.PublishWarning(context.Background(), newWarningEvent()); err != nil {
		t.Fatalf("nil enqueuer should no-op, got %v", err)
	}
}
