package controller

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// TestPublishTenantChange_EnqueuesWholeTenant proves a whole-tenant sweep is
// enqueued (no asset scope) with the given reason kind — the shape a priority-
// rule change relies on.
func TestPublishTenantChange_EnqueuesWholeTenant(t *testing.T) {
	q := &captureQueue{}
	p := NewControlChangePublisher(q, nil)
	tid := shared.NewID()

	p.PublishTenantChange(context.Background(), tid, ReasonRuleChanged, "priority rule created")

	if len(q.reqs) != 1 {
		t.Fatalf("want 1 enqueued request, got %d", len(q.reqs))
	}
	r := q.reqs[0]
	if r.TenantID != tid {
		t.Fatalf("tenant = %s, want %s", r.TenantID, tid)
	}
	if r.Reason != ReasonRuleChanged {
		t.Fatalf("reason = %s, want %s", r.Reason, ReasonRuleChanged)
	}
	if len(r.AssetIDs) != 0 {
		t.Fatalf("whole-tenant sweep must carry no AssetIDs, got %d", len(r.AssetIDs))
	}
}

// TestPublishTenantChange_NilQueueNoPanic guards the nil-safety contract.
func TestPublishTenantChange_NilQueueNoPanic(t *testing.T) {
	p := NewControlChangePublisher(nil, nil)
	p.PublishTenantChange(context.Background(), shared.NewID(), ReasonRuleChanged, "x")
}
