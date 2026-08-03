package finding

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app/outbox"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

type fakeEnqueuer struct {
	calls []outbox.EnqueueParams
	err   error
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, p)
	return nil
}

func classPtr(c vulnerability.PriorityClass) *vulnerability.PriorityClass { return &c }

func newOutboxPub() (*OutboxPriorityChangePublisher, *fakeEnqueuer) {
	q := &fakeEnqueuer{}
	return NewOutboxPriorityChangePublisher(q, logger.NewNop()), q
}

// TestOutboxPublisher_Escalation_Enqueues is the core case: an operator must
// not miss that a finding they triaged as P3 silently became P0.
func TestOutboxPublisher_Escalation_Enqueues(t *testing.T) {
	p, q := newOutboxPub()
	tid, fid := shared.NewID(), shared.NewID()

	err := p.Publish(context.Background(), PriorityChangeEvent{
		TenantID:      tid,
		FindingID:     fid,
		PreviousClass: classPtr(vulnerability.PriorityP3),
		NewClass:      vulnerability.PriorityP0,
		Reason:        "CVE newly listed in KEV",
		Source:        "sweep",
		At:            time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(q.calls) != 1 {
		t.Fatalf("want 1 enqueue, got %d", len(q.calls))
	}
	got := q.calls[0]
	if got.TenantID != tid {
		t.Errorf("TenantID = %v, want %v", got.TenantID, tid)
	}
	if got.EventType != string(integration.EventTypeFindingPriorityEscalated) {
		t.Errorf("EventType = %q, want %q", got.EventType, integration.EventTypeFindingPriorityEscalated)
	}
	if got.AggregateType != "finding" {
		t.Errorf("AggregateType = %q, want finding", got.AggregateType)
	}
	if got.AggregateID == nil || got.AggregateID.String() != fid.String() {
		t.Errorf("AggregateID = %v, want %v", got.AggregateID, fid)
	}
	// Severity carries the new class so the tenant's existing per-integration
	// severity filter routes it without a new knob.
	if got.Severity != "critical" {
		t.Errorf("Severity = %q, want critical for P0", got.Severity)
	}
	if got.URL != "/findings/"+fid.String() {
		t.Errorf("URL = %q", got.URL)
	}
	if got.Metadata["previous_class"] != "P3" || got.Metadata["new_class"] != "P0" {
		t.Errorf("metadata classes wrong: %+v", got.Metadata)
	}
	if got.Metadata["source"] != "sweep" {
		t.Errorf("metadata source = %v, want sweep", got.Metadata["source"])
	}
}

// TestOutboxPublisher_FirstClassification_DoesNotEnqueue: every newly ingested
// finding gets a first classification, and those are already announced by the
// "new_finding" notification. Publishing them here would double-notify every
// finding of every ingest batch.
func TestOutboxPublisher_FirstClassification_DoesNotEnqueue(t *testing.T) {
	p, q := newOutboxPub()
	if err := p.Publish(context.Background(), PriorityChangeEvent{
		TenantID:      shared.NewID(),
		FindingID:     shared.NewID(),
		PreviousClass: nil,
		NewClass:      vulnerability.PriorityP0,
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(q.calls) != 0 {
		t.Fatalf("first classification must not notify, got %d enqueues", len(q.calls))
	}
}

// TestOutboxPublisher_Deescalation_DoesNotEnqueue: a control was applied and
// the finding got less urgent. Good news does not page anyone.
func TestOutboxPublisher_Deescalation_DoesNotEnqueue(t *testing.T) {
	p, q := newOutboxPub()
	if err := p.Publish(context.Background(), PriorityChangeEvent{
		TenantID:      shared.NewID(),
		FindingID:     shared.NewID(),
		PreviousClass: classPtr(vulnerability.PriorityP0),
		NewClass:      vulnerability.PriorityP2,
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(q.calls) != 0 {
		t.Fatalf("de-escalation must not notify, got %d enqueues", len(q.calls))
	}
}

func TestOutboxPublisher_SeverityMapping(t *testing.T) {
	cases := []struct {
		from, to vulnerability.PriorityClass
		want     string
	}{
		{vulnerability.PriorityP1, vulnerability.PriorityP0, "critical"},
		{vulnerability.PriorityP2, vulnerability.PriorityP1, "high"},
		{vulnerability.PriorityP3, vulnerability.PriorityP2, "medium"},
	}
	for _, c := range cases {
		p, q := newOutboxPub()
		if err := p.Publish(context.Background(), PriorityChangeEvent{
			TenantID:      shared.NewID(),
			FindingID:     shared.NewID(),
			PreviousClass: classPtr(c.from),
			NewClass:      c.to,
		}); err != nil {
			t.Fatalf("Publish %s->%s: %v", c.from, c.to, err)
		}
		if len(q.calls) != 1 {
			t.Fatalf("%s->%s: want 1 enqueue, got %d", c.from, c.to, len(q.calls))
		}
		if q.calls[0].Severity != c.want {
			t.Errorf("%s->%s severity = %q, want %q", c.from, c.to, q.calls[0].Severity, c.want)
		}
	}
}

// TestOutboxPublisher_UnknownClass_NotAnEscalation keeps a garbage or
// future class from being read as "more urgent than everything".
func TestOutboxPublisher_UnknownClass_NotAnEscalation(t *testing.T) {
	p, q := newOutboxPub()
	if err := p.Publish(context.Background(), PriorityChangeEvent{
		TenantID:      shared.NewID(),
		FindingID:     shared.NewID(),
		PreviousClass: classPtr(vulnerability.PriorityP3),
		NewClass:      vulnerability.PriorityClass("P9"),
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(q.calls) != 0 {
		t.Fatalf("unknown class must not notify, got %d enqueues", len(q.calls))
	}
}

func TestOutboxPublisher_NilOutbox_IsNoOp(t *testing.T) {
	p := NewOutboxPriorityChangePublisher(nil, nil)
	if err := p.Publish(context.Background(), PriorityChangeEvent{
		PreviousClass: classPtr(vulnerability.PriorityP3),
		NewClass:      vulnerability.PriorityP0,
	}); err != nil {
		t.Fatalf("nil outbox must be a silent no-op, got %v", err)
	}
}

// TestOutboxPublisher_EnqueueError_Propagates lets publishIfChanged refund the
// flood-guard slot instead of permanently burning it.
func TestOutboxPublisher_EnqueueError_Propagates(t *testing.T) {
	q := &fakeEnqueuer{err: errors.New("db down")}
	p := NewOutboxPriorityChangePublisher(q, logger.NewNop())
	err := p.Publish(context.Background(), PriorityChangeEvent{
		TenantID:      shared.NewID(),
		FindingID:     shared.NewID(),
		PreviousClass: classPtr(vulnerability.PriorityP3),
		NewClass:      vulnerability.PriorityP0,
	})
	if err == nil {
		t.Fatal("enqueue failure must be reported to the caller")
	}
}

// TestClassificationChain_EscalationReachesOutbox is the end-to-end check for
// the whole seam as the composition root assembles it: the real
// PriorityClassificationService, the real flood guard, and the real outbox
// publisher. It drives publishIfChanged — the exact call ClassifyFinding and
// EnrichAndClassifyBatch make — and asserts an outbox entry actually lands.
//
// The unit tests above would all still pass with the publisher unwired, which
// is precisely how this defect survived. This one would not.
func TestClassificationChain_EscalationReachesOutbox(t *testing.T) {
	q := &fakeEnqueuer{}
	s := &PriorityClassificationService{logger: logger.NewNop()}
	s.SetChangePublisher(NewOutboxPriorityChangePublisher(q, logger.NewNop()))
	s.SetPriorityFloodGuard(NewPriorityFloodGuard(PriorityFloodConfig{}))

	prev := vulnerability.PriorityP3
	s.publishIfChanged(
		context.Background(),
		shared.NewID(), shared.NewID(),
		&prev,
		vulnerability.PriorityClassification{
			Class:  vulnerability.PriorityP0,
			Reason: "CVE added to KEV catalog",
			Source: "sweep",
		},
	)

	if len(q.calls) != 1 {
		t.Fatalf("P3->P0 escalation produced %d outbox entries, want 1: the classification chain is not reaching the outbox", len(q.calls))
	}
	if q.calls[0].EventType != string(integration.EventTypeFindingPriorityEscalated) {
		t.Errorf("EventType = %q", q.calls[0].EventType)
	}
	if q.calls[0].Severity != "critical" {
		t.Errorf("Severity = %q, want critical", q.calls[0].Severity)
	}

	// Re-confirming the same class must stay silent even with everything wired.
	p0 := vulnerability.PriorityP0
	s.publishIfChanged(context.Background(), shared.NewID(), shared.NewID(), &p0,
		vulnerability.PriorityClassification{Class: vulnerability.PriorityP0, Source: "sweep"})
	if len(q.calls) != 1 {
		t.Fatalf("no-op reclassification enqueued a notification: %d entries", len(q.calls))
	}
}

// TestPriorityEscalationEventType_IsSelectable guards the delivery-side half of
// this feature. enabled_event_types is an opt-in whitelist: an outbox entry
// whose event type is not in an integration's list matches zero integrations,
// is marked completed by the "no matching integrations" branch, archived and
// deleted — enqueued successfully and delivered nowhere, with no error logged.
//
// So the event type must be registered in AllEventTypes(), which is what the
// UI renders and what ValidateEventTypes accepts. Without that a tenant cannot
// select it and the publisher above is inert no matter how correct it is.
func TestPriorityEscalationEventType_IsSelectable(t *testing.T) {
	found := false
	for _, info := range integration.AllEventTypes() {
		if info.Type == integration.EventTypeFindingPriorityEscalated {
			found = true
			if info.Label == "" || info.Description == "" {
				t.Errorf("event type registered without UI metadata: %+v", info)
			}
		}
	}
	if !found {
		t.Fatal("EventTypeFindingPriorityEscalated missing from AllEventTypes(); " +
			"tenants cannot enable it and every escalation notification is silently dropped at delivery")
	}

	ok, invalid := integration.ValidateEventTypes(
		[]integration.EventType{integration.EventTypeFindingPriorityEscalated},
		[]string{integration.ModuleFindings},
	)
	if !ok {
		t.Fatalf("ValidateEventTypes rejects the escalation event type: %v", invalid)
	}
}
