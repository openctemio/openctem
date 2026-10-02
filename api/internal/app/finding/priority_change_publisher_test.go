package finding

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// (F3, B1, B2): the priority-change publisher is the mechanism
// that wires reclassification to downstream systems (notifications,
// assignment-rule re-routing, dashboard live feed).
//
// Unit tests here exercise the publisher contract directly via the
// publishIfChanged helper without needing a full classification run.
// Classification-path integration tests live in tests/integration/.

// capturePub records events in memory so tests can assert emission.
type capturePub struct {
	mu     sync.Mutex
	events []PriorityChangeEvent
	err    error
}

func (c *capturePub) Publish(_ context.Context, ev PriorityChangeEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.events = append(c.events, ev)
	return nil
}

func (c *capturePub) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func (c *capturePub) last() PriorityChangeEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return PriorityChangeEvent{}
	}
	return c.events[len(c.events)-1]
}

func newSvc(pub PriorityChangePublisher) *PriorityClassificationService {
	s := &PriorityClassificationService{logger: logger.NewNop()}
	if pub != nil {
		s.SetChangePublisher(pub)
	}
	return s
}

// TestPublishIfChanged_FirstClassification_Emits confirms the first
// classification (previous == nil) emits an event — the case
// "finding was just created and got its first priority" must be visible
// to downstream systems.
func TestPublishIfChanged_FirstClassification_Emits(t *testing.T) {
	pub := &capturePub{}
	s := newSvc(pub)

	s.publishIfChanged(
		context.Background(),
		shared.NewID(), shared.NewID(),
		nil, // no previous class
		vulnerability.PriorityClassification{Class: "P1", Reason: "first", Source: "auto"},
	)
	if pub.count() != 1 {
		t.Fatalf("want 1 event, got %d", pub.count())
	}
	if pub.last().PreviousClass != nil {
		t.Fatalf("first classification must have PreviousClass nil")
	}
	if pub.last().NewClass != "P1" {
		t.Fatalf("NewClass = %q, want P1", pub.last().NewClass)
	}
}

// TestPublishIfChanged_SameClass_NoEmit pins down the invariant: the
// publisher must only fire on actual transitions. Running
// reclassification that re-confirms the same class must not spam the
// outbox.
func TestPublishIfChanged_SameClass_NoEmit(t *testing.T) {
	pub := &capturePub{}
	s := newSvc(pub)

	prev := vulnerability.PriorityClass("P2")
	s.publishIfChanged(
		context.Background(),
		shared.NewID(), shared.NewID(),
		&prev,
		vulnerability.PriorityClassification{Class: "P2", Reason: "no change", Source: "sweep"},
	)
	if pub.count() != 0 {
		t.Fatalf("same-class must not emit, got %d events", pub.count())
	}
}

func TestPublishIfChanged_TransitionEmits(t *testing.T) {
	pub := &capturePub{}
	s := newSvc(pub)

	prev := vulnerability.PriorityClass("P3")
	fid := shared.NewID()
	tid := shared.NewID()
	s.publishIfChanged(
		context.Background(),
		tid, fid,
		&prev,
		vulnerability.PriorityClassification{Class: "P0", Reason: "KEV flip", Source: "sweep"},
	)
	if pub.count() != 1 {
		t.Fatalf("want 1 event, got %d", pub.count())
	}
	ev := pub.last()
	if ev.PreviousClass == nil || *ev.PreviousClass != "P3" {
		t.Fatalf("previous class wrong: %+v", ev.PreviousClass)
	}
	if ev.NewClass != "P0" || ev.Source != "sweep" {
		t.Fatalf("new class / source wrong: %+v", ev)
	}
	if ev.TenantID != tid || ev.FindingID != fid {
		t.Fatalf("ids wrong: %+v", ev)
	}
	if ev.At.IsZero() {
		t.Fatalf("At must be set")
	}
}

// TestPublishIfChanged_NilPublisher_NoPanic protects the "safe default"
// behaviour — classification must not crash when no publisher is wired.
func TestPublishIfChanged_NilPublisher_NoPanic(t *testing.T) {
	s := newSvc(nil)
	// Should be a no-op, no panic.
	s.publishIfChanged(
		context.Background(),
		shared.NewID(), shared.NewID(),
		nil,
		vulnerability.PriorityClassification{Class: "P1"},
	)
}

// TestPublishIfChanged_PublisherError_DoesNotCrash confirms a broken
// publisher (e.g. Redis down) does not take down classification.
func TestPublishIfChanged_PublisherError_DoesNotCrash(t *testing.T) {
	pub := &capturePub{err: errors.New("boom")}
	s := newSvc(pub)
	s.publishIfChanged(
		context.Background(),
		shared.NewID(), shared.NewID(),
		nil,
		vulnerability.PriorityClassification{Class: "P1"},
	)
	// Publisher returned err but classification completed (no panic,
	// no escape of error). count() should still be 0 because our
	// capturePub early-returns on err before appending.
	if pub.count() != 0 {
		t.Fatalf("want 0 (publisher errored), got %d", pub.count())
	}
}
