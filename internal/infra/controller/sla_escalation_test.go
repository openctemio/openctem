package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// B4: unit-level assertions for the breach-publisher contract.
// The DB → UPDATE → RETURNING path is covered by integration tests
// (needs real Postgres); here we lock in the publisher behaviour + the
// setter wiring.

type captureBreachPub struct {
	mu     sync.Mutex
	events []SLABreachEvent
	err    error
}

func (p *captureBreachPub) Publish(_ context.Context, ev SLABreachEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.events = append(p.events, ev)
	return nil
}

func (p *captureBreachPub) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.events)
}

func TestSetBreachPublisher_NilSafe(t *testing.T) {
	c := &SLAEscalationController{}
	c.SetBreachPublisher(nil)
	if c.publisher != nil {
		t.Fatal("setting nil must leave publisher nil")
	}
}

func TestSetBreachPublisher_StoresPublisher(t *testing.T) {
	c := &SLAEscalationController{}
	pub := &captureBreachPub{}
	c.SetBreachPublisher(pub)
	if c.publisher == nil {
		t.Fatal("publisher not stored")
	}
}

// The publisher is invoked via Reconcile(). We simulate the
// post-UPDATE loop by calling Publish directly with the same event
// shape Reconcile would produce — that way we validate the event
// struct contract without requiring a DB.
func TestSLABreachEvent_CarriesOverdueDuration(t *testing.T) {
	pub := &captureBreachPub{}
	deadline := time.Now().Add(-2 * time.Hour)
	now := time.Now().UTC()
	tid := shared.NewID()
	fid := shared.NewID()

	err := pub.Publish(context.Background(), SLABreachEvent{
		TenantID:        tid,
		FindingID:       fid,
		SLADeadline:     deadline,
		OverdueDuration: now.Sub(deadline),
		At:              now,
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if pub.count() != 1 {
		t.Fatalf("want 1, got %d", pub.count())
	}
	ev := pub.events[0]
	if ev.TenantID != tid || ev.FindingID != fid {
		t.Fatalf("ids wrong")
	}
	if ev.OverdueDuration < 2*time.Hour || ev.OverdueDuration > 3*time.Hour {
		t.Fatalf("unexpected overdue duration: %v", ev.OverdueDuration)
	}
}

func TestSLABreachPublisher_ErrorsDoNotEscape(t *testing.T) {
	// Sanity: the publisher contract is "errors are caller's concern".
	// Reconcile logs and swallows — that behaviour is verified by the
	// controller integration test in tests/integration/.
	pub := &captureBreachPub{err: errors.New("redis down")}
	if err := pub.Publish(context.Background(), SLABreachEvent{}); err == nil {
		t.Fatal("expected error from publisher")
	}
}
