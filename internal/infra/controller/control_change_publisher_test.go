package controller

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

type captureQueue struct {
	mu    sync.Mutex
	reqs  []ReclassifyRequest
	err   error
}

func (c *captureQueue) Enqueue(_ context.Context, r ReclassifyRequest) error {
	if c.err != nil {
		return c.err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reqs = append(c.reqs, r)
	return nil
}

func (c *captureQueue) DequeueBatch(_ context.Context, _ int) ([]ReclassifyRequest, error) {
	return nil, nil
}

func TestControlChangePublish_EmptyAssetList_NoOp(t *testing.T) {
	q := &captureQueue{}
	p := NewControlChangePublisher(q, nil)
	p.PublishChange(context.Background(), shared.NewID(), nil, "test")
	if len(q.reqs) != 0 {
		t.Fatal("empty asset list must not enqueue")
	}
}

func TestControlChangePublish_Enqueues(t *testing.T) {
	q := &captureQueue{}
	p := NewControlChangePublisher(q, nil)
	tid := shared.NewID()
	assets := []shared.ID{shared.NewID(), shared.NewID()}
	p.PublishChange(context.Background(), tid, assets, "control activated")
	if len(q.reqs) != 1 {
		t.Fatalf("want 1 request, got %d", len(q.reqs))
	}
	r := q.reqs[0]
	if r.TenantID != tid || r.Reason != ReasonControlChange {
		t.Fatalf("wrong fields: %+v", r)
	}
}

func TestControlChangePublish_QueueErrorSwallowed(t *testing.T) {
	q := &captureQueue{err: errors.New("redis down")}
	p := NewControlChangePublisher(q, nil)
	p.PublishChange(context.Background(), shared.NewID(), []shared.ID{shared.NewID()}, "x")
	// No panic, no propagation.
}

func TestControlChangePublish_NilQueue_Safe(t *testing.T) {
	p := NewControlChangePublisher(nil, nil)
	p.PublishChange(context.Background(), shared.NewID(), []shared.ID{shared.NewID()}, "x")
}
