package reclassify

import (
	"context"
	"sync"
	"testing"

	"github.com/openctemio/api/internal/infra/controller"
	"github.com/openctemio/api/pkg/domain/shared"
)

func TestMemoryQueue_EnqueueDequeue_FIFO(t *testing.T) {
	q := NewMemoryQueue()
	ctx := context.Background()
	tenantID := shared.NewID()

	for i := 0; i < 3; i++ {
		if err := q.Enqueue(ctx, controller.ReclassifyRequest{
			TenantID: tenantID,
			Reason:   controller.ReasonManual,
		}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	if q.Len() != 3 {
		t.Fatalf("len = %d, want 3", q.Len())
	}

	batch, err := q.DequeueBatch(ctx, 2)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(batch) != 2 {
		t.Fatalf("batch size = %d, want 2", len(batch))
	}
	if q.Len() != 1 {
		t.Fatalf("remaining = %d, want 1", q.Len())
	}
}

func TestMemoryQueue_EmptyDequeue_ReturnsEmpty(t *testing.T) {
	q := NewMemoryQueue()
	batch, err := q.DequeueBatch(context.Background(), 10)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if len(batch) != 0 {
		t.Fatalf("expected empty batch, got %d", len(batch))
	}
}

func TestMemoryQueue_DequeueBatch_CapsAtAvailable(t *testing.T) {
	q := NewMemoryQueue()
	ctx := context.Background()
	_ = q.Enqueue(ctx, controller.ReclassifyRequest{TenantID: shared.NewID()})

	batch, _ := q.DequeueBatch(ctx, 100)
	if len(batch) != 1 {
		t.Fatalf("expected 1 item, got %d", len(batch))
	}
}

func TestMemoryQueue_ConcurrentEnqueue_IsSafe(t *testing.T) {
	q := NewMemoryQueue()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = q.Enqueue(ctx, controller.ReclassifyRequest{TenantID: shared.NewID()})
		}()
	}
	wg.Wait()
	if q.Len() != 50 {
		t.Fatalf("len = %d, want 50", q.Len())
	}
}
