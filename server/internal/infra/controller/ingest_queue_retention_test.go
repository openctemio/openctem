package controller

import (
	"context"
	"testing"
	"time"
)

type fakeQueuePurge struct{ calls map[string]int }

func (f *fakeQueuePurge) step(name string, limit int) (int64, error) {
	f.calls[name]++
	if name == "jobs" && f.calls[name] < 3 {
		return int64(limit), nil // full batches: keep going
	}
	return 1, nil
}
func (f *fakeQueuePurge) PurgePayloadsForPlatform(_ context.Context, _ time.Time, n int) (int64, error) {
	return f.step("payloads", n)
}
func (f *fakeQueuePurge) PurgeFinishedJobsForPlatform(_ context.Context, before time.Time, n int) (int64, error) {
	if time.Since(before) < IngestQueueRetention-time.Minute {
		return 0, nil
	}
	return f.step("jobs", n)
}
func (f *fakeQueuePurge) PurgeFinishedReportsForPlatform(_ context.Context, _ time.Time, n int) (int64, error) {
	return f.step("reports", n)
}

func TestIngestQueueRetention_BatchesEachKind(t *testing.T) {
	f := &fakeQueuePurge{calls: map[string]int{}}
	c := NewIngestQueueRetentionController(f, 0)
	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.calls["payloads"] != 1 || f.calls["jobs"] != 3 || f.calls["reports"] != 1 {
		t.Fatalf("calls %v", f.calls)
	}
	if n != 1+2*ingestQueuePurgeBatch+1+1 {
		t.Fatalf("deleted %d", n)
	}
	if !c.Exclusive() || c.Interval() != IngestQueueRetentionInterval {
		t.Fatal("controller settings")
	}
}
