package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
)

type fakeRescorer struct {
	claims  []int // Claimed per call
	calls   int
	err     error
	delay   time.Duration
	reconq  int64
	statsOK bool
}

func (f *fakeRescorer) ProcessRiskQueue(_ context.Context, limit int) (assetapp.RiskQueueResult, error) {
	c := 0
	if f.calls < len(f.claims) {
		c = f.claims[f.calls]
	}
	f.calls++
	return assetapp.RiskQueueResult{Claimed: c, Scored: c, Changed: c / 2}, f.err
}

func (f *fakeRescorer) RiskQueueStats(context.Context) (assetdom.RiskQueueStats, error) {
	f.statsOK = true
	return assetdom.RiskQueueStats{Depth: 3, OldestAge: time.Second}, nil
}

func (f *fakeRescorer) EnqueueRiskReconcile(_ context.Context, d time.Duration) (int64, error) {
	f.delay = d
	return f.reconq, nil
}

func TestAssetRiskScoreController_DrainsFullBatchesThenStops(t *testing.T) {
	f := &fakeRescorer{claims: []int{assetapp.DefaultRiskQueueBatch, assetapp.DefaultRiskQueueBatch, 7}}
	c := NewAssetRiskScoreController(f, 0)
	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 3 || n != 2*assetapp.DefaultRiskQueueBatch+7 || !f.statsOK {
		t.Fatalf("calls=%d scored=%d stats=%v", f.calls, n, f.statsOK)
	}
}

func TestAssetRiskScoreController_ReportsErrorAndStopsOnShortBatch(t *testing.T) {
	f := &fakeRescorer{claims: []int{2}, err: errors.New("boom")}
	if _, err := NewAssetRiskScoreController(f, 0).Reconcile(context.Background()); err == nil || f.calls != 1 {
		t.Fatalf("err=%v calls=%d", err, f.calls)
	}
}

func TestAssetRiskReconcileController_QueuesBehindEvents(t *testing.T) {
	f := &fakeRescorer{reconq: 12}
	c := NewAssetRiskReconcileController(f, 0)
	n, err := c.Reconcile(context.Background())
	if err != nil || n != 12 || f.delay <= 0 || c.Interval() != 24*time.Hour || !c.Exclusive() {
		t.Fatalf("n=%d err=%v delay=%v", n, err, f.delay)
	}
}
