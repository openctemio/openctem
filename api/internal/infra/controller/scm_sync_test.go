package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

type fakeSCMSyncer struct {
	called int
	ret    int
	err    error
}

func (f *fakeSCMSyncer) SyncAllConnectedSCMIntegrations(_ context.Context) (int, error) {
	f.called++
	return f.ret, f.err
}

func TestSCMSyncController_NameAndInterval(t *testing.T) {
	c := NewSCMSyncController(&fakeSCMSyncer{}, 6*time.Hour, logger.NewNop())
	if c.Name() != "scm-sync" {
		t.Errorf("Name = %q, want scm-sync", c.Name())
	}
	if c.Interval() != 6*time.Hour {
		t.Errorf("Interval = %v, want 6h", c.Interval())
	}
}

func TestSCMSyncController_ReconcileDelegates(t *testing.T) {
	f := &fakeSCMSyncer{ret: 7}
	c := NewSCMSyncController(f, time.Hour, logger.NewNop())
	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile err: %v", err)
	}
	if n != 7 || f.called != 1 {
		t.Errorf("got n=%d called=%d, want n=7 called=1", n, f.called)
	}
}

func TestSCMSyncController_ReconcilePropagatesError(t *testing.T) {
	f := &fakeSCMSyncer{err: errors.New("boom")}
	c := NewSCMSyncController(f, time.Hour, logger.NewNop())
	if _, err := c.Reconcile(context.Background()); err == nil {
		t.Error("expected error to propagate")
	}
}
