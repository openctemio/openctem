package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type fakeSyncStore struct {
	due     []*integration.Integration
	updated []*integration.Integration
	listErr error
}

func (s *fakeSyncStore) ListDueForSync(_ context.Context, _ integration.Provider, _ time.Time, _ int) ([]*integration.Integration, error) {
	return s.due, s.listErr
}
func (s *fakeSyncStore) Update(_ context.Context, i *integration.Integration) error {
	s.updated = append(s.updated, i)
	return nil
}

type fakeSyncer struct {
	syncedTenants []shared.ID
	failFor       map[string]bool // tenantID → fail
}

func (f *fakeSyncer) SyncTenant(_ context.Context, tenantID shared.ID) error {
	f.syncedTenants = append(f.syncedTenants, tenantID)
	if f.failFor[tenantID.String()] {
		return errors.New("pull failed")
	}
	return nil
}

func connectedDD(tenantID shared.ID) *integration.Integration {
	intg := integration.NewIntegration(shared.NewID(), tenantID, "dd",
		integration.CategorySecurity, integration.ProviderDefectDojo, integration.AuthTypeToken)
	intg.SetSyncInterval(60)
	intg.SetConnected()
	return intg
}

func TestDefectDojoScheduler_SyncsEachDueAndAdvances(t *testing.T) {
	t1, t2 := shared.NewID(), shared.NewID()
	store := &fakeSyncStore{due: []*integration.Integration{connectedDD(t1), connectedDD(t2)}}
	syncer := &fakeSyncer{}
	c := NewDefectDojoSyncController(store, syncer, logger.NewNop())

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 2 {
		t.Fatalf("synced = %d, want 2", n)
	}
	if len(syncer.syncedTenants) != 2 {
		t.Fatalf("syncer called %d times, want 2 (one per due integration, each under its tenant)", len(syncer.syncedTenants))
	}
	// Both integrations persisted with an advanced next_sync_at.
	if len(store.updated) != 2 {
		t.Fatalf("updated %d integrations, want 2", len(store.updated))
	}
	for _, intg := range store.updated {
		if intg.NextSyncAt() == nil || !intg.NextSyncAt().After(time.Now()) {
			t.Errorf("next_sync_at not advanced into the future: %v", intg.NextSyncAt())
		}
	}
}

func TestDefectDojoScheduler_FailureRecordedButStillReschedules(t *testing.T) {
	t1 := shared.NewID()
	store := &fakeSyncStore{due: []*integration.Integration{connectedDD(t1)}}
	syncer := &fakeSyncer{failFor: map[string]bool{t1.String(): true}}
	c := NewDefectDojoSyncController(store, syncer, logger.NewNop())

	n, err := c.Reconcile(context.Background())
	if n != 0 {
		t.Errorf("synced = %d, want 0 (the only one failed)", n)
	}
	if err == nil {
		t.Error("expected the sync error surfaced to the controller")
	}
	if len(store.updated) != 1 {
		t.Fatalf("a failed sync must still persist rescheduling, updated=%d", len(store.updated))
	}
	upd := store.updated[0]
	if upd.SyncError() == "" {
		t.Error("failure should record a sync_error")
	}
	if upd.NextSyncAt() == nil || !upd.NextSyncAt().After(time.Now()) {
		t.Error("a failed sync must still advance next_sync_at (retry next interval, not hammer)")
	}
}

func TestDefectDojoScheduler_NoDue_NoOp(t *testing.T) {
	c := NewDefectDojoSyncController(&fakeSyncStore{}, &fakeSyncer{}, logger.NewNop())
	n, err := c.Reconcile(context.Background())
	if n != 0 || err != nil {
		t.Fatalf("no due integrations should be a clean no-op, got n=%d err=%v", n, err)
	}
}
