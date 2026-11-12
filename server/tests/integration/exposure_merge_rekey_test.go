package integration

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Exposure-event fingerprints embed the asset id. An asset merge used to move
// the events to the kept asset without re-keying them, so the next scan of the
// kept asset created a second event and the moved one never auto-resolved
// (RFC-043 B20). The merge now re-keys them and folds duplicates.

type expMerge struct {
	t                  *testing.T
	db                 *sql.DB
	tenant, keep, away shared.ID
}

func newExpMerge(t *testing.T, name string) *expMerge {
	t.Helper()
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	m := &expMerge{t: t, db: db, tenant: createTestTenant(t, db, name)}
	m.keep = createTestAsset(t, db, m.tenant, name+"-keep")
	m.away = createTestAsset(t, db, m.tenant, name+"-away")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM exposure_events WHERE tenant_id=$1`, m.tenant.String())
		_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id=$1`, m.tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, m.tenant.String())
	})
	return m
}

func (m *expMerge) merge() {
	m.t.Helper()
	var reviewID string
	if err := m.db.QueryRow(`
		INSERT INTO asset_dedup_review (tenant_id, keep_asset_id, merge_asset_ids, keep_asset_name,
			merge_asset_names, normalized_name, asset_type, status)
		VALUES ($1,$2,ARRAY[$3]::uuid[],'keep',ARRAY['away'],'x','repository','pending') RETURNING id`,
		m.tenant.String(), m.keep.String(), m.away.String()).Scan(&reviewID); err != nil {
		m.t.Fatalf("seed review: %v", err)
	}
	repo := postgres.NewAssetDedupRepository(&postgres.DB{DB: m.db})
	if err := repo.ApproveAndMerge(context.Background(), m.tenant.String(), reviewID, shared.NewID().String(), nil); err != nil {
		m.t.Fatalf("merge: %v", err)
	}
}

func (m *expMerge) count(q string, args ...any) int {
	m.t.Helper()
	var n int
	if err := m.db.QueryRow(q, args...).Scan(&n); err != nil {
		m.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func newExposure(t *testing.T, repo *postgres.ExposureRepository, tenant, asset shared.ID, title string) *exposure.ExposureEvent {
	t.Helper()
	e, err := exposure.NewExposureEvent(tenant, exposure.EventTypePortOpen, exposure.SeverityHigh, title, "nmap",
		map[string]any{"port": 22, "protocol": "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	e.SetAssetID(&asset)
	if err := repo.Upsert(context.Background(), e); err != nil {
		t.Fatalf("upsert exposure: %v", err)
	}
	return e
}

func TestApproveAndMerge_FoldsDuplicateExposureEvents(t *testing.T) {
	f := newExpMerge(t, "merge-exposure-fold")
	repo := postgres.NewExposureRepository(&postgres.DB{DB: f.db})

	older := newExposure(t, repo, f.tenant, f.away, "SSH open")
	newer := newExposure(t, repo, f.tenant, f.keep, "SSH open")
	old := time.Now().Add(-72 * time.Hour)
	if _, err := f.db.Exec(`UPDATE exposure_events SET created_at=$2, first_seen_at=$2, state='accepted',
			resolution_notes='bastion host, risk accepted' WHERE id=$1`, older.ID().String(), old); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO exposure_state_history (exposure_event_id, previous_state, new_state, reason)
			VALUES ($1,'active','accepted','accepted by owner')`, older.ID().String()); err != nil {
		t.Fatal(err)
	}

	f.merge()

	if n := f.count(`SELECT count(*) FROM exposure_events WHERE tenant_id=$1`, f.tenant.String()); n != 1 {
		t.Fatalf("the two events are one exposure on the kept asset, got %d events", n)
	}
	var id, asset, fp, state, notes string
	var firstSeen time.Time
	if err := f.db.QueryRow(`SELECT id, asset_id, fingerprint, state, COALESCE(resolution_notes,''), first_seen_at
			FROM exposure_events WHERE tenant_id=$1`, f.tenant.String()).Scan(&id, &asset, &fp, &state, &notes, &firstSeen); err != nil {
		t.Fatal(err)
	}
	want := exposure.Fingerprint(f.tenant.String(), "port_open", "SSH open", "nmap", f.keep.String(),
		map[string]any{"port": 22, "protocol": "tcp"})
	if id != older.ID().String() || asset != f.keep.String() || fp != want {
		t.Errorf("the earliest event should survive on the kept asset with its fingerprint: id=%s (older %s, newer %s) asset=%s fp ok=%v",
			id, older.ID(), newer.ID(), asset, fp == want)
	}
	if state != "accepted" || notes == "" {
		t.Errorf("the risk acceptance was lost: state=%s notes=%q", state, notes)
	}
	if !firstSeen.Before(time.Now().Add(-71 * time.Hour)) {
		t.Errorf("first_seen_at should be the earliest of the two, got %s", firstSeen)
	}
	if n := f.count(`SELECT count(*) FROM exposure_state_history WHERE exposure_event_id=$1 AND reason='accepted by owner'`, id); n != 1 {
		t.Errorf("state history of the event did not survive the merge")
	}
}

func TestApproveAndMerge_RekeysMovedExposureSoRescansUpdateIt(t *testing.T) {
	f := newExpMerge(t, "merge-exposure-rekey")
	repo := postgres.NewExposureRepository(&postgres.DB{DB: f.db})

	moved := newExposure(t, repo, f.tenant, f.away, "SSH open")

	f.merge()

	// The next scan of the kept asset reports the same exposure.
	newExposure(t, repo, f.tenant, f.keep, "SSH open")

	if n := f.count(`SELECT count(*) FROM exposure_events WHERE tenant_id=$1`, f.tenant.String()); n != 1 {
		t.Fatalf("a rescan of the kept asset created a second event (%d events)", n)
	}
	if n := f.count(`SELECT count(*) FROM exposure_events WHERE id=$1 AND asset_id=$2`, moved.ID().String(), f.keep.String()); n != 1 {
		t.Errorf("the moved event should be the one the rescan updated")
	}
}
