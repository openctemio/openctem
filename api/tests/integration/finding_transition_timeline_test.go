package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type timelineFixture struct {
	db            *sql.DB
	repo          *postgres.FindingRepository
	tenant, other shared.ID
	asset         shared.ID
}

func newTimelineFixture(t *testing.T) *timelineFixture {
	t.Helper()
	db := setupTestDB(t)
	f := &timelineFixture{db: db, repo: postgres.NewFindingRepository(&postgres.DB{DB: db}),
		tenant: createTestTenant(t, db, "timeline"), other: createTestTenant(t, db, "timeline-other"), asset: shared.NewID()}
	t.Cleanup(func() {
		for _, id := range []shared.ID{f.tenant, f.other} {
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String())
		}
		_ = db.Close()
	})
	f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'tl-host', 'host')`, f.asset.String(), f.tenant.String())
	return f
}

func (f *timelineFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.db.Exec(q, args...); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

// finding adds an open sast finding of tool "tl-tool" and returns its id and fingerprint.
func (f *timelineFixture) finding(t *testing.T, status string) (shared.ID, string) {
	t.Helper()
	id := shared.NewID()
	fp := "tl-" + id.String()
	f.exec(t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, last_seen_at)
		VALUES ($1, $2, $3, 'sast', 'tl-tool', 'm', 'high', $4, $5, NOW() - INTERVAL '1 day')`,
		id.String(), f.tenant.String(), f.asset.String(), fp, status)
	return id, fp
}

type timelineEntry struct {
	kind, actorType, source string
	changes                 map[string]any
}

func (f *timelineFixture) entries(t *testing.T, id shared.ID) []timelineEntry {
	t.Helper()
	rows, err := f.db.Query(`SELECT activity_type, actor_type, COALESCE(source, ''), changes FROM finding_activities
		WHERE tenant_id = $1 AND finding_id = $2 ORDER BY created_at`, f.tenant.String(), id.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []timelineEntry
	for rows.Next() {
		var e timelineEntry
		var raw []byte
		if err := rows.Scan(&e.kind, &e.actorType, &e.source, &raw); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(raw, &e.changes)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// wantOne checks the finding has exactly one timeline entry, for the move.
func (f *timelineFixture) wantOne(t *testing.T, label string, id shared.ID, kind, source, oldStatus, newStatus string, extra map[string]any) {
	t.Helper()
	es := f.entries(t, id)
	if len(es) != 1 {
		t.Errorf("%s: %d timeline entries, want exactly 1: %+v", label, len(es), es)
		return
	}
	e := es[0]
	if e.kind != kind || e.source != source || e.changes["old_status"] != oldStatus || e.changes["new_status"] != newStatus {
		t.Errorf("%s: entry %s/%s %v -> %v, want %s/%s %s -> %s", label, e.kind, e.source,
			e.changes["old_status"], e.changes["new_status"], kind, source, oldStatus, newStatus)
	}
	for k, v := range extra {
		if e.changes[k] != v {
			t.Errorf("%s: changes[%s] = %v, want %v", label, k, e.changes[k], v)
		}
	}
}

// Every automatic move writes its timeline entry in the same transaction, with
// the old and new status, the source and the evidence behind it.
func TestTransitionTimeline_AutomaticMovesAreRecorded(t *testing.T) {
	f := newTimelineFixture(t)
	ctx := context.Background()
	scanCtx := vulnerability.WithTransitionEvidence(ctx, map[string]any{"scanner": "tl-tool", "scan_id": "cmd-1"})

	// Covered scan auto-resolve.
	covered, _ := f.finding(t, "confirmed")
	if _, err := f.repo.ResolveCoverageStale(scanCtx, f.tenant, []shared.ID{covered}); err != nil {
		t.Fatal(err)
	}
	f.wantOne(t, "coverage auto-resolve", covered, "auto_resolved", "auto", "confirmed", "resolved",
		map[string]any{"reason": "not_found_in_full_scan", "scanner": "tl-tool", "scan_id": "cmd-1"})

	// Template drift.
	drifted, _ := f.finding(t, "new")
	if _, err := f.repo.MarkCoverageNotObserved(scanCtx, f.tenant, []shared.ID{drifted}); err != nil {
		t.Fatal(err)
	}
	// Template drift marks it stale: the status does not move, so no entry.
	var driftEntries int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1`, drifted.String()).Scan(&driftEntries); err != nil || driftEntries != 0 {
		t.Errorf("template drift wrote %d entries (%v), want 0 (no status move)", driftEntries, err)
	}

	// Source said mitigated.
	mitigated, mfp := f.finding(t, "in_progress")
	if _, err := f.repo.ResolveSourceMitigated(ctx, f.tenant, "tl-tool",
		[]vulnerability.SourceMitigation{{Fingerprint: mfp, AssetID: f.asset, MitigatedAt: time.Now()}}, false); err != nil {
		t.Fatal(err)
	}
	f.wantOne(t, "source mitigated", mitigated, "auto_resolved", "auto", "in_progress", "resolved",
		map[string]any{"reason": "source_mitigated"})

	// VEX not_affected in a scan report.
	vexed, vfp := f.finding(t, "new")
	if _, err := f.repo.ApplyVEXNotAffected(ctx, f.tenant, "tl-tool",
		[]vulnerability.VEXNotAffected{{Fingerprint: vfp, AssetID: f.asset.String(), Resolution: "not affected"}}, false); err != nil {
		t.Fatal(err)
	}
	// A false positive needs four-eyes: the statement requests it, the status stays.
	if es := f.entries(t, vexed); len(es) != 1 || es[0].kind != "approval_requested" || es[0].changes["requested_status"] != "false_positive" {
		t.Errorf("ingest VEX: entries %+v, want one approval_requested for false_positive", es)
	}

	// A scan re-detects a resolved finding.
	reopened, rfp := f.finding(t, "confirmed")
	f.exec(t, `UPDATE findings SET status = 'resolved', resolution = 'patched', resolved_at = NOW() WHERE id = $1`, reopened.String())
	if _, err := f.repo.AutoReopenByFingerprintsBatch(scanCtx, f.tenant, []string{rfp}); err != nil {
		t.Fatal(err)
	}
	f.wantOne(t, "scan reopen", reopened, "auto_reopened", "auto", "resolved", "confirmed",
		map[string]any{"reason": "regression_detected_again", "previous_resolution": "patched", "scan_id": "cmd-1"})

	// An application path on the platform's behalf (IOC correlator,
	// validation, workflow, auto-assign) through the full-row Update.
	moved, _ := f.finding(t, "resolved")
	loaded, err := f.repo.GetByID(ctx, f.tenant, moved)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.TransitionStatus(vulnerability.FindingStatusConfirmed, "ioc", nil); err != nil {
		t.Fatal(err)
	}
	wf := vulnerability.WithStatusTransition(ctx, vulnerability.StatusTransition{Source: "workflow", ActorName: "workflow:wf-1"})
	if err := f.repo.Update(wf, loaded); err != nil {
		t.Fatal(err)
	}
	f.wantOne(t, "platform Update", moved, "status_changed", "workflow", "resolved", "confirmed", nil)

	// A person's Update records nothing here: the service writes their entry.
	person, _ := f.finding(t, "new")
	pl, err := f.repo.GetByID(ctx, f.tenant, person)
	if err != nil {
		t.Fatal(err)
	}
	if err := pl.TransitionStatus(vulnerability.FindingStatusConfirmed, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Update(ctx, pl); err != nil {
		t.Fatal(err)
	}
	if es := f.entries(t, person); len(es) != 0 {
		t.Errorf("person Update wrote %d entries from the trigger, want 0 (the service records it)", len(es))
	}
}

// The entry belongs to the moved finding's tenant, and a transition set in one
// transaction never leaks into the next (another tenant's later move).
func TestTransitionTimeline_TenantAndTransactionScoped(t *testing.T) {
	f := newTimelineFixture(t)
	ctx := context.Background()
	a, _ := f.finding(t, "confirmed")
	if _, err := f.repo.ResolveCoverageStale(ctx, f.tenant, []shared.ID{a}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND tenant_id = $2`,
		a.String(), f.other.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("an entry was written under another tenant")
	}

	// A plain status write on another connection afterwards writes nothing.
	otherAsset, otherID := shared.NewID(), shared.NewID()
	f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'tl-o', 'host')`, otherAsset.String(), f.other.String())
	f.exec(t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sast', 'tl-tool', 'm', 'high', $4, 'new')`, otherID.String(), f.other.String(), otherAsset.String(), "tl-o-"+otherID.String())
	f.exec(t, `UPDATE findings SET status = 'confirmed' WHERE id = $1`, otherID.String())
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1`, otherID.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("a status write outside a named transition wrote %d entries, want 0", n)
	}
}
