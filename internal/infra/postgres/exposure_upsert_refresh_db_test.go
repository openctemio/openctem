package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/exposure"
)

// The exposure upsert only moved last_seen_at/updated_at on re-sighting, so a
// re-escalated exposure (info -> critical) kept its stale first-seen severity,
// title and description forever. The fix refreshes those descriptive fields but
// deliberately PRESERVES state so a re-scan can't silently reopen a resolved
// exposure. This guards both halves of that decision.

func openExposureRefreshDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping exposure-refresh DB test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

func TestExposureUpsert_RefreshesSeverityPreservesState(t *testing.T) {
	ctx := context.Background()
	db := openExposureRefreshDB(t)
	repo := NewExposureRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)

	// First sighting: an informational open port, active.
	event1, err := exposure.NewExposureEvent(
		tenantID, exposure.EventTypePortOpen, exposure.SeverityInfo,
		"Port 22 open", "scanner", nil)
	if err != nil {
		t.Fatalf("new exposure event: %v", err)
	}
	if err := repo.Upsert(ctx, event1); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	fp := event1.Fingerprint()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM exposure_events WHERE tenant_id = $1 AND fingerprint = $2`, tenantID.String(), fp)
	})

	// Operator resolves it out-of-band.
	if _, err := db.ExecContext(ctx,
		`UPDATE exposure_events SET state = 'resolved' WHERE tenant_id = $1 AND fingerprint = $2`,
		tenantID.String(), fp); err != nil {
		t.Fatalf("mark resolved: %v", err)
	}

	// Re-scan re-sights the same fingerprint, now escalated to critical with a
	// reworded title/description and an active state. Reconstitute lets us pin
	// the same fingerprint while changing the descriptive fields.
	now := time.Now().UTC()
	event2 := exposure.Reconstitute(
		event1.ID(), tenantID, nil,
		exposure.EventTypePortOpen, exposure.SeverityCritical, exposure.StateActive,
		"Port 22 open — now exploitable", "escalated by re-scan",
		map[string]any{"note": "escalated"}, fp, "scanner", event1.FirstSeenAt(), now,
		nil, nil, "", event1.CreatedAt(), now,
	)
	if event2.Fingerprint() != fp {
		t.Fatalf("test setup: event2 fingerprint %q != %q", event2.Fingerprint(), fp)
	}
	if err := repo.Upsert(ctx, event2); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}

	var (
		severity, state, title, desc string
		rows                         int
	)
	if err := db.QueryRowContext(ctx,
		`SELECT severity, state, title, description FROM exposure_events
		 WHERE tenant_id = $1 AND fingerprint = $2`,
		tenantID.String(), fp).Scan(&severity, &state, &title, &desc); err != nil {
		t.Fatalf("read exposure: %v", err)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM exposure_events WHERE tenant_id = $1 AND fingerprint = $2`,
		tenantID.String(), fp).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}

	if rows != 1 {
		t.Errorf("row count = %d, want 1: re-sighting must merge, not duplicate", rows)
	}
	if severity != "critical" {
		t.Errorf("severity = %q, want critical — re-escalation must refresh the stored severity", severity)
	}
	if title != "Port 22 open — now exploitable" {
		t.Errorf("title = %q, want refreshed title", title)
	}
	if desc != "escalated by re-scan" {
		t.Errorf("description = %q, want refreshed description", desc)
	}
	if state != "resolved" {
		t.Errorf("state = %q, want resolved preserved — a re-scan must not silently reopen a resolved exposure", state)
	}
}
