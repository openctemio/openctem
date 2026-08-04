package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// endpoint_asset_id is nullable, and nothing will ever fill it in later.
//
// Migration 000155 promised "a nightly reconciler job pairs events with assets
// by agent_id". That job was never written and could not be: `agents` has no
// asset column, `assets` has no agent column, and there is no join table — so
// there is no key to pair BY. It is also the wrong idea, because only the
// producer knows which endpoint an event describes; an EDR/XDR forwarder
// reports on many hosts.
//
// So an event without an asset link is permanently invisible to every
// asset-scoped read — Stage-4 detection correlation's heuristic fallback and
// the per-asset Stage-6 dashboards — while the response says "accepted" and the
// IOC correlator, which keys on values inside the event, still works. That is a
// half-working feature that looks fully working.
//
// These tests pin the counter that makes it visible.

func openTelemetryDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping telemetry ingest tests")
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

func seedTelemetryTenant(t *testing.T, db *sql.DB) shared.ID {
	t.Helper()

	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		id.String(), "telemetry unpaired test", "tel-"+id.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
	})
	return id
}

func seedTelemetryAsset(t *testing.T, db *sql.DB, tenantID shared.ID) shared.ID {
	t.Helper()

	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`,
		id.String(), tenantID.String(), "host-"+id.String()); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return id
}

// ingestEvents posts a batch as an authenticated tenant agent and returns the
// decoded response.
func ingestEvents(t *testing.T, db *sql.DB, tenantID shared.ID, events []map[string]any) ingestResponse {
	t.Helper()

	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	h := NewRuntimeTelemetryHandler(db, logger.NewNop())

	r := httptest.NewRequest(http.MethodPost, "/api/v1/telemetry-events", bytes.NewReader(body))
	tid := tenantID
	agt := &agent.Agent{ID: shared.NewID(), TenantID: &tid, Status: agent.AgentStatusActive}
	r = r.WithContext(context.WithValue(r.Context(), agentContextKey, agt))

	w := httptest.NewRecorder()
	h.Ingest(w, r)

	// 202 on a fully-accepted batch, 207 when some events were rejected.
	if w.Code != http.StatusAccepted && w.Code != http.StatusMultiStatus {
		t.Fatalf("ingest returned %d: %s", w.Code, w.Body.String())
	}

	var resp ingestResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM runtime_telemetry_events WHERE tenant_id = $1`, tenantID.String())
	})
	return resp
}

func event(assetID string) map[string]any {
	e := map[string]any{
		"event_type":  "network_connect",
		"observed_at": time.Now().UTC().Format(time.RFC3339),
	}
	if assetID != "" {
		e["endpoint_asset_id"] = assetID
	}
	return e
}

// The core case: a producer that never sends endpoint_asset_id gets a fully
// successful response. Without the counter there is nothing in that response to
// tell it half the feature does not apply.
func TestIngest_ReportsUnpairedEvents(t *testing.T) {
	db := openTelemetryDB(t)
	tenantID := seedTelemetryTenant(t, db)

	resp := ingestEvents(t, db, tenantID, []map[string]any{
		event(""), event(""), event(""),
	})

	if resp.Accepted != 3 {
		t.Fatalf("accepted = %d, want 3 (errors: %v)", resp.Accepted, resp.Errors)
	}
	if resp.Rejected != 0 {
		t.Fatalf("rejected = %d, want 0: unpaired events are stored, not refused", resp.Rejected)
	}
	if resp.Unpaired != 3 {
		t.Fatalf("unpaired = %d, want 3: the response claims full success while every "+
			"event is invisible to asset-scoped correlation", resp.Unpaired)
	}
}

// A producer doing it right must not be told it has a problem.
func TestIngest_PairedEventsAreNotCountedUnpaired(t *testing.T) {
	db := openTelemetryDB(t)
	tenantID := seedTelemetryTenant(t, db)
	assetID := seedTelemetryAsset(t, db, tenantID)

	resp := ingestEvents(t, db, tenantID, []map[string]any{
		event(assetID.String()), event(assetID.String()),
	})

	if resp.Accepted != 2 {
		t.Fatalf("accepted = %d, want 2 (errors: %v)", resp.Accepted, resp.Errors)
	}
	if resp.Unpaired != 0 {
		t.Fatalf("unpaired = %d, want 0: these events carry a valid asset link", resp.Unpaired)
	}
}

// A mixed batch is the realistic case — the count must be per-event, not a
// boolean about the batch.
func TestIngest_CountsUnpairedPerEvent(t *testing.T) {
	db := openTelemetryDB(t)
	tenantID := seedTelemetryTenant(t, db)
	assetID := seedTelemetryAsset(t, db, tenantID)

	resp := ingestEvents(t, db, tenantID, []map[string]any{
		event(assetID.String()), event(""), event(assetID.String()), event(""),
	})

	if resp.Accepted != 4 {
		t.Fatalf("accepted = %d, want 4 (errors: %v)", resp.Accepted, resp.Errors)
	}
	if resp.Unpaired != 2 {
		t.Fatalf("unpaired = %d, want 2", resp.Unpaired)
	}
}

// Unpaired counts ACCEPTED events only. A rejected event was never stored, so
// counting it here would overstate the gap and send a producer looking for a
// configuration problem that is really a validation error.
func TestIngest_RejectedEventsAreNotCountedUnpaired(t *testing.T) {
	db := openTelemetryDB(t)
	tenantID := seedTelemetryTenant(t, db)

	resp := ingestEvents(t, db, tenantID, []map[string]any{
		{"observed_at": time.Now().UTC().Format(time.RFC3339)}, // no event_type -> rejected
		event(""), // accepted, unpaired
	})

	if resp.Rejected != 1 {
		t.Fatalf("rejected = %d, want 1", resp.Rejected)
	}
	if resp.Accepted != 1 {
		t.Fatalf("accepted = %d, want 1", resp.Accepted)
	}
	if resp.Unpaired != 1 {
		t.Fatalf("unpaired = %d, want 1: a rejected event was never stored and must "+
			"not be reported as an unpaired one", resp.Unpaired)
	}
}
