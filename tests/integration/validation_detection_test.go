package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app/validation"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
)

// Stage-4 detection correlation against real SQL.
//
// These exercise internal/infra/postgres/telemetry_probe_repository.go —
// the queries the DetectionCorrelator depends on. Unit tests fake the
// probe, so without these the SQL itself (correlation_id cast, event_type
// = ANY($5), the observed_at vs received_at split) is unverified.

// TestDetectionCorrelation_NoTelemetryPipeline is the field case: a tenant
// with zero telemetry rows must come back no_telemetry_source, NOT
// not_observed. Today no first-party producer writes this table at all,
// so this is the state every real tenant is in.
func TestDetectionCorrelation_NoTelemetryPipeline(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}

	tenantID := createTestTenant(t, sqlDB, "detnone")
	assetID := createTestAsset(t, sqlDB, tenantID, "detnone-asset")
	t.Cleanup(func() { cleanupTestData(sqlDB, tenantID) })

	c := validation.NewDetectionCorrelator(postgres.NewTelemetryProbeRepository(db))
	start := time.Now().UTC().Add(-time.Minute)

	v := c.Evaluate(context.Background(), tenantID, validation.Evidence{
		ExecutorKind: "safe-check",
		Outcome:      validation.OutcomeDetected,
		StartedAt:    start,
		EndedAt:      start.Add(5 * time.Second),
		Target:       validation.Target{AssetID: assetID, Type: "host", Address: "h:443"},
	}, shared.ID{})

	if v.Status != validation.DetectionNoTelemetrySource {
		t.Fatalf("status = %q, want %q", v.Status, validation.DetectionNoTelemetrySource)
	}
	if v.Status.IsDetectionGap() {
		t.Fatal("a tenant with no telemetry integration must not be reported as a failed control")
	}
}

// TestDetectionCorrelation_ObservedByCorrelationID proves the exact-match
// SQL path end to end, including the UUID column.
func TestDetectionCorrelation_ObservedByCorrelationID(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}

	tenantID := createTestTenant(t, sqlDB, "detcorr")
	assetID := createTestAsset(t, sqlDB, tenantID, "detcorr-asset")
	t.Cleanup(func() { cleanupTestData(sqlDB, tenantID) })

	corrID := shared.NewID()
	start := time.Now().UTC().Add(-time.Minute)

	// A control reacted and its forwarder stamped the correlation id.
	// observed_at is deliberately OUTSIDE the 5-minute window to prove the
	// stamped path is time-independent.
	if _, err := sqlDB.Exec(`
		INSERT INTO runtime_telemetry_events
		       (tenant_id, endpoint_asset_id, event_type, severity, observed_at, properties, correlation_id)
		VALUES ($1, $2, 'network_connect', 'medium', $3, '{}'::jsonb, $4)`,
		tenantID.String(), assetID.String(), start.Add(-6*time.Hour), corrID.String(),
	); err != nil {
		t.Fatalf("insert telemetry: %v", err)
	}

	c := validation.NewDetectionCorrelator(postgres.NewTelemetryProbeRepository(db))
	v := c.Evaluate(context.Background(), tenantID, validation.Evidence{
		ExecutorKind: "safe-check",
		Outcome:      validation.OutcomeDetected,
		StartedAt:    start,
		EndedAt:      start.Add(5 * time.Second),
		Target:       validation.Target{AssetID: assetID, Type: "host", Address: "h:443"},
	}, corrID)

	if v.Status != validation.DetectionObserved {
		t.Fatalf("status = %q, want %q", v.Status, validation.DetectionObserved)
	}
	if v.Detail["match_mode"] != "correlation_id" {
		t.Fatalf("match_mode = %v, want correlation_id", v.Detail["match_mode"])
	}
}

// TestDetectionCorrelation_HeuristicWindowAndTypeFilter proves the
// fallback SQL: telemetry is flowing, but only an in-window event of a
// plausible type counts.
func TestDetectionCorrelation_HeuristicWindowAndTypeFilter(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}

	tenantID := createTestTenant(t, sqlDB, "detheur")
	assetID := createTestAsset(t, sqlDB, tenantID, "detheur-asset")
	t.Cleanup(func() { cleanupTestData(sqlDB, tenantID) })

	start := time.Now().UTC().Add(-time.Minute)
	ev := validation.Evidence{
		ExecutorKind: "safe-check",
		Outcome:      validation.OutcomeDetected,
		StartedAt:    start,
		EndedAt:      start.Add(5 * time.Second),
		Target:       validation.Target{AssetID: assetID, Type: "host", Address: "h:443"},
	}
	probe := postgres.NewTelemetryProbeRepository(db)
	c := validation.NewDetectionCorrelator(probe)

	// 1. In-window but an IMPLAUSIBLE type for a remote network probe.
	// The pipeline is now live, so the verdict must be not_observed —
	// a real gap — and must NOT be dragged to "observed" by host noise.
	if _, err := sqlDB.Exec(`
		INSERT INTO runtime_telemetry_events
		       (tenant_id, endpoint_asset_id, event_type, severity, observed_at, properties)
		VALUES ($1, $2, 'file_write', 'info', $3, '{}'::jsonb)`,
		tenantID.String(), assetID.String(), start.Add(time.Second),
	); err != nil {
		t.Fatalf("insert noise telemetry: %v", err)
	}

	v := c.Evaluate(context.Background(), tenantID, ev, shared.ID{})
	if v.Status != validation.DetectionNotObserved {
		t.Fatalf("with only implausible-type noise: status = %q, want %q (detail=%v)",
			v.Status, validation.DetectionNotObserved, v.Detail)
	}
	if live, _ := v.Detail["telemetry_pipeline_live"].(bool); !live {
		t.Fatal("pipeline must be reported live once any row exists")
	}

	// 2. A plausible type inside the window → observed.
	if _, err := sqlDB.Exec(`
		INSERT INTO runtime_telemetry_events
		       (tenant_id, endpoint_asset_id, event_type, severity, observed_at, properties)
		VALUES ($1, $2, 'network_connect', 'medium', $3, '{}'::jsonb)`,
		tenantID.String(), assetID.String(), start.Add(2*time.Second),
	); err != nil {
		t.Fatalf("insert matching telemetry: %v", err)
	}

	v = c.Evaluate(context.Background(), tenantID, ev, shared.ID{})
	if v.Status != validation.DetectionObserved {
		t.Fatalf("status = %q, want %q (detail=%v)", v.Status, validation.DetectionObserved, v.Detail)
	}
	if v.Detail["confidence"] != "heuristic" {
		t.Fatalf("confidence = %v, want heuristic", v.Detail["confidence"])
	}

	// 3. A plausible type OUTSIDE the window must not match. Push the
	// evidence window back so the row above falls beyond post-window.
	late := ev
	late.StartedAt = start.Add(-2 * time.Hour)
	late.EndedAt = late.StartedAt.Add(5 * time.Second)
	v = c.Evaluate(context.Background(), tenantID, late, shared.ID{})
	if v.Status != validation.DetectionNotObserved {
		t.Fatalf("out-of-window telemetry must not match: status = %q, want %q",
			v.Status, validation.DetectionNotObserved)
	}
}

// TestDetectionCorrelation_PersistedOnEvidence proves the verdict reaches
// the validation_evidence row (real columns + CHECK constraint).
func TestDetectionCorrelation_PersistedOnEvidence(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}

	tenantID := createTestTenant(t, sqlDB, "detpersist")
	assetID := createTestAsset(t, sqlDB, tenantID, "detpersist-asset")
	findingID := createTestFinding(t, sqlDB, tenantID, assetID, "detection persist")
	t.Cleanup(func() { cleanupTestData(sqlDB, tenantID) })

	store := validation.NewEvidenceStore(postgres.NewValidationEvidenceRepository(db))
	store.SetDetectionCorrelator(
		validation.NewDetectionCorrelator(postgres.NewTelemetryProbeRepository(db)),
	)

	start := time.Now().UTC().Add(-time.Minute)
	if _, err := store.Record(context.Background(), tenantID, findingID, nil, validation.Evidence{
		ExecutorKind: "safe-check",
		Technique:    "T1046",
		Target:       validation.Target{AssetID: assetID, Type: "host", Address: "h:443"},
		StartedAt:    start,
		EndedAt:      start.Add(5 * time.Second),
		Outcome:      validation.OutcomeDetected,
		Summary:      "still reachable",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	var status string
	if err := sqlDB.QueryRow(
		`SELECT detection_status FROM validation_evidence WHERE tenant_id = $1 AND finding_id = $2`,
		tenantID.String(), findingID.String(),
	).Scan(&status); err != nil {
		t.Fatalf("read back detection_status: %v", err)
	}
	if status != string(validation.DetectionNoTelemetrySource) {
		t.Fatalf("persisted detection_status = %q, want %q", status, validation.DetectionNoTelemetrySource)
	}

	// And it must survive the read path.
	rows, err := postgres.NewValidationEvidenceRepository(db).ListByFinding(context.Background(), tenantID, findingID)
	if err != nil {
		t.Fatalf("ListByFinding: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].DetectionStatus != validation.DetectionNoTelemetrySource {
		t.Fatalf("round-tripped status = %q, want %q",
			rows[0].DetectionStatus, validation.DetectionNoTelemetrySource)
	}
	if rows[0].DetectionDetail["reason"] == nil {
		t.Fatal("detection_detail must round-trip the reason")
	}
}
