package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/shared"
)

// TelemetryProbeRepository reads runtime_telemetry_events on behalf of
// the Stage-4 detection correlator. It implements
// validation.TelemetryProbe.
//
// Every query is tenant-scoped. Counts are capped with LIMIT-style
// short-circuits (EXISTS / LIMIT 1) where the caller only needs
// presence, so a busy tenant's telemetry volume never turns a
// validation completion into a table scan.
type TelemetryProbeRepository struct {
	db *DB
}

// NewTelemetryProbeRepository creates the repository.
func NewTelemetryProbeRepository(db *DB) *TelemetryProbeRepository {
	return &TelemetryProbeRepository{db: db}
}

// PipelineLive reports whether ANY runtime telemetry has arrived for the
// tenant since `since`.
//
// This is the guard that keeps "no telemetry integration connected"
// from being reported as "your controls detected nothing". It
// deliberately ignores asset, event type and correlation — the only
// question is whether the pipeline is delivering at all.
//
// received_at (not observed_at) is the right column: we are asking when
// data reached US, not when it happened on the endpoint. A backfill of
// week-old events still proves the pipeline is alive.
func (r *TelemetryProbeRepository) PipelineLive(ctx context.Context, tenantID shared.ID, since time.Time) (bool, error) {
	const q = `
		SELECT EXISTS (
			SELECT 1 FROM runtime_telemetry_events
			 WHERE tenant_id = $1 AND received_at >= $2
			 LIMIT 1
		)
	`
	var live bool
	if err := r.db.QueryRowContext(ctx, q, tenantID.String(), since.UTC()).Scan(&live); err != nil {
		return false, fmt.Errorf("telemetry pipeline liveness: %w", err)
	}
	return live, nil
}

// CountByCorrelationID counts events a producer explicitly stamped with
// this validation's correlation id. No time bounds — an exact stamp is
// trustworthy whenever it arrives, which is what makes this path immune
// to the late-telemetry false negative that the time-window fallback
// suffers from.
func (r *TelemetryProbeRepository) CountByCorrelationID(ctx context.Context, tenantID, correlationID shared.ID) (int, error) {
	const q = `
		SELECT COUNT(*) FROM runtime_telemetry_events
		 WHERE tenant_id = $1 AND correlation_id = $2
	`
	var n int
	if err := r.db.QueryRowContext(ctx, q, tenantID.String(), correlationID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count telemetry by correlation id: %w", err)
	}
	return n, nil
}

// CountNearTarget counts events on the asset within [from, to] whose
// event_type is one of eventTypes. The heuristic fallback used when no
// producer stamped a correlation id.
//
// observed_at (not received_at) is the right column here: we are asking
// what happened on the endpoint during the probe window, and a
// forwarder's delivery lag must not shift the event out of the window.
func (r *TelemetryProbeRepository) CountNearTarget(
	ctx context.Context,
	tenantID, assetID shared.ID,
	from, to time.Time,
	eventTypes []string,
) (int, error) {
	if len(eventTypes) == 0 {
		return 0, nil
	}
	const q = `
		SELECT COUNT(*) FROM runtime_telemetry_events
		 WHERE tenant_id = $1
		   AND endpoint_asset_id = $2
		   AND observed_at >= $3
		   AND observed_at <= $4
		   AND event_type = ANY($5)
	`
	var n int
	err := r.db.QueryRowContext(ctx, q,
		tenantID.String(), assetID.String(), from.UTC(), to.UTC(), pq.Array(eventTypes),
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count telemetry near target: %w", err)
	}
	return n, nil
}
