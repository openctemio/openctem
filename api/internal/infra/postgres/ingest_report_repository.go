package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// IngestReportRepository implements ingestreport.Repository (RFC-026).
type IngestReportRepository struct {
	db *DB
}

// NewIngestReportRepository constructs an IngestReportRepository.
func NewIngestReportRepository(db *DB) *IngestReportRepository {
	return &IngestReportRepository{db: db}
}

var _ ingestreport.Repository = (*IngestReportRepository)(nil)

const ingestReportColumns = `
	id, tenant_id, sensor_id, report_id, command_id, scan_zone_id, state,
	media_type, sensor_type, user_agent, header_digest, header, tool_name,
	implicit_commit, segment_count, segments_received, assets_received, findings_received, committed_at,
	segment_outcomes, touched_asset_ids, auto_resolved, auto_resolve,
	expires_at, received_at, updated_at`

// Create inserts a report; ErrExists on (tenant, sensor, report_id) conflict.
func (r *IngestReportRepository) Create(ctx context.Context, rep *ingestreport.Report) error {
	header := rep.Header
	if len(header) == 0 {
		header = []byte("{}")
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO ingest_reports (
			id, tenant_id, sensor_id, report_id, command_id, scan_zone_id, state,
			media_type, sensor_type, user_agent, header_digest, header, tool_name,
			implicit_commit, expires_at, received_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $16)
		ON CONFLICT (tenant_id, sensor_id, report_id) DO NOTHING`,
		rep.ID.String(), rep.TenantID.String(), rep.SensorID.String(), rep.ReportID,
		nullIDPtr(rep.CommandID), nullIDPtr(rep.ScanZoneID), string(rep.State),
		rep.MediaType, rep.SensorType, rep.UserAgent, rep.HeaderDigest, header, rep.ToolName,
		rep.ImplicitCommit, rep.ExpiresAt, rep.ReceivedAt,
	)
	if err != nil {
		return fmt.Errorf("create ingest report: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ingestreport.ErrExists
	}
	return nil
}

// Get returns a report scoped to its tenant and sensor.
func (r *IngestReportRepository) Get(ctx context.Context, tenantID, sensorID shared.ID, reportID string) (*ingestreport.Report, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+ingestReportColumns+`
		FROM ingest_reports WHERE tenant_id = $1 AND sensor_id = $2 AND report_id = $3`,
		tenantID.String(), sensorID.String(), reportID)
	return scanIngestReport(row)
}

// GetByID returns a report by primary key.
func (r *IngestReportRepository) GetByID(ctx context.Context, id shared.ID) (*ingestreport.Report, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+ingestReportColumns+`
		FROM ingest_reports WHERE id = $1`, id.String())
	return scanIngestReport(row)
}

// CountOpen counts a sensor's uncommitted, unexpired reports.
func (r *IngestReportRepository) CountOpen(ctx context.Context, sensorID shared.ID, now time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM ingest_reports
		WHERE sensor_id = $1 AND state = 'receiving' AND committed_at IS NULL AND expires_at > $2`,
		sensorID.String(), now).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count open ingest reports: %w", err)
	}
	return n, nil
}

// ReserveSegment counts a segment and its items, refusing past the limits.
func (r *IngestReportRepository) ReserveSegment(ctx context.Context, id shared.ID, assets, findings, maxAssets, maxFindings int, expiresAt time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE ingest_reports
		SET segments_received = segments_received + 1,
			assets_received = assets_received + $2,
			findings_received = findings_received + $3,
			expires_at = GREATEST(expires_at, $6), updated_at = NOW()
		WHERE id = $1
		  AND assets_received + $2 <= $4
		  AND findings_received + $3 <= $5`,
		id.String(), assets, findings, maxAssets, maxFindings, expiresAt)
	if err != nil {
		return false, fmt.Errorf("reserve ingest report segment: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ReleaseSegment undoes a reservation.
func (r *IngestReportRepository) ReleaseSegment(ctx context.Context, id shared.ID, assets, findings int) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE ingest_reports
		SET segments_received = GREATEST(segments_received - 1, 0),
			assets_received = GREATEST(assets_received - $2, 0),
			findings_received = GREATEST(findings_received - $3, 0),
			updated_at = NOW()
		WHERE id = $1`, id.String(), assets, findings)
	if err != nil {
		return fmt.Errorf("release ingest report segment: %w", err)
	}
	return nil
}

// Abandon marks an uncommitted, receiving report expired.
func (r *IngestReportRepository) Abandon(ctx context.Context, id shared.ID) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE ingest_reports SET state = 'expired', updated_at = NOW()
		WHERE id = $1 AND state = 'receiving' AND committed_at IS NULL`, id.String())
	if err != nil {
		return false, fmt.Errorf("abandon ingest report: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// Commit closes a receiving report.
func (r *IngestReportRepository) Commit(ctx context.Context, id shared.ID, segmentCount int, implicit bool, at time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE ingest_reports
		SET committed_at = $2, segment_count = $3, implicit_commit = $4,
			state = 'queued', updated_at = NOW()
		WHERE id = $1 AND committed_at IS NULL AND state = 'receiving'`,
		id.String(), at, segmentCount, implicit)
	if err != nil {
		return false, fmt.Errorf("commit ingest report: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// RecordSegmentOutcome stores a segment's outcome under its number (replacing
// a previous attempt's) and unions the touched asset ids.
func (r *IngestReportRepository) RecordSegmentOutcome(ctx context.Context, id shared.ID, seq int, o ingestreport.SegmentOutcome, touched []shared.ID) error {
	outcome, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("marshal segment outcome: %w", err)
	}
	ids := make([]string, 0, len(touched))
	for _, t := range touched {
		ids = append(ids, t.String())
	}
	_, err = r.db.ExecContext(ctx, `
		UPDATE ingest_reports
		SET segment_outcomes = jsonb_set(segment_outcomes, ARRAY[$2::text], $3::jsonb, true),
			touched_asset_ids = ARRAY(
				SELECT DISTINCT u FROM unnest(touched_asset_ids || $4::uuid[]) AS u
			),
			updated_at = NOW()
		WHERE id = $1`,
		id.String(), ingestreport.OutcomeKey(seq), outcome, pq.Array(ids))
	if err != nil {
		return fmt.Errorf("record segment outcome: %w", err)
	}
	return nil
}

// ClaimFinalize moves a committed report with an outcome for every segment
// to processing. Exactly one caller wins.
func (r *IngestReportRepository) ClaimFinalize(ctx context.Context, id shared.ID) (*ingestreport.Report, bool, error) {
	row := r.db.QueryRowContext(ctx, `
		UPDATE ingest_reports
		SET state = 'processing', updated_at = NOW()
		WHERE id = $1
		  AND committed_at IS NOT NULL
		  AND state = 'queued'
		  AND (SELECT COUNT(*) FROM jsonb_object_keys(segment_outcomes)) >= segment_count
		RETURNING `+ingestReportColumns, id.String())
	rep, err := scanIngestReport(row)
	if errors.Is(err, ingestreport.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return rep, true, nil
}

// Finish records the final state and the auto-resolve outcome.
func (r *IngestReportRepository) Finish(ctx context.Context, id shared.ID, state ingestreport.State, autoResolved int, autoResolve string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE ingest_reports
		SET state = $2, auto_resolved = $3, auto_resolve = NULLIF($4, ''), updated_at = NOW()
		WHERE id = $1`, id.String(), string(state), autoResolved, autoResolve)
	if err != nil {
		return fmt.Errorf("finish ingest report: %w", err)
	}
	return nil
}

// MarkFailed marks a report failed unless it already finished.
func (r *IngestReportRepository) MarkFailed(ctx context.Context, id shared.ID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE ingest_reports SET state = 'failed', updated_at = NOW()
		WHERE id = $1 AND state NOT IN ('completed', 'expired')`, id.String())
	if err != nil {
		return fmt.Errorf("mark ingest report failed: %w", err)
	}
	return nil
}

// Reopen returns a failed report to queued (committed) or receiving.
func (r *IngestReportRepository) Reopen(ctx context.Context, id shared.ID, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE ingest_reports
		SET state = CASE WHEN committed_at IS NULL THEN 'receiving' ELSE 'queued' END,
			expires_at = GREATEST(expires_at, $2), updated_at = NOW()
		WHERE id = $1 AND state = 'failed'`, id.String(), expiresAt)
	if err != nil {
		return fmt.Errorf("reopen ingest report: %w", err)
	}
	return nil
}

// ExpireStale marks uncommitted reports past their expiry expired.
func (r *IngestReportRepository) ExpireStale(ctx context.Context, now time.Time) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE ingest_reports SET state = 'expired', updated_at = NOW()
		WHERE state = 'receiving' AND committed_at IS NULL AND expires_at < $1`, now)
	if err != nil {
		return 0, fmt.Errorf("expire ingest reports: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// PurgeStaging bounds what reports that will never be applied keep
// (RFC-026 staging): it empties the segment payloads of expired reports
// (expired by their window or abandoned by the sensor: nothing reads them
// again), and deletes, at most batch rows each, the failed and expired
// reports (their jobs cascade) and the finished jobs without a report last
// changed before before. Completed reports are kept: coverage and CI
// coverage read them.
func (r *IngestReportRepository) PurgeStaging(ctx context.Context, before time.Time, batch int) (ingestreport.StagingPurge, error) {
	var out ingestreport.StagingPurge
	res, err := r.db.ExecContext(ctx, `
		UPDATE ingest_jobs j SET payload = ''::bytea, updated_at = NOW()
		WHERE j.id IN (
			SELECT j2.id FROM ingest_jobs j2
			JOIN ingest_reports ir ON ir.id = j2.ingest_report_id
			WHERE ir.state = 'expired' AND octet_length(j2.payload) > 0
			LIMIT $1)`, batch)
	if err != nil {
		return out, fmt.Errorf("clear expired report payloads: %w", err)
	}
	n, _ := res.RowsAffected()
	out.PayloadsCleared = int(n)

	res, err = r.db.ExecContext(ctx, `
		DELETE FROM ingest_reports WHERE id IN (
			SELECT id FROM ingest_reports
			WHERE state IN ('failed', 'expired') AND updated_at < $1
			LIMIT $2)`, before, batch)
	if err != nil {
		return out, fmt.Errorf("delete stale ingest reports: %w", err)
	}
	n, _ = res.RowsAffected()
	out.ReportsDeleted = int(n)

	res, err = r.db.ExecContext(ctx, `
		DELETE FROM ingest_jobs WHERE id IN (
			SELECT id FROM ingest_jobs
			WHERE ingest_report_id IS NULL AND status IN ('completed', 'dead') AND updated_at < $1
			LIMIT $2)`, before, batch)
	if err != nil {
		return out, fmt.Errorf("delete finished ingest jobs: %w", err)
	}
	n, _ = res.RowsAffected()
	out.JobsDeleted = int(n)
	return out, nil
}

func scanIngestReport(row rowScanner) (*ingestreport.Report, error) {
	var (
		rep                ingestreport.Report
		id, tenant, sensor string
		reportID           string
		commandID, zoneID  sql.NullString
		state              string
		header, outcomes   []byte
		segmentCount       sql.NullInt64
		committedAt        sql.NullTime
		touched            []string
		autoResolve        sql.NullString
	)
	err := row.Scan(
		&id, &tenant, &sensor, &reportID, &commandID, &zoneID, &state,
		&rep.MediaType, &rep.SensorType, &rep.UserAgent, &rep.HeaderDigest, &header, &rep.ToolName,
		&rep.ImplicitCommit, &segmentCount, &rep.SegmentsReceived, &rep.AssetsReceived, &rep.FindingsReceived, &committedAt,
		&outcomes, pq.Array(&touched), &rep.AutoResolved, &autoResolve,
		&rep.ExpiresAt, &rep.ReceivedAt, &rep.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ingestreport.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan ingest report: %w", err)
	}
	if rep.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("parse ingest report id: %w", err)
	}
	if rep.TenantID, err = shared.IDFromString(tenant); err != nil {
		return nil, fmt.Errorf("parse ingest report tenant: %w", err)
	}
	if rep.SensorID, err = shared.IDFromString(sensor); err != nil {
		return nil, fmt.Errorf("parse ingest report sensor: %w", err)
	}
	rep.ReportID = reportID
	rep.CommandID = parseNullID(commandID)
	rep.ScanZoneID = parseNullID(zoneID)
	rep.State = protov2.ReportState(state)
	rep.Header = header
	if segmentCount.Valid {
		n := int(segmentCount.Int64)
		rep.SegmentCount = &n
	}
	if committedAt.Valid {
		t := committedAt.Time
		rep.CommittedAt = &t
	}
	raw := map[string]ingestreport.SegmentOutcome{}
	if len(outcomes) > 0 {
		if err := json.Unmarshal(outcomes, &raw); err != nil {
			return nil, fmt.Errorf("parse segment outcomes: %w", err)
		}
	}
	if rep.Outcomes, err = ingestreport.ParseOutcomes(raw); err != nil {
		return nil, err
	}
	rep.TouchedAssetIDs = make([]shared.ID, 0, len(touched))
	for _, t := range touched {
		tid, err := shared.IDFromString(t)
		if err != nil {
			return nil, fmt.Errorf("parse touched asset id: %w", err)
		}
		rep.TouchedAssetIDs = append(rep.TouchedAssetIDs, tid)
	}
	rep.AutoResolve = autoResolve.String
	return &rep, nil
}
