package postgres

// Finding sightings: who reported a finding, one row per finding and source
// (docs/architecture/finding-sightings.md). recordSightings runs inside the
// receipt transaction (IngestReceiptRepository.Record), so a sighting is
// recorded exactly when its receipt is. Every statement is pinned to the
// tenant: the findings, the command, its step and run, and the sensor are
// all read under the receipt's tenant_id, so a row can only ever name the
// tenant's own sensor and scan.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// maxSightingSender is the width of finding_sightings.sender.
const maxSightingSender = 128

// recordSightingsSQL upserts the sightings of one delta.
//
//	$1 tenant, $2 channel, $3 sensor id (nullable), $4 sender, $5 tool,
//	$6 tool version, $7 command id (nullable), $8 receipt id, $9 source ref,
//	$10 at, $11 finding ids, $12 fingerprints, $13 the per-finding cap,
//	$14 whether the sender is a sensor.
//
// The command's step, run and scan, and the sensor, resolve only under
// the tenant: a shared sensor (no tenant) is recorded without its id, as
// the platform. A repeat within one receipt changes nothing (one write per
// finding and run, however many reports the run sends); a new receipt
// moves last seen and counts once. Rows are written in finding id order so
// concurrent receipts lock them in the same order.
const recordSightingsSQL = `
WITH cmd AS (
	SELECT st.id AS step_id, sr.id AS run_id, sr.scan_id
	FROM commands c
	LEFT JOIN scan_run_steps st ON st.id = c.scan_run_step_id
	LEFT JOIN scan_runs sr ON sr.id = st.scan_run_id AND sr.tenant_id = c.tenant_id
	WHERE c.tenant_id = $1 AND c.id = $7::uuid
), sen AS (
	SELECT s.id FROM sensors s WHERE s.tenant_id = $1 AND s.id = $3::uuid
), src AS (
	SELECT (SELECT id FROM sen) AS sensor_id,
		CASE WHEN $14::boolean AND (SELECT id FROM sen) IS NULL THEN '` + ingestreceipt.SharedSensorSender + `' ELSE $4::text END AS sender,
		(SELECT scan_id FROM cmd) AS scan_id, (SELECT run_id FROM cmd) AS run_id, (SELECT step_id FROM cmd) AS step_id
), hit AS (
	SELECT f.id FROM findings f
	WHERE f.tenant_id = $1 AND (f.id = ANY($11::uuid[]) OR f.fingerprint = ANY($12::text[]))
)
INSERT INTO finding_sightings (tenant_id, finding_id, channel, sensor_id, sender, tool, scan_id, tool_version,
	first_seen_at, last_seen_at, seen_count, first_receipt_id, last_receipt_id, last_source_ref, last_run_id,
	last_step_run_id, last_command_id)
SELECT $1::uuid, hit.id, $2::text, src.sensor_id, src.sender, $5::text, src.scan_id, NULLIF($6::text, ''),
	$10::timestamptz, $10::timestamptz, 1, $8::uuid, $8::uuid, $9::text, src.run_id, src.step_id, $7::uuid
FROM hit CROSS JOIN src
WHERE (SELECT count(*) FROM finding_sightings x WHERE x.tenant_id = $1 AND x.finding_id = hit.id) < $13::integer
   OR EXISTS (SELECT 1 FROM finding_sightings x
		WHERE x.tenant_id = $1 AND x.finding_id = hit.id AND x.channel = $2::text
		  AND x.sensor_id IS NOT DISTINCT FROM src.sensor_id AND x.sender = src.sender AND x.tool = $5::text
		  AND x.scan_id IS NOT DISTINCT FROM src.scan_id)
ORDER BY hit.id
ON CONFLICT (tenant_id, finding_id, channel, sensor_id, sender, tool, scan_id) DO UPDATE SET
	last_seen_at     = GREATEST(finding_sightings.last_seen_at, EXCLUDED.last_seen_at),
	first_seen_at    = LEAST(finding_sightings.first_seen_at, EXCLUDED.first_seen_at),
	seen_count       = finding_sightings.seen_count + 1,
	last_receipt_id  = EXCLUDED.last_receipt_id,
	last_source_ref  = EXCLUDED.last_source_ref,
	last_run_id      = COALESCE(EXCLUDED.last_run_id, finding_sightings.last_run_id),
	last_step_run_id = COALESCE(EXCLUDED.last_step_run_id, finding_sightings.last_step_run_id),
	last_command_id  = COALESCE(EXCLUDED.last_command_id, finding_sightings.last_command_id),
	tool_version     = COALESCE(EXCLUDED.tool_version, finding_sightings.tool_version)
WHERE finding_sightings.last_receipt_id IS DISTINCT FROM EXCLUDED.last_receipt_id`

// recordSightings records who reported the delta's findings: the created,
// reopened, policy-decided and still-detected ones. A coverage decision
// (no report) and a closure are not sightings.
func recordSightings(ctx context.Context, tx *sql.Tx, d *ingestreceipt.Delta, kind ingestreceipt.SourceKind,
	ref string, receiptID shared.ID, at time.Time) error {
	if d.Reports == 0 {
		return nil
	}
	ids := make([]string, 0, len(d.Created)+len(d.Reopened)+len(d.Decided))
	for _, id := range d.Created {
		ids = append(ids, id.String())
	}
	for _, id := range d.Reopened {
		ids = append(ids, id.String())
	}
	for _, a := range d.Decided {
		ids = append(ids, a.FindingID.String())
	}
	fps := nonEmptyUnique(d.StillDetected)
	if len(ids) == 0 && len(fps) == 0 {
		return nil
	}
	var sensorID, commandID sql.NullString
	isSensor := d.Instance.Kind == ingestreceipt.InstanceSensor
	sender := ""
	switch d.Instance.Kind {
	case ingestreceipt.InstanceSensor:
		if id, err := shared.IDFromString(d.Instance.ID); err == nil && !id.IsZero() {
			sensorID = sql.NullString{String: id.String(), Valid: true}
		}
	case ingestreceipt.InstanceCI, ingestreceipt.InstanceConnector:
		sender = clip(d.Instance.ID, maxSightingSender)
	}
	if d.Source.CommandID != nil {
		commandID = sql.NullString{String: d.Source.CommandID.String(), Valid: true}
	}
	tool := clipTool(d.Tool)
	if tool == unknownTool {
		tool = ""
	}
	_, err := tx.ExecContext(ctx, recordSightingsSQL,
		d.TenantID.String(), string(ingestreceipt.ChannelOf(kind)), sensorID, sender, tool,
		clip(d.ToolVersion, maxToolName), commandID, receiptID.String(), clip(ref, 128), at,
		pq.Array(ids), pq.Array(fps), ingestreceipt.MaxSightingsPerFinding, isSensor)
	if err != nil {
		return fmt.Errorf("record sightings: %w", err)
	}
	return nil
}

// FindingSightings returns the sources of one finding, last seen first.
// Sensor and scan names are joined under the tenant (a deleted sensor or
// scan keeps its id and loses its name); the receipt is reported as kept
// only while it exists.
func (r *IngestReceiptRepository) FindingSightings(ctx context.Context, tenantID, findingID shared.ID) ([]ingestreceipt.Sighting, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.channel, s.sensor_id::text, COALESCE(se.name, ''), s.sender, s.tool, COALESCE(s.tool_version, ''),
			s.scan_id::text, COALESCE(sc.name, ''), s.first_seen_at, s.last_seen_at, s.seen_count,
			s.last_receipt_id::text, (ir.id IS NOT NULL), COALESCE(s.last_source_ref, ''), s.last_run_id::text,
			s.last_step_run_id::text, s.last_command_id::text, s.first_receipt_id::text, s.backfilled
		FROM finding_sightings s
		LEFT JOIN sensors se ON se.tenant_id = s.tenant_id AND se.id = s.sensor_id
		LEFT JOIN scans sc ON sc.tenant_id = s.tenant_id AND sc.id = s.scan_id
		LEFT JOIN ingest_receipts ir ON ir.tenant_id = s.tenant_id AND ir.id = s.last_receipt_id
		WHERE s.tenant_id = $1 AND s.finding_id = $2
		ORDER BY s.last_seen_at DESC, s.channel, s.tool
		LIMIT $3`, tenantID.String(), findingID.String(), ingestreceipt.MaxSightingsPerFinding)
	if err != nil {
		return nil, fmt.Errorf("list finding sightings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]ingestreceipt.Sighting, 0, 4)
	for rows.Next() {
		var s ingestreceipt.Sighting
		var channel string
		var sensorID, scanID, receiptID, runID, stepID, commandID, firstReceipt sql.NullString
		if err := rows.Scan(&channel, &sensorID, &s.SensorName, &s.Sender, &s.Tool, &s.ToolVersion, &scanID,
			&s.ScanName, &s.FirstSeenAt, &s.LastSeenAt, &s.SeenCount, &receiptID, &s.ReceiptKept, &s.LastSourceRef,
			&runID, &stepID, &commandID, &firstReceipt, &s.Backfilled); err != nil {
			return nil, fmt.Errorf("scan finding sighting: %w", err)
		}
		s.Channel = ingestreceipt.Channel(channel)
		s.SensorID, s.ScanID, s.LastReceiptID = nullIDFromString(sensorID), nullIDFromString(scanID), nullIDFromString(receiptID)
		s.LastRunID, s.LastStepRunID, s.LastCommandID = nullIDFromString(runID), nullIDFromString(stepID), nullIDFromString(commandID)
		s.FirstReceiptID = nullIDFromString(firstReceipt)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list finding sightings: %w", err)
	}
	if len(out) == 0 {
		// No sources: say whether the finding is the tenant's at all, so
		// another tenant's id answers not found rather than an empty list.
		var mine bool
		if err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM findings WHERE tenant_id = $1 AND id = $2)`,
			tenantID.String(), findingID.String()).Scan(&mine); err != nil {
			return nil, fmt.Errorf("check finding: %w", err)
		}
		if !mine {
			return nil, shared.ErrNotFound
		}
	}
	return out, nil
}
