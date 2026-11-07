package postgres

// Finding source records: what each source reported for a finding, one row
// per finding and source (docs/architecture/finding-source-records.md).
// Every statement is pinned to the tenant: findings are matched by
// fingerprint under the caller's tenant, and the sensor is kept only when it
// is one of the tenant's own sensors.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// maxSourceRecordBatch bounds the rows of one upsert statement.
const maxSourceRecordBatch = 500

// sourceRecordValueCols are the value columns of finding_source_records, in
// the order of the upsert's input arrays ($11 onward), with their casts.
var sourceRecordValueCols = func() []struct{ name, cast string } {
	jsonCols := map[string]bool{}
	for _, n := range strings.Fields(`type_details source_meta scores vulnerability_ids source_extra`) {
		jsonCols[n] = true
	}
	names := strings.Fields(`tool_version title description snippet recommendation message severity cvss_score
		cvss_vector type_details native_vuln_id native_scheme source_meta scores vulnerability_ids source_extra
		location_key`)
	out := make([]struct{ name, cast string }, 0, len(names))
	for _, n := range names {
		c := ""
		if jsonCols[n] {
			c = sqlJSONBCast
		}
		out = append(out, struct{ name, cast string }{n, c})
	}
	return out
}()

// Casts of the upsert's inputs.
const (
	sqlJSONBCast    = "::jsonb"
	sqlTextArray    = "text[]"
	sqlNumericArray = "numeric[]"
)

// upsertSourceRecordsSQL writes what one source reported.
//
//	$1 tenant, $2 channel, $3 sensor id (nullable), $4 sender, $5 tool,
//	$6 whether the sender is a sensor, $7 the per-finding cap,
//	$8 fingerprints, $9 observed at, $10 clipped, then one array per
//	value column (sourceRecordValueCols).
//
// A repeat of the source replaces each value it carries when its
// observation is not older than the stored one; an empty value never
// erases. Rows are written in finding id order.
var upsertSourceRecordsSQL = func() string {
	inArrays := "$8::text[], $9::timestamptz[], $10::boolean[]"
	inNames := "fingerprint, observed_at, clipped"
	insCols, insVals, sets := "", "", ""
	for i, c := range sourceRecordValueCols {
		typ := sqlTextArray
		if c.name == "cvss_score" {
			typ = sqlNumericArray
		}
		inArrays += fmt.Sprintf(", $%d::%s", 11+i, typ)
		inNames += ", " + c.name
		insCols += ", " + c.name
		insVals += ", d." + c.name + c.cast
		sets += fmt.Sprintf(`,
	%[1]s = CASE WHEN EXCLUDED.last_seen_at >= r.last_seen_at
		THEN COALESCE(EXCLUDED.%[1]s, r.%[1]s) ELSE COALESCE(r.%[1]s, EXCLUDED.%[1]s) END`, c.name)
	}
	return `
WITH sen AS (
	SELECT s.id FROM sensors s WHERE s.tenant_id = $1 AND s.id = $3::uuid
), src AS (
	SELECT (SELECT id FROM sen) AS sensor_id,
		CASE WHEN $6::boolean AND (SELECT id FROM sen) IS NULL THEN '` + ingestreceipt.SharedSensorSender + `' ELSE $4::text END AS sender
), d AS (
	SELECT f.id AS finding_id, i.*
	FROM unnest(` + inArrays + `) AS i(` + inNames + `)
	JOIN findings f ON f.tenant_id = $1 AND f.fingerprint = i.fingerprint
)
INSERT INTO finding_source_records AS r (tenant_id, finding_id, channel, sensor_id, sender, tool,
	first_seen_at, last_seen_at, clipped` + insCols + `)
SELECT $1::uuid, d.finding_id, $2::text, src.sensor_id, src.sender, $5::text,
	d.observed_at, d.observed_at, d.clipped` + insVals + `
FROM d CROSS JOIN src
WHERE (SELECT count(*) FROM finding_source_records x WHERE x.tenant_id = $1 AND x.finding_id = d.finding_id) < $7::integer
   OR EXISTS (SELECT 1 FROM finding_source_records x
		WHERE x.tenant_id = $1 AND x.finding_id = d.finding_id AND x.channel = $2::text
		  AND x.sensor_id IS NOT DISTINCT FROM src.sensor_id AND x.sender = src.sender AND x.tool = $5::text)
ORDER BY d.finding_id
ON CONFLICT (tenant_id, finding_id, channel, sensor_id, sender, tool) DO UPDATE SET
	first_seen_at = LEAST(r.first_seen_at, EXCLUDED.first_seen_at),
	last_seen_at  = GREATEST(r.last_seen_at, EXCLUDED.last_seen_at),
	clipped     = r.clipped OR EXCLUDED.clipped,
	backfilled    = false,
	updated_at    = now()` + sets
}()

// UpsertSourceRecords stores what src reported for the tenant's findings
// with the given fingerprints (vulnerability.SourceRecordRepository). Values
// are sanitized here; a fingerprint the tenant has no finding for writes
// nothing. Returns the rows inserted or updated.
func (r *FindingRepository) UpsertSourceRecords(ctx context.Context, tenantID shared.ID, src vulnerability.SourceIdentity,
	values []vulnerability.SourceRecordValues) (int64, error) {
	if len(values) == 0 {
		return 0, nil
	}
	channel := src.Channel
	if channel == "" || channel == string(ingestreceipt.ChannelUnknown) {
		return 0, fmt.Errorf("source records: channel %q is not a sighting channel", channel)
	}
	// One row per fingerprint (a repeat within a batch would hit the same
	// row twice): the newest observation wins, in fingerprint order.
	now := time.Now().UTC()
	byFP := make(map[string]vulnerability.SourceRecordValues, len(values))
	for _, v := range values {
		if v.Fingerprint == "" {
			continue
		}
		if v.ObservedAt.IsZero() {
			v.ObservedAt = now
		}
		if old, ok := byFP[v.Fingerprint]; ok && old.ObservedAt.After(v.ObservedAt) {
			continue
		}
		byFP[v.Fingerprint] = v.Sanitize()
	}
	fps := make([]string, 0, len(byFP))
	for fp := range byFP {
		fps = append(fps, fp)
	}
	sort.Strings(fps)

	var sensorID sql.NullString
	if src.SensorID != nil && !src.SensorID.IsZero() {
		sensorID = sql.NullString{String: src.SensorID.String(), Valid: true}
	}
	sender := ""
	if !src.IsSensor {
		sender = clip(src.Sender, maxSightingSender)
	}
	tool := clipTool(src.Tool)
	if tool == unknownTool {
		tool = ""
	}

	var total int64
	for start := 0; start < len(fps); start += maxSourceRecordBatch {
		chunk := fps[start:min(start+maxSourceRecordBatch, len(fps))]
		args, err := sourceRecordArgs(chunk, byFP)
		if err != nil {
			return total, err
		}
		args = append([]any{tenantID.String(), channel, sensorID, sender, tool, src.IsSensor,
			vulnerability.MaxSourceRecordsPerFinding}, args...)
		res, err := r.db.ExecContext(ctx, upsertSourceRecordsSQL, args...)
		if err != nil {
			return total, fmt.Errorf("upsert finding source records: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// sourceRecordArgs builds the input arrays of one upsert chunk ($8 on).
func sourceRecordArgs(fps []string, byFP map[string]vulnerability.SourceRecordValues) ([]any, error) {
	n := len(fps)
	observed := make([]string, n)
	clipped := make([]bool, n)
	cols := make([][]sql.NullString, len(sourceRecordValueCols))
	for i := range cols {
		cols[i] = make([]sql.NullString, n)
	}
	for i, fp := range fps {
		v := byFP[fp]
		observed[i] = v.ObservedAt.UTC().Format(time.RFC3339Nano)
		clipped[i] = v.Truncated
		var nid, scheme string
		if v.Interop.Native != nil {
			nid, scheme = v.Interop.Native.VulnID, v.Interop.Native.Scheme
		}
		var score string
		if v.CVSSScore != nil {
			score = fmt.Sprintf("%.1f", *v.CVSSScore)
		}
		var typeDetails sql.NullString
		if len(v.TypeDetails) > 0 {
			typeDetails = sql.NullString{String: string(v.TypeDetails), Valid: true}
		}
		row := []sql.NullString{
			nullString(v.ToolVersion), nullString(v.Title), nullString(v.Description), nullString(v.Snippet),
			nullString(v.Recommendation), nullString(v.Message), nullString(v.Severity), nullString(score),
			nullString(v.CVSSVector), typeDetails, nullString(nid), nullString(scheme),
			jsonOrNull(v.Interop.SourceMeta()), jsonOrNull(v.Interop.Scores), jsonOrNull(v.Interop.VulnerabilityIDs),
			jsonOrNull(v.Interop.SourceExtra), nullString(v.Interop.LocationKey),
		}
		if len(row) != len(sourceRecordValueCols) {
			return nil, fmt.Errorf("source records: %d values for %d columns", len(row), len(sourceRecordValueCols))
		}
		for c := range row {
			cols[c][i] = row[c]
		}
	}
	args := []any{pq.Array(fps), pq.Array(observed), pq.Array(clipped)}
	for _, c := range cols {
		args = append(args, pq.Array(c))
	}
	return args, nil
}

// ListSourceRecords returns the source records of one finding of the
// tenant, the primary (first reporting) tool's first, then by first seen.
// The sensor's name is joined under the tenant. ErrNotFound when the
// finding is not the tenant's.
func (r *FindingRepository) ListSourceRecords(ctx context.Context, tenantID, findingID shared.ID) ([]vulnerability.SourceRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.channel, s.sensor_id::text, COALESCE(se.name, ''), s.sender, s.tool, COALESCE(s.tool_version, ''),
			s.first_seen_at, s.last_seen_at, s.clipped, s.backfilled,
			(btrim(f.tool_name) <> '' AND lower(btrim(f.tool_name)) = lower(btrim(s.tool))) AS is_primary,
			COALESCE(s.title, ''), COALESCE(s.description, ''), COALESCE(s.snippet, ''), COALESCE(s.recommendation, ''),
			COALESCE(s.message, ''), COALESCE(s.severity, ''), s.cvss_score::float8, COALESCE(s.cvss_vector, ''),
			s.type_details, COALESCE(s.native_vuln_id, ''), COALESCE(s.native_scheme, ''), s.source_meta, s.scores,
			s.vulnerability_ids, s.source_extra, COALESCE(s.location_key, '')
		FROM finding_source_records s
		JOIN findings f ON f.tenant_id = s.tenant_id AND f.id = s.finding_id
		LEFT JOIN sensors se ON se.tenant_id = s.tenant_id AND se.id = s.sensor_id
		WHERE s.tenant_id = $1 AND s.finding_id = $2
		ORDER BY is_primary DESC, s.first_seen_at, s.channel, s.tool, s.sender
		LIMIT $3`, tenantID.String(), findingID.String(), 2*vulnerability.MaxSourceRecordsPerFinding)
	if err != nil {
		return nil, fmt.Errorf("list finding source records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]vulnerability.SourceRecord, 0, 4)
	for rows.Next() {
		rec, err := scanSourceRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list finding source records: %w", err)
	}
	if len(out) == 0 {
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

func scanSourceRecord(rows *sql.Rows) (vulnerability.SourceRecord, error) {
	var rec vulnerability.SourceRecord
	v := &rec.Values
	var sensorID sql.NullString
	var score sql.NullFloat64
	var typeDetails, meta, scores, vids, extra []byte
	var nativeID, scheme string
	if err := rows.Scan(&rec.Channel, &sensorID, &rec.SensorName, &rec.Sender, &rec.Tool, &v.ToolVersion,
		&rec.FirstSeenAt, &rec.LastSeenAt, &v.Truncated, &rec.Backfilled, &rec.Primary,
		&v.Title, &v.Description, &v.Snippet, &v.Recommendation, &v.Message, &v.Severity, &score, &v.CVSSVector,
		&typeDetails, &nativeID, &scheme, &meta, &scores, &vids, &extra, &v.Interop.LocationKey); err != nil {
		return rec, fmt.Errorf("scan finding source record: %w", err)
	}
	rec.SensorID = nullIDFromString(sensorID)
	if score.Valid {
		s := score.Float64
		v.CVSSScore = &s
	}
	if len(typeDetails) > 0 {
		v.TypeDetails = json.RawMessage(typeDetails)
	}
	if len(meta) > 0 {
		var m vulnerability.InteropSourceMeta
		if json.Unmarshal(meta, &m) == nil {
			v.Interop.Native, v.Interop.Lifecycle, v.Interop.Solution = m.Native, m.Lifecycle, m.Solution
		}
	}
	if v.Interop.Native == nil && (nativeID != "" || scheme != "") {
		v.Interop.Native = &vulnerability.InteropNative{}
	}
	if v.Interop.Native != nil {
		if v.Interop.Native.VulnID == "" {
			v.Interop.Native.VulnID = nativeID
		}
		if v.Interop.Native.Scheme == "" {
			v.Interop.Native.Scheme = scheme
		}
	}
	if len(scores) > 0 {
		_ = json.Unmarshal(scores, &v.Interop.Scores)
	}
	if len(vids) > 0 {
		_ = json.Unmarshal(vids, &v.Interop.VulnerabilityIDs)
	}
	if len(extra) > 0 {
		_ = json.Unmarshal(extra, &v.Interop.SourceExtra)
	}
	// Stored rows were sanitized on write; sanitizing on read keeps a row
	// written by any other path (the backfill) within the same bounds.
	v.Interop = vulnerability.SanitizeInteropData(v.Interop)
	return rec, nil
}

// foldLoserSourceRecords prepares a finding merge: a source both findings
// have is folded into the survivor's record (the earlier first seen, the
// later last seen, the newer record's values with the older one's filling
// what it leaves empty), so the generic move that follows drops nothing a
// source said. The loser's other records then move to the survivor.
func foldLoserSourceRecords(ctx context.Context, tx *sql.Tx, tenantID, survivorID, loserID string) error {
	sets := ""
	for _, c := range sourceRecordValueCols {
		sets += fmt.Sprintf(`,
			%[1]s = CASE WHEN l.last_seen_at > s.last_seen_at THEN COALESCE(l.%[1]s, s.%[1]s) ELSE COALESCE(s.%[1]s, l.%[1]s) END`, c.name)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE finding_source_records s SET
			first_seen_at = LEAST(s.first_seen_at, l.first_seen_at),
			last_seen_at = GREATEST(s.last_seen_at, l.last_seen_at),
			clipped = s.clipped OR l.clipped,
			backfilled = s.backfilled AND l.backfilled,
			updated_at = now()`+sets+`
		FROM finding_source_records l
		WHERE s.tenant_id = $3 AND s.finding_id = $1 AND l.tenant_id = $3 AND l.finding_id = $2
		  AND l.channel = s.channel AND l.sensor_id IS NOT DISTINCT FROM s.sensor_id
		  AND l.sender = s.sender AND l.tool = s.tool`, survivorID, loserID, tenantID); err != nil {
		return fmt.Errorf("fold merged finding's source records: %w", err)
	}
	return nil
}
