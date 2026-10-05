package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Source interoperability data of findings (migration 001105, CTIS 1.4).
// Written and read here only, never by the generic finding SELECT, so lists,
// exports, tickets and notifications cannot carry it. Every statement is
// scoped by tenant_id.

// maxInteropBatch bounds one UPDATE (rows per statement).
const maxInteropBatch = 500

// UpdateInteropBatch stores each sighting's interop data on the tenant's
// finding with that fingerprint. A member the sighting does not carry keeps
// the stored value; one it carries replaces it (the latest sighting wins).
// Data is sanitized again here (defense in depth).
func (r *FindingRepository) UpdateInteropBatch(ctx context.Context, tenantID shared.ID, updates []vulnerability.InteropUpdate) (int64, error) {
	var total int64
	for start := 0; start < len(updates); start += maxInteropBatch {
		end := min(start+maxInteropBatch, len(updates))
		n := end - start
		fps := make([]string, 0, n)
		nativeIDs := make([]sql.NullString, 0, n)
		schemes := make([]sql.NullString, 0, n)
		metas := make([]sql.NullString, 0, n)
		scores := make([]sql.NullString, 0, n)
		vids := make([]sql.NullString, 0, n)
		extras := make([]sql.NullString, 0, n)
		locs := make([]sql.NullString, 0, n)
		vexStatus := make([]sql.NullString, 0, n)
		vexJust := make([]sql.NullString, 0, n)
		vexStmt := make([]sql.NullString, 0, n)
		vexSrc := make([]sql.NullString, 0, n)
		vexAt := make([]sql.NullString, 0, n) // RFC 3339, cast to timestamptz
		for _, u := range updates[start:end] {
			d := vulnerability.SanitizeInteropData(u.Data)
			if u.Fingerprint == "" || d.IsEmpty() {
				continue
			}
			fps = append(fps, u.Fingerprint)
			var nid, scheme string
			if d.Native != nil {
				nid, scheme = d.Native.VulnID, d.Native.Scheme
			}
			nativeIDs = append(nativeIDs, nullString(nid))
			schemes = append(schemes, nullString(scheme))
			metas = append(metas, jsonOrNull(d.SourceMeta()))
			scores = append(scores, jsonOrNull(d.Scores))
			vids = append(vids, jsonOrNull(d.VulnerabilityIDs))
			extras = append(extras, jsonOrNull(d.SourceExtra))
			locs = append(locs, nullString(d.LocationKey))
			if v := d.VEX; v != nil {
				vexStatus = append(vexStatus, nullString(v.Status))
				vexJust = append(vexJust, nullString(v.Justification))
				vexStmt = append(vexStmt, nullString(v.Statement))
				vexSrc = append(vexSrc, nullString(v.Source))
				at := time.Now().UTC()
				if v.AsOf != nil {
					at = *v.AsOf
				}
				vexAt = append(vexAt, sql.NullString{String: at.UTC().Format(time.RFC3339Nano), Valid: true})
			} else {
				vexStatus = append(vexStatus, sql.NullString{})
				vexJust = append(vexJust, sql.NullString{})
				vexStmt = append(vexStmt, sql.NullString{})
				vexSrc = append(vexSrc, sql.NullString{})
				vexAt = append(vexAt, sql.NullString{})
			}
		}
		if len(fps) == 0 {
			continue
		}
		// A VEX statement replaces the previous one as a whole (status,
		// justification, statement, source, time), so a new statement never
		// keeps an old justification.
		res, err := r.db.ExecContext(ctx, `
			UPDATE findings AS f SET
				native_vuln_id    = COALESCE(d.native_vuln_id, f.native_vuln_id),
				native_scheme     = COALESCE(d.native_scheme, f.native_scheme),
				source_meta       = COALESCE(d.source_meta::jsonb, f.source_meta),
				scores            = COALESCE(d.scores::jsonb, f.scores),
				vulnerability_ids = COALESCE(d.vulnerability_ids::jsonb, f.vulnerability_ids),
				source_extra      = COALESCE(d.source_extra::jsonb, f.source_extra),
				location_key      = COALESCE(d.location_key, f.location_key),
				vex_status        = CASE WHEN d.vex_status IS NOT NULL THEN d.vex_status ELSE f.vex_status END,
				vex_justification = CASE WHEN d.vex_status IS NOT NULL THEN d.vex_justification ELSE f.vex_justification END,
				vex_statement     = CASE WHEN d.vex_status IS NOT NULL THEN d.vex_statement ELSE f.vex_statement END,
				vex_source        = CASE WHEN d.vex_status IS NOT NULL THEN d.vex_source ELSE f.vex_source END,
				vex_at            = CASE WHEN d.vex_status IS NOT NULL THEN d.vex_at::timestamptz ELSE f.vex_at END
			FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[],
				$9::text[], $10::text[], $11::text[], $12::text[], $13::text[], $14::text[])
				AS d(fingerprint, native_vuln_id, native_scheme, source_meta, scores, vulnerability_ids, source_extra,
					location_key, vex_status, vex_justification, vex_statement, vex_source, vex_at)
			WHERE f.tenant_id = $1 AND f.fingerprint = d.fingerprint`,
			tenantID.String(), pq.Array(fps), pq.Array(nativeIDs), pq.Array(schemes), pq.Array(metas),
			pq.Array(scores), pq.Array(vids), pq.Array(extras), pq.Array(locs),
			pq.Array(vexStatus), pq.Array(vexJust), pq.Array(vexStmt), pq.Array(vexSrc), pq.Array(vexAt))
		if err != nil {
			return total, fmt.Errorf("update finding interop data: %w", err)
		}
		rows, _ := res.RowsAffected()
		total += rows
	}
	return total, nil
}

func jsonOrNull(v any) sql.NullString {
	b := vulnerability.MarshalJSONOrNil(v)
	if b == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}

// GetInterop returns the interop data of one finding of the tenant. The
// caller has already authorized the finding (tenant, data scope, pentest
// membership); a missing finding is ErrNotFound. Nil without an error when
// the finding has none.
func (r *FindingRepository) GetInterop(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.InteropData, error) {
	var meta, scores, vids, extra []byte
	var loc, vexStatus, vexJust, vexStmt, vexSrc sql.NullString
	var vexAt sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		SELECT source_meta, scores, vulnerability_ids, source_extra, location_key,
			vex_status, vex_justification, vex_statement, vex_source, vex_at
		FROM findings WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), findingID.String()).Scan(&meta, &scores, &vids, &extra, &loc,
		&vexStatus, &vexJust, &vexStmt, &vexSrc, &vexAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get finding interop data: %w", err)
	}
	var d vulnerability.InteropData
	if len(meta) > 0 {
		var m vulnerability.InteropSourceMeta
		if json.Unmarshal(meta, &m) == nil {
			d.Native, d.Lifecycle, d.Solution = m.Native, m.Lifecycle, m.Solution
		}
	}
	if len(scores) > 0 {
		_ = json.Unmarshal(scores, &d.Scores)
	}
	if len(vids) > 0 {
		_ = json.Unmarshal(vids, &d.VulnerabilityIDs)
	}
	if len(extra) > 0 {
		_ = json.Unmarshal(extra, &d.SourceExtra)
	}
	d.LocationKey = loc.String
	if vexStatus.Valid {
		d.VEX = &vulnerability.InteropVEX{
			Status: vexStatus.String, Justification: vexJust.String,
			Statement: vexStmt.String, Source: vexSrc.String,
		}
		if vexAt.Valid {
			t := vexAt.Time.UTC()
			d.VEX.AsOf = &t
		}
	}
	// Stored rows were sanitized on write; sanitizing on read keeps a row
	// written by any other path within the same bounds.
	d = vulnerability.SanitizeInteropData(d)
	if d.IsEmpty() {
		return nil, nil //nolint:nilnil // no interop data recorded
	}
	return &d, nil
}

// ApplyVEXNotAffected closes the tenant's open findings that a VEX
// not_affected statement covers, or with dryRun only returns the ones it
// would close. A finding qualifies only when it is the tenant's, on the
// stated asset, under the stated key, open, and not from a human source
// (pentest, manual, bug bounty, red team). It becomes false_positive with
// resolution_method 'vex_not_affected' and the statement's reason as its
// resolution. Returns the ids closed (or that would be).
func (r *FindingRepository) ApplyVEXNotAffected(ctx context.Context, tenantID shared.ID,
	items []vulnerability.VEXNotAffected, dryRun bool) ([]shared.ID, error) {
	if len(items) == 0 {
		return nil, nil
	}
	fps := make([]string, len(items))
	assets := make([]string, len(items))
	reasons := make([]string, len(items))
	for i, it := range items {
		fps[i] = it.Fingerprint
		assets[i] = it.AssetID
		reasons[i] = it.Resolution
	}
	match := `
		WITH m AS (
			SELECT * FROM unnest($2::text[], $3::uuid[], $4::text[]) AS m(fingerprint, asset_id, reason)
		)
		SELECT f.id, m.reason
		FROM findings f
		JOIN m ON m.fingerprint = f.fingerprint AND m.asset_id = f.asset_id
		WHERE f.tenant_id = $1
			AND f.status IN ` + coverageOpenStatuses + `
			AND f.source NOT IN ` + coverageProtectedSources
	query := `SELECT id::text FROM (` + match + `) x`
	if !dryRun {
		query = `
		UPDATE findings f
		SET status = 'false_positive',
			resolution = x.reason,
			resolution_method = 'vex_not_affected',
			resolved_at = NOW(),
			updated_at = NOW()
		FROM (` + match + `) x
		WHERE f.tenant_id = $1 AND f.id = x.id
			AND f.status IN ` + coverageOpenStatuses + `
		RETURNING f.id::text`
	}
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(fps), pq.Array(assets), pq.Array(reasons))
	if err != nil {
		return nil, fmt.Errorf("apply vex not_affected: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("scan vex finding id: %w", err)
		}
		if id, err := shared.IDFromString(idStr); err == nil {
			out = append(out, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate vex findings: %w", err)
	}
	return out, nil
}
