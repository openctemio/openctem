package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// VEX documents imported by a person (findingimport). Every statement is
// scoped by tenant_id first; the caller filters the candidates by the
// uploader's data scope before anything is written.

// purlBaseSQL is the version-less, lower-case base of software_versions.purl, the
// same rule as vulnerability.SplitPURL.
const purlBaseSQL = `lower(rtrim(regexp_replace(split_part(split_part(c.purl, '#', 1), '?', 1), '@[^@/]*$', ''), '/'))`

// purlVersionSQL is the version of software_versions.purl (” when it has none).
const purlVersionSQL = `COALESCE(substring(split_part(split_part(c.purl, '#', 1), '?', 1) from '@([^@/]*)$'), '')`

// MatchVEXDocument returns the tenant's findings a VEX statement covers (see
// vulnerability.VEXDocumentQuery), at most limit of them.
func (r *FindingRepository) MatchVEXDocument(ctx context.Context, tenantID shared.ID,
	q vulnerability.VEXDocumentQuery, limit int) ([]vulnerability.VEXCandidate, error) {
	if len(q.IDs) == 0 || len(q.Products) == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > vulnerability.MaxVEXMatchFindings {
		limit = vulnerability.MaxVEXMatchFindings
	}
	bases := make([]string, len(q.Products))
	versions := make([]string, len(q.Products))
	for i, p := range q.Products {
		bases[i], versions[i] = p.Base, p.Version
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id::text, f.asset_id::text, f.status, f.source
		FROM findings f
		JOIN software_versions c ON c.id = f.component_id
		WHERE f.tenant_id = $1
			AND (
				upper(f.cve_id) = ANY($2::text[])
				OR f.cve_ids && $2::text[]
				OR upper(f.rule_id) = ANY($2::text[])
				OR (f.vulnerability_ids IS NOT NULL AND EXISTS (
					SELECT 1 FROM jsonb_array_elements(f.vulnerability_ids) e
					WHERE upper(e->>'id') = ANY($2::text[])))
			)
			AND EXISTS (
				SELECT 1 FROM unnest($3::text[], $4::text[]) AS p(base, version)
				WHERE `+purlBaseSQL+` = p.base
					AND (p.version = '' OR `+purlVersionSQL+` = p.version OR c.raw = p.version)
			)
			AND (cardinality($6::text[]) = 0 OR EXISTS (
				SELECT 1 FROM assets a
				WHERE a.tenant_id = $1 AND a.id = f.asset_id AND lower(a.name) = ANY($6::text[])
			))
		ORDER BY f.id
		LIMIT $5`,
		tenantID.String(), pq.Array(q.IDs), pq.Array(bases), pq.Array(versions), limit, pq.Array(nonNilStrings(q.AssetNames)))
	if err != nil {
		return nil, fmt.Errorf("match vex document: %w", err)
	}
	defer rows.Close()
	var out []vulnerability.VEXCandidate
	for rows.Next() {
		var id, asset, status, source string
		if err := rows.Scan(&id, &asset, &status, &source); err != nil {
			return nil, fmt.Errorf("scan vex candidate: %w", err)
		}
		fid, err1 := shared.IDFromString(id)
		aid, err2 := shared.IDFromString(asset)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, vulnerability.VEXCandidate{ID: fid, AssetID: aid, Status: status, Source: source})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate vex candidates: %w", err)
	}
	return out, nil
}

// ApplyVEXDocument stores a VEX statement on the tenant's findings ids. With
// closeNotAffected (a not_affected statement under INGEST_VEX=enforce, from
// an uploader allowed to approve false positives), each of them that is open
// and not from a human source (pentest, manual, bug bounty, red team) also
// becomes false_positive with resolution_method 'vex_not_affected' and
// resolution reason. Returns the ids it stored the statement on and the ids
// it closed.
func (r *FindingRepository) ApplyVEXDocument(ctx context.Context, tenantID shared.ID, ids []shared.ID,
	v vulnerability.InteropVEX, closeNotAffected bool, reason string) (stored, closed []shared.ID, err error) {
	if len(ids) == 0 {
		return nil, nil, nil
	}
	sv := vulnerability.SanitizeInteropData(vulnerability.InteropData{VEX: &v}).VEX
	if sv == nil {
		return nil, nil, fmt.Errorf("apply vex document: invalid statement")
	}
	closeNotAffected = closeNotAffected && sv.Status == vulnerability.VEXStatusNotAffected
	at := time.Now().UTC()
	if sv.AsOf != nil {
		at = sv.AsOf.UTC()
	}
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		WITH t AS (
			SELECT f.id,
				($8 AND f.status IN `+vexFalsePositiveFromSQL+` AND f.source NOT IN `+coverageProtectedSources+`) AS closable
			FROM findings f
			WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[])
			FOR UPDATE
		)
		UPDATE findings f SET
			vex_status        = $3,
			vex_justification = $4,
			vex_statement     = $5,
			vex_source        = $6,
			vex_at            = $7,
			status            = CASE WHEN t.closable THEN 'false_positive' ELSE f.status END,
			resolution        = CASE WHEN t.closable THEN $9 ELSE f.resolution END,
			resolution_method = CASE WHEN t.closable THEN 'vex_not_affected' ELSE f.resolution_method END,
			resolved_at       = CASE WHEN t.closable THEN NOW() ELSE f.resolved_at END,
			updated_at        = NOW()
		FROM t
		WHERE f.tenant_id = $1 AND f.id = t.id
		RETURNING f.id::text, t.closable`,
		tenantID.String(), pq.Array(idStrs), sv.Status, nullString(sv.Justification), nullString(sv.Statement),
		nullString(sv.Source), at, closeNotAffected, reason)
	if err != nil {
		return nil, nil, fmt.Errorf("apply vex document: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var idStr string
		var wasClosed sql.NullBool
		if err := rows.Scan(&idStr, &wasClosed); err != nil {
			return nil, nil, fmt.Errorf("scan vex document row: %w", err)
		}
		id, perr := shared.IDFromString(idStr)
		if perr != nil {
			continue
		}
		stored = append(stored, id)
		if wasClosed.Bool {
			closed = append(closed, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate vex document rows: %w", err)
	}
	return stored, closed, nil
}
