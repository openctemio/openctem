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
// requestNotAffected (a not_affected statement under INGEST_VEX=enforce, from
// an uploader allowed to approve false positives), each of them that is open
// and not from a human source (pentest, manual, bug bounty, red team) also
// gets a pending false-positive request by the actor "vex" with the
// statement's justification, and an approval_requested timeline entry: a false
// positive needs a second person, so the document never sets the status
// itself. A finding that already has a pending request, or whose earlier VEX
// request a person rejected or canceled, gets none. Returns the ids it stored
// the statement on and the ids it requested a false positive for.
func (r *FindingRepository) ApplyVEXDocument(ctx context.Context, tenantID shared.ID, ids []shared.ID,
	v vulnerability.InteropVEX, requestNotAffected bool, reason string) (stored, requested []shared.ID, err error) {
	if len(ids) == 0 {
		return nil, nil, nil
	}
	sv := vulnerability.SanitizeInteropData(vulnerability.InteropData{VEX: &v}).VEX
	if sv == nil {
		return nil, nil, fmt.Errorf("apply vex document: invalid statement")
	}
	requestNotAffected = requestNotAffected && sv.Status == vulnerability.VEXStatusNotAffected
	at := time.Now().UTC()
	if sv.AsOf != nil {
		at = sv.AsOf.UTC()
	}
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}
	err = r.db.withFindingTransition(ctx, findingTransition{
		Source: "vex", Reason: "vex_not_affected", ActorType: "integration", ActorName: "system: VEX document",
		Message: "An uploaded VEX document says the component is not affected",
	}, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			UPDATE findings SET
				vex_status        = $3,
				vex_justification = $4,
				vex_statement     = $5,
				vex_source        = $6,
				vex_at            = $7,
				updated_at        = NOW()
			WHERE tenant_id = $1 AND id = ANY($2::uuid[])
			RETURNING id::text`,
			tenantID.String(), pq.Array(idStrs), sv.Status, nullString(sv.Justification), nullString(sv.Statement),
			nullString(sv.Source), at)
		if err != nil {
			return fmt.Errorf("apply vex document: %w", err)
		}
		stored, err = scanIDs(rows)
		if err != nil {
			return err
		}
		if !requestNotAffected || len(stored) == 0 {
			return nil
		}
		storedStrs := make([]string, len(stored))
		for i, id := range stored {
			storedStrs[i] = id.String()
		}
		requested, err = insertVEXFalsePositiveRequests(ctx, tx, tenantID, storedStrs, reason,
			string(vulnerability.ClosureReasonFromVEXJustification(sv.Justification)),
			"system: VEX document", "An uploaded VEX document says the component is not affected; a person decides")
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return stored, requested, nil
}

// insertVEXFalsePositiveRequests opens the pending false positive request by
// the actor "vex" for each of the tenant's findings ids that is open work and
// not from a human source, with an approval_requested timeline entry (actorName
// and message). A finding that already has a pending request, or whose earlier
// VEX request a person rejected or canceled, gets none. A false positive needs
// a second person, so no VEX path (document or statement) sets the status
// itself. Returns the ids a request was opened for.
func insertVEXFalsePositiveRequests(ctx context.Context, tx *sql.Tx, tenantID shared.ID, ids []string,
	justification, closureReason, actorName, message string) ([]shared.ID, error) {
	//nolint:gosec // G202: fixed SQL fragments (lifecycle lists) and numbered placeholders only
	rows, err := tx.QueryContext(ctx, `
		WITH ins AS (
			INSERT INTO finding_status_approvals (tenant_id, finding_id, requested_status, requested_by_actor, justification, status, closure_reason, decide_by)
			SELECT $1::uuid, f.id, 'false_positive', '`+vulnerability.ApprovalActorVEX+`', LEFT($3, 1000), 'pending', $4,
			       NOW() + INTERVAL '14 days' -- vulnerability.DefaultDecisionWindow
			FROM findings f
			WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[])
			  AND f.status IN `+vexFalsePositiveFromSQL+` AND f.source NOT IN `+coverageProtectedSources+`
			  AND NOT EXISTS (
				SELECT 1 FROM finding_status_approvals p
				WHERE p.tenant_id = $1::uuid AND p.finding_id = f.id
				  AND (p.status = 'pending' OR (p.requested_by_actor = '`+vulnerability.ApprovalActorVEX+`' AND p.status IN ('rejected', 'canceled'))))
			ON CONFLICT DO NOTHING
			RETURNING id, finding_id
		), timeline AS (
			INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
			SELECT $1::uuid, i.finding_id, 'approval_requested', 'integration', $5,
			       jsonb_build_object('requested_status', 'false_positive', 'requested_by', '`+vulnerability.ApprovalActorVEX+`', 'approval_id', i.id),
			       'auto', $6
			FROM ins i
		)
		SELECT finding_id::text FROM ins`,
		tenantID.String(), pq.Array(ids), justification, closureReason, actorName, message)
	if err != nil {
		return nil, fmt.Errorf("request vex false positive: %w", err)
	}
	return scanIDs(rows)
}
