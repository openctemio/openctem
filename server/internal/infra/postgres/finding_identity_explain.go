package postgres

// Identity explanation of one finding (docs/architecture/deduplication.md,
// "Why a finding is one"): its recipe and field names, the tools that
// reported it and the duplicates merged into it. The finding itself is
// authorized by the caller (GetFindingWithScope); the tombstones are each
// filtered by the caller's data scope here, so a restricted member never
// learns of a merged finding on an asset outside their scope. No key,
// fingerprint or field value is read into the result.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// mergeReasonPattern keeps only cause codes the server writes; anything else
// in the activity's changes is not returned.
var mergeReasonPattern = regexp.MustCompile(`^[a-z_]{1,32}$`)

// ExplainIdentity returns the identity explanation of a finding of the
// tenant. scope is the caller's data scope (nil: an internal call, not
// narrowed); it filters the merged duplicates and their tools.
func (r *FindingRepository) ExplainIdentity(ctx context.Context, tenantID, findingID shared.ID, scope *shared.DataScope) (*vulnerability.IdentityExplanation, error) {
	var (
		algo     sql.NullString
		fields   pq.StringArray
		version  int
		rawKey   []byte
		toolName string
		lastSeen sql.NullTime
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT identity_algo, identity_fields, fingerprint_version, identity_key,
		       COALESCE(tool_name, ''), last_seen_at
		FROM findings
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), findingID.String()).
		Scan(&algo, &fields, &version, &rawKey, &toolName, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read finding identity: %w", err)
	}
	out := vulnerability.IdentityRecipe(algo.String, fields, version, rawKey)

	scopeCond, scopeArgs := "TRUE", []any(nil)
	if scope != nil {
		scopeCond, scopeArgs = filterspec.AssigneeScopeSQL("t.asset_id", "t.assigned_to", scope, 3)
	}
	args := append([]any{tenantID.String(), findingID.String()}, scopeArgs...)

	out.Merged, err = r.mergedDuplicates(ctx, scopeCond, args)
	if err != nil {
		return nil, err
	}
	out.Sources, err = r.identitySources(ctx, scopeCond, args)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// mergedDuplicates lists the in-scope tombstones of the finding ($2), newest
// merge first, with the cause recorded on the tombstone's duplicate_marked
// activity.
func (r *FindingRepository) mergedDuplicates(ctx context.Context, scopeCond string, args []any) ([]vulnerability.IdentityMerged, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id, COALESCE(t.tool_name, ''),
		       COALESCE(a.created_at, t.resolved_at, t.updated_at) AS merged_at,
		       COALESCE(a.reason, '')
		FROM findings t
		LEFT JOIN LATERAL (
			SELECT fa.created_at, fa.changes->>'reason' AS reason
			FROM finding_activities fa
			WHERE fa.tenant_id = t.tenant_id AND fa.finding_id = t.id
			  AND fa.activity_type = 'duplicate_marked'
			ORDER BY fa.created_at DESC
			LIMIT 1
		) a ON TRUE
		WHERE t.tenant_id = $1 AND t.duplicate_of = $2 AND t.status = 'duplicate'
		  AND `+scopeCond+`
		ORDER BY merged_at DESC, t.id
		LIMIT `+itoa(vulnerability.MaxIdentityMerged), args...)
	if err != nil {
		return nil, fmt.Errorf("list merged duplicates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []vulnerability.IdentityMerged{}
	for rows.Next() {
		var (
			id, tool, reason string
			at               time.Time
		)
		if err := rows.Scan(&id, &tool, &at, &reason); err != nil {
			return nil, fmt.Errorf("scan merged duplicate: %w", err)
		}
		pid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		if !mergeReasonPattern.MatchString(reason) {
			reason = ""
		}
		out = append(out, vulnerability.IdentityMerged{ID: pid, ToolName: tool, MergedAt: at, Reason: reason})
	}
	return out, rows.Err()
}

// identitySources is the union of the finding's own tool, the tools of the
// ingest receipts that touched it and the tools of its in-scope tombstones,
// each with its latest sighting, most recent first.
func (r *FindingRepository) identitySources(ctx context.Context, scopeCond string, args []any) ([]vulnerability.IdentitySource, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT tool, MAX(seen) AS seen FROM (
			SELECT f.tool_name AS tool, f.last_seen_at AS seen
			FROM findings f
			WHERE f.tenant_id = $1 AND f.id = $2
			UNION ALL
			SELECT ir.tool_name, fia.created_at
			FROM finding_ingest_actions fia
			JOIN ingest_receipts ir ON ir.id = fia.receipt_id AND ir.tenant_id = fia.tenant_id
			WHERE fia.tenant_id = $1 AND fia.finding_id = $2
			UNION ALL
			SELECT t.tool_name, t.last_seen_at
			FROM findings t
			WHERE t.tenant_id = $1 AND t.duplicate_of = $2 AND t.status = 'duplicate'
			  AND `+scopeCond+`
		) s
		WHERE tool IS NOT NULL AND tool <> ''
		GROUP BY tool
		ORDER BY MAX(seen) DESC NULLS LAST, tool
		LIMIT `+itoa(vulnerability.MaxIdentitySources), args...)
	if err != nil {
		return nil, fmt.Errorf("list identity sources: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []vulnerability.IdentitySource{}
	for rows.Next() {
		var (
			tool string
			seen sql.NullTime
		)
		if err := rows.Scan(&tool, &seen); err != nil {
			return nil, fmt.Errorf("scan identity source: %w", err)
		}
		src := vulnerability.IdentitySource{Tool: tool}
		if seen.Valid {
			t := seen.Time
			src.LastSeenAt = &t
		}
		out = append(out, src)
	}
	return out, rows.Err()
}
