package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

// Asset merge: every row that points at a merged asset is moved to the kept
// asset before the merged assets are deleted. Anything left behind is lost to
// ON DELETE CASCADE or orphaned by ON DELETE SET NULL.
//
// The tables below are the complete list. TestAssetMergeCoversEveryAssetReference
// compares it with every foreign key to assets (and every *asset_id column
// without one) in the migrated schema, so a new table cannot silently lose
// data in a merge again: it fails until the table is added here.

// mergeKey is one UNIQUE key of a table, excluding the asset column. nullSafe
// columns compare with IS NOT DISTINCT FROM, for indexes built over
// COALESCE(col, ...); the others compare with =, which matches a plain UNIQUE
// index (NULLs distinct) and a partial index WHERE col IS NOT NULL.
type mergeKey struct {
	cols     []string
	nullSafe []string
}

// mergeRef is one column that references assets.id.
type mergeRef struct {
	table  string
	column string
	// tenantCol scopes every statement; "" when the table has none (the asset
	// ids themselves were checked against the tenant first).
	tenantCol string
	// idCol orders rows to pick a survivor among duplicates: "id" or "ctid".
	idCol string
	// keys are the UNIQUE keys that include the asset column. Empty: a plain
	// UPDATE cannot conflict. One empty mergeKey: at most one row per asset
	// (the asset column is the whole key).
	keys []mergeKey
}

var assetMergeRefs = []mergeRef{
	// No UNIQUE key on the asset column: plain move.
	{table: "findings", column: "asset_id", tenantCol: "tenant_id"},
	{table: "exposures", column: "asset_id", tenantCol: "tenant_id"},
	{table: "suppression_rules", column: "asset_id", tenantCol: "tenant_id"},
	{table: "sla_policies", column: "asset_id", tenantCol: "tenant_id"},
	{table: "scan_sessions", column: "asset_id", tenantCol: "tenant_id"},
	{table: "pipeline_runs", column: "asset_id", tenantCol: "tenant_id"},
	{table: "exposure_events", column: "asset_id", tenantCol: "tenant_id"},
	{table: "runtime_telemetry_events", column: "endpoint_asset_id", tenantCol: "tenant_id"},
	{table: "attack_path_nodes", column: "asset_id"},
	{table: "threat_model_threats", column: "entry_point_asset_id", tenantCol: "tenant_id"},
	{table: "threat_model_threats", column: "hop_asset_id", tenantCol: "tenant_id"},
	{table: "threat_model_threats", column: "target_asset_id", tenantCol: "tenant_id"},
	// A retest's asset follows its finding (RFC-039): the per-asset in-flight
	// cap counts by asset_id.
	{table: "finding_retests", column: "asset_id", tenantCol: "tenant_id"},
	// CI runs and break-glass overrides (RFC-051) follow their repository.
	{table: "ci_runs", column: "repository_asset_id", tenantCol: "tenant_id"},
	{table: "ci_gate_overrides", column: "repository_asset_id", tenantCol: "tenant_id"},

	// UNIQUE keys: drop the merged row when the kept asset already has the key.
	{table: "asset_services", column: "asset_id", tenantCol: "tenant_id", idCol: "id",
		keys: []mergeKey{{cols: []string{"port", "protocol"}}}},
	{table: "asset_components", column: "asset_id", tenantCol: "tenant_id", idCol: "id",
		keys: []mergeKey{
			{cols: []string{"component_id", "path"}},
			{cols: []string{"name", "version"}, nullSafe: []string{"branch_id"}},
		}},
	{table: "business_unit_assets", column: "asset_id", tenantCol: "tenant_id", idCol: "id",
		keys: []mergeKey{{cols: []string{"business_unit_id"}}}},
	{table: "asset_group_members", column: "asset_id", idCol: "ctid",
		keys: []mergeKey{{cols: []string{"asset_group_id"}}}},
	{table: "asset_owners", column: "asset_id", idCol: "id",
		keys: []mergeKey{{cols: []string{"user_id"}}, {cols: []string{"group_id"}}}},
	{table: "user_accessible_assets", column: "asset_id", tenantCol: "tenant_id", idCol: "ctid",
		keys: []mergeKey{{cols: []string{"user_id"}}}},
	// Explicit data-scope grants follow the asset: whoever could see a merged
	// asset by a grant sees the kept one.
	{table: "asset_access_grants", column: "asset_id", tenantCol: "tenant_id", idCol: "id",
		keys: []mergeKey{{cols: []string{"user_id"}}}},
	{table: "asset_sources", column: "asset_id", idCol: "id",
		keys: []mergeKey{{cols: []string{"source_type", "source_id"}}}},
	{table: "business_service_assets", column: "asset_id", tenantCol: "tenant_id", idCol: "id",
		keys: []mergeKey{{cols: []string{"service_id", "dependency_type"}}}},
	{table: "compensating_control_assets", column: "asset_id", idCol: "ctid",
		keys: []mergeKey{{cols: []string{"control_id"}}}},
	{table: "scan_coverage_state", column: "asset_id", tenantCol: "tenant_id", idCol: "ctid",
		keys: []mergeKey{{}}},
	// The kept asset takes the merged assets' identifiers, so later reports
	// carrying them land on it. A strong identifier is unique per tenant and
	// so is never on both.
	{table: "asset_identifiers", column: "asset_id", tenantCol: "tenant_id", idCol: "id",
		keys: []mergeKey{{cols: []string{"kind", "value"}}}},
	// Attribution evidence (RFC-036): the kept asset takes every reason the
	// merged ones had; the same (rule, source) on both is one piece of
	// evidence, and the kept row keeps the earliest first sighting.
	{table: "easm_evidence", column: "asset_id", tenantCol: "tenant_id", idCol: "id",
		keys: []mergeKey{{cols: []string{"rule", "source"}}}},
	// DNS-check rotation state (RFC-036): the kept asset's own state wins;
	// a merged asset's state for a check the kept one never ran moves.
	{table: "easm_dns_check_state", column: "asset_id", tenantCol: "tenant_id", idCol: "ctid",
		keys: []mergeKey{{cols: []string{"check_kind"}}}},
	// Scan stage chaining (research/27 P0-3): what a step produced follows
	// the asset (one row per step run and asset), and a run's target
	// provenance names the kept asset.
	{table: "scan_step_outputs", column: "asset_id", tenantCol: "tenant_id", idCol: "ctid",
		keys: []mergeKey{{cols: []string{"step_run_id"}}}},
	{table: "scan_run_targets", column: "asset_id", tenantCol: "tenant_id"},
	{table: "scan_run_targets", column: "parent_asset_id", tenantCol: "tenant_id"},
}

// assetMergeEdgeRefs are directed edges between two assets. An edge between
// the kept asset and a merged one (or two merged ones) would become a loop,
// so it is dropped before the endpoints are moved.
var assetMergeEdgeRefs = []string{"asset_relationships", "relationship_suggestions"}

// assetMergeSpecialRefs are handled by dedicated code in mergeAssetReferences.
var assetMergeSpecialRefs = map[string]string{
	"assets.parent_id":                         "children move to the kept asset",
	"asset_repositories.asset_id":              "copied to the kept asset when it has none; branches move",
	"asset_relationships.source_asset_id":      "edge",
	"asset_relationships.target_asset_id":      "edge",
	"relationship_suggestions.source_asset_id": "edge",
	"relationship_suggestions.target_asset_id": "edge",
	"pentest_campaigns.asset_ids":              "array: merged ids replaced by the kept id",
	"asset_dedup_review.keep_asset_id":         "other pending reviews about a merged asset are dropped",
	"asset_dedup_review.merge_asset_ids":       "other pending reviews about a merged asset are dropped",
	"asset_attributions.asset_id":              "the kept asset keeps the most recent human decision of any merged asset; automatic records of merged assets are dropped (the moved evidence re-derives them)",
}

// assetMergeLeftAlone are references a merge deliberately does not move.
var assetMergeLeftAlone = map[string]string{
	"asset_state_history.asset_id":        "immutable audit log (UPDATE is blocked by a trigger); removed with the merged asset",
	"asset_merge_log.kept_asset_id":       "the merge record itself",
	"asset_merge_log.merged_asset_id":     "the merge record itself",
	"ctem_cycle_scope_snapshots.asset_id": "historical snapshot of a closed scope",
	"ingest_reports.touched_asset_ids":    "historical record of one report",
	// The type normalisation ledger (migration 000684) describes the row as
	// that migration moved it; its down migration restores only rows still
	// holding that pair, so a merged asset's entry goes with it.
	"asset_type_reclassifications.asset_id": "ledger of one migration; removed with the merged asset",
}

// mergeAssetReferences moves everything that references mergeIDs onto keepID.
// It runs inside the merge transaction, before the merged assets are deleted.
func mergeAssetReferences(ctx context.Context, tx *sql.Tx, tenantID, reviewID, keepID string, mergeIDs []string) error {
	if err := checkMergeTenant(ctx, tx, tenantID, keepID, mergeIDs); err != nil {
		return err
	}
	// Findings first, while they still sit on the merged assets: re-key them for
	// the kept asset and fold duplicates into one survivor (never a delete).
	if err := rekeyMergedFindings(ctx, tx, tenantID, keepID, mergeIDs); err != nil {
		return err
	}
	// Branches first: their components and findings are moved below by asset.
	if err := mergeRepositoryExtension(ctx, tx, tenantID, keepID, mergeIDs); err != nil {
		return err
	}
	if err := mergeAttribution(ctx, tx, tenantID, keepID, mergeIDs); err != nil {
		return err
	}
	// Exposure events embed the asset id in their fingerprint: re-key them for
	// the kept asset before they move, folding duplicates into one event.
	if err := rekeyMergedExposures(ctx, tx, tenantID, keepID, mergeIDs); err != nil {
		return err
	}
	for _, ref := range assetMergeRefs {
		if err := repointRef(ctx, tx, ref, keepID, mergeIDs, tenantID); err != nil {
			return err
		}
	}
	for _, table := range assetMergeEdgeRefs {
		if err := repointEdges(ctx, tx, table, keepID, mergeIDs, tenantID); err != nil {
			return err
		}
	}
	return repointNonFKRefs(ctx, tx, tenantID, reviewID, keepID, mergeIDs)
}

// checkMergeTenant refuses a merge whose assets are not all in the tenant.
// Tables without a tenant column are scoped by these ids alone.
func checkMergeTenant(ctx context.Context, tx *sql.Tx, tenantID, keepID string, mergeIDs []string) error {
	all := append([]string{keepID}, mergeIDs...)
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM assets WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL`,
		tenantID, pq.Array(all)).Scan(&n); err != nil {
		return fmt.Errorf("check merge assets: %w", err)
	}
	if n != len(uniqueStrings(all)) {
		return fmt.Errorf("merge assets are missing or not in this tenant (%d of %d found)", n, len(all))
	}
	return nil
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func repointRef(ctx context.Context, tx *sql.Tx, ref mergeRef, keepID string, mergeIDs []string, tenantID string) error {
	for _, k := range ref.keys {
		if err := dropConflicts(ctx, tx, ref, k, keepID, mergeIDs, tenantID); err != nil {
			return err
		}
	}
	args := []any{keepID, pq.Array(mergeIDs)}
	scope := ""
	if ref.tenantCol != "" {
		scope = fmt.Sprintf(" AND %s = $3", ref.tenantCol)
		args = append(args, tenantID)
	}
	//nolint:gosec // G201: identifiers come from the fixed assetMergeRefs list, never user input.
	q := fmt.Sprintf(`UPDATE %[1]s SET %[2]s = $1 WHERE %[2]s = ANY($2)%[3]s`, ref.table, ref.column, scope)
	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("move %s.%s: %w", ref.table, ref.column, err)
	}
	return nil
}

// keyMatch is the SQL predicate "rows a and b have the same key".
func keyMatch(k mergeKey, a, b string) string {
	parts := make([]string, 0, len(k.cols)+len(k.nullSafe)+1)
	for _, c := range k.cols {
		parts = append(parts, fmt.Sprintf("%s.%s = %s.%s", a, c, b, c))
	}
	for _, c := range k.nullSafe {
		parts = append(parts, fmt.Sprintf("%s.%s IS NOT DISTINCT FROM %s.%s", a, c, b, c))
	}
	if len(parts) == 0 {
		return "TRUE"
	}
	return strings.Join(parts, " AND ")
}

// dropConflicts deletes the merged rows that would collide on key k once
// moved: those whose key the kept asset already has, then all but the lowest
// idCol among merged rows sharing a key. The kept asset's row wins.
func dropConflicts(ctx context.Context, tx *sql.Tx, ref mergeRef, k mergeKey, keepID string, mergeIDs []string, tenantID string) error {
	merge := pq.Array(mergeIDs)
	var mT, kT string
	args := []any{keepID, merge}
	if ref.tenantCol != "" {
		mT = fmt.Sprintf(" AND m.%s = $3", ref.tenantCol)
		kT = fmt.Sprintf(" AND k.%s = $3", ref.tenantCol)
		args = append(args, tenantID)
	}
	//nolint:gosec // G201: identifiers come from the fixed assetMergeRefs list, never user input.
	q1 := fmt.Sprintf(`DELETE FROM %[1]s m WHERE m.%[2]s = ANY($2)%[3]s
		AND EXISTS (SELECT 1 FROM %[1]s k WHERE k.%[2]s = $1%[4]s AND %[5]s)`,
		ref.table, ref.column, mT, kT, keyMatch(k, "k", "m"))
	if _, err := tx.ExecContext(ctx, q1, args...); err != nil {
		return fmt.Errorf("dedup %s vs kept asset: %w", ref.table, err)
	}

	var mT2, bT string
	args2 := []any{merge}
	if ref.tenantCol != "" {
		mT2 = fmt.Sprintf(" AND m.%s = $2", ref.tenantCol)
		bT = fmt.Sprintf(" AND b.%s = $2", ref.tenantCol)
		args2 = append(args2, tenantID)
	}
	//nolint:gosec // G201: identifiers come from the fixed assetMergeRefs list, never user input.
	q2 := fmt.Sprintf(`DELETE FROM %[1]s m WHERE m.%[2]s = ANY($1)%[3]s
		AND EXISTS (SELECT 1 FROM %[1]s b WHERE b.%[2]s = ANY($1)%[5]s AND %[4]s AND b.%[6]s < m.%[6]s)`,
		ref.table, ref.column, mT2, keyMatch(k, "b", "m"), bT, ref.idCol)
	if _, err := tx.ExecContext(ctx, q2, args2...); err != nil {
		return fmt.Errorf("dedup %s among merged assets: %w", ref.table, err)
	}
	return nil
}

// repointEdges moves directed edges (UNIQUE tenant, source, target, type).
func repointEdges(ctx context.Context, tx *sql.Tx, table, keepID string, mergeIDs []string, tenantID string) error {
	//nolint:gosec // G201: table comes from the fixed assetMergeEdgeRefs list.
	loops := fmt.Sprintf(`DELETE FROM %s WHERE tenant_id = $3 AND (
		(source_asset_id = ANY($2) AND target_asset_id = $1) OR
		(source_asset_id = $1 AND target_asset_id = ANY($2)) OR
		(source_asset_id = ANY($2) AND target_asset_id = ANY($2)))`, table)
	if _, err := tx.ExecContext(ctx, loops, keepID, pq.Array(mergeIDs), tenantID); err != nil {
		return fmt.Errorf("drop %s loops: %w", table, err)
	}
	for _, end := range []struct{ column, other string }{
		{"source_asset_id", "target_asset_id"},
		{"target_asset_id", "source_asset_id"},
	} {
		ref := mergeRef{table: table, column: end.column, tenantCol: "tenant_id", idCol: "id",
			keys: []mergeKey{{cols: []string{end.other, "relationship_type"}}}}
		if err := repointRef(ctx, tx, ref, keepID, mergeIDs, tenantID); err != nil {
			return err
		}
	}
	return nil
}

// mergeRepositoryExtension keeps the repository data of merged repository
// assets. asset_repositories is keyed by asset_id and referenced by
// repository_branches without ON UPDATE CASCADE, so the row cannot be moved:
// the kept asset gets a copy when it has none, branches are moved to it, and
// a branch whose name the kept repository already has hands its findings,
// branch occurrences and components to that branch first.
func mergeRepositoryExtension(ctx context.Context, tx *sql.Tx, tenantID, keepID string, mergeIDs []string) error {
	merge := pq.Array(mergeIDs)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO asset_repositories
		SELECT (jsonb_populate_record(NULL::asset_repositories, to_jsonb(r) || jsonb_build_object('asset_id', $1::uuid))).*
		FROM asset_repositories r
		WHERE r.asset_id = ANY($2)
		  AND NOT EXISTS (SELECT 1 FROM asset_repositories k WHERE k.asset_id = $1)
		ORDER BY r.asset_id
		LIMIT 1`, keepID, merge); err != nil {
		return fmt.Errorf("copy repository extension: %w", err)
	}

	// Same-name branches: move what hangs off the merged branch, then drop it.
	pairs, err := collidingBranches(ctx, tx, keepID, merge)
	if err != nil {
		return err
	}

	branchRefs := []mergeRef{
		{table: "findings", column: "branch_id", tenantCol: "tenant_id"},
		{table: "finding_branch_occurrences", column: "branch_id", tenantCol: "tenant_id", idCol: "id",
			keys: []mergeKey{{cols: []string{"finding_id"}}}},
		{table: "asset_components", column: "branch_id", tenantCol: "tenant_id", idCol: "id",
			keys: []mergeKey{{cols: []string{"asset_id", "name", "version"}}}},
	}
	for _, p := range pairs {
		for _, ref := range branchRefs {
			if err := repointRef(ctx, tx, ref, p.to, []string{p.from}, tenantID); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM repository_branches WHERE id = $1`, p.from); err != nil {
			return fmt.Errorf("drop merged branch: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE repository_branches SET repository_id = $1 WHERE repository_id = ANY($2)`,
		keepID, merge); err != nil {
		// No asset_repositories row for the kept asset means no merged asset
		// had one either, so there is nothing to move.
		return fmt.Errorf("move branches: %w", err)
	}
	return nil
}

type branchPair struct{ from, to string }

// collidingBranches pairs each merged-repository branch with the kept
// repository's branch of the same name.
func collidingBranches(ctx context.Context, tx *sql.Tx, keepID string, merge any) ([]branchPair, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT m.id, k.id FROM repository_branches m
		JOIN repository_branches k ON k.repository_id = $1 AND k.name = m.name
		WHERE m.repository_id = ANY($2)`, keepID, merge)
	if err != nil {
		return nil, fmt.Errorf("list colliding branches: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var pairs []branchPair
	for rows.Next() {
		var p branchPair
		if err := rows.Scan(&p.from, &p.to); err != nil {
			return nil, fmt.Errorf("scan branch pair: %w", err)
		}
		pairs = append(pairs, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate branch pairs: %w", err)
	}
	return pairs, nil
}

// repointNonFKRefs moves references that are not foreign keys: child assets,
// asset-id arrays, and other pending dedup reviews.
func repointNonFKRefs(ctx context.Context, tx *sql.Tx, tenantID, reviewID, keepID string, mergeIDs []string) error {
	merge := pq.Array(mergeIDs)
	stmts := []struct{ what, q string }{
		// A merged asset that was the kept asset's parent leaves it parentless
		// rather than its own parent.
		{"kept asset parent", `UPDATE assets SET parent_id = NULL
			WHERE id = $1 AND tenant_id = $3 AND parent_id = ANY($2)`},
		{"child assets", `UPDATE assets SET parent_id = $1
			WHERE tenant_id = $3 AND parent_id = ANY($2) AND id <> $1 AND NOT (id = ANY($2))`},
		{"pentest campaign assets", `UPDATE pentest_campaigns SET asset_ids = ARRAY(
				SELECT DISTINCT CASE WHEN a = ANY($2) THEN $1::uuid ELSE a END FROM unnest(asset_ids) AS a)
			WHERE tenant_id = $3 AND asset_ids && $2::uuid[]`},
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s.q, keepID, merge, tenantID); err != nil {
			return fmt.Errorf("move %s: %w", s.what, err)
		}
	}
	// Other pending reviews about a merged asset were computed from assets
	// that no longer exist. Ingest proposes them again if the duplicates are
	// still there; approving a stale one would merge the wrong set.
	if _, err := tx.ExecContext(ctx, `DELETE FROM asset_dedup_review
		WHERE tenant_id = $2 AND status = 'pending' AND id <> $3
		  AND (keep_asset_id = ANY($1) OR merge_asset_ids && $1::uuid[])`,
		merge, tenantID, reviewID); err != nil {
		return fmt.Errorf("drop stale pending reviews: %w", err)
	}
	return nil
}

// mergeAttribution settles the attribution record (one per asset) before the
// merged assets are deleted, which would cascade their records away:
//
//   - a person's decision is never lost to a merge: of all human decisions
//     on the kept and merged assets, the most recent one ends up on the kept
//     asset (older ones remain in the audit log);
//   - without any human decision, the kept asset keeps its own record (or
//     none: a legacy asset counts as confirmed and must not be demoted by a
//     merged asset's needs_review), and merged assets' automatic records are
//     dropped — their evidence moves to the kept asset, and the next
//     collector run re-derives the state from it.
//
// It also folds the earliest first sighting of duplicate evidence into the
// kept asset's row before repointRef drops the duplicate.
func mergeAttribution(ctx context.Context, tx *sql.Tx, tenantID, keepID string, mergeIDs []string) error {
	merge := pq.Array(mergeIDs)
	var winner sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT asset_id FROM asset_attributions
		WHERE tenant_id = $3 AND decided_at IS NOT NULL AND (asset_id = $1 OR asset_id = ANY($2))
		ORDER BY decided_at DESC, (asset_id = $1) DESC
		LIMIT 1`, keepID, merge, tenantID).Scan(&winner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("pick attribution decision: %w", err)
	}
	if winner.Valid && winner.String != keepID {
		if _, err := tx.ExecContext(ctx, `DELETE FROM asset_attributions WHERE asset_id = $1 AND tenant_id = $2`,
			keepID, tenantID); err != nil {
			return fmt.Errorf("replace kept attribution: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE asset_attributions SET asset_id = $1, updated_at = now()
			WHERE asset_id = $2 AND tenant_id = $3`, keepID, winner.String, tenantID); err != nil {
			return fmt.Errorf("move attribution decision: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM asset_attributions WHERE tenant_id = $2 AND asset_id = ANY($1)`,
		merge, tenantID); err != nil {
		return fmt.Errorf("drop merged attribution: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE easm_evidence k SET
			first_observed_at = LEAST(k.first_observed_at, m.first_seen),
			last_observed_at  = GREATEST(k.last_observed_at, m.last_seen)
		FROM (SELECT rule, source, min(first_observed_at) AS first_seen, max(last_observed_at) AS last_seen
		      FROM easm_evidence WHERE tenant_id = $3 AND asset_id = ANY($2) GROUP BY rule, source) m
		WHERE k.asset_id = $1 AND k.tenant_id = $3 AND k.rule = m.rule AND k.source = m.source`,
		keepID, merge, tenantID); err != nil {
		return fmt.Errorf("fold duplicate evidence: %w", err)
	}
	return nil
}

// AssetMergeReferenceHandling returns "table.column" -> how a merge treats
// it, for every asset reference the merge knows about. The schema-coverage
// test compares it with the migrated schema.
func AssetMergeReferenceHandling() map[string]string {
	out := make(map[string]string, len(assetMergeRefs)+len(assetMergeSpecialRefs)+len(assetMergeLeftAlone))
	for _, r := range assetMergeRefs {
		if len(r.keys) == 0 {
			out[r.table+"."+r.column] = "moved"
		} else {
			out[r.table+"."+r.column] = "moved; rows whose unique key the kept asset already has are dropped"
		}
	}
	for k, v := range assetMergeSpecialRefs {
		out[k] = v
	}
	for k, v := range assetMergeLeftAlone {
		out[k] = "left alone: " + v
	}
	return out
}
