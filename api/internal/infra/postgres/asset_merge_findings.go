package postgres

// Findings in an asset merge (RFC-043 §9, §14).
//
// A finding's fingerprint embeds its asset id, so a finding moved to the kept
// asset must be re-keyed. When the re-keyed fingerprint is already taken — the
// kept asset (or another merged asset) has the same finding — the two are one
// finding. The earliest-created one survives; the other becomes a tombstone
// (status duplicate, duplicate_of = survivor) after its state and every row
// that references it have been carried over. No finding is ever deleted: a
// delete would cascade comments, activities, approvals, evidence, retests and
// more (see findingMergeRefs).
//
// All of it runs inside the merge transaction, before the findings are moved.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// findingMergeRefs are the columns that reference findings.id. A loser's rows
// move to the survivor; rows whose unique key the survivor already has are
// dropped (the survivor's copy wins). TestFindingMergeCoversEveryFindingReference
// compares this list with the schema, so a new table cannot be forgotten.
var findingMergeRefs = []mergeRef{
	{table: "finding_comments", column: "finding_id", tenantCol: "tenant_id"},
	{table: "finding_activities", column: "finding_id", tenantCol: "tenant_id"},
	{table: "finding_status_approvals", column: "finding_id", tenantCol: "tenant_id"},
	{table: "validation_evidence", column: "finding_id", tenantCol: "tenant_id"},
	{table: "pentest_retests", column: "finding_id", tenantCol: "tenant_id"},
	// At most one pending retest per finding (ux_finding_retests_one_pending):
	// settleLoserPendingRetest runs first, so the move cannot collide.
	{table: "finding_retests", column: "finding_id", tenantCol: "tenant_id"},
	{table: "ai_triage_results", column: "finding_id", tenantCol: "tenant_id"},
	// Evidence follows its finding (its secrets hang off the evidence row).
	{table: "finding_evidence", column: "finding_id", tenantCol: "tenant_id"},
	{table: "iocs", column: "source_finding_id", tenantCol: "tenant_id"},
	{table: "ioc_matches", column: "finding_id", tenantCol: "tenant_id"},
	{table: "findings", column: "duplicate_of", tenantCol: "tenant_id"},
	// Every key the loser had (rememberFindingKey adds its current one first)
	// resolves to the survivor from now on. The key is the whole primary key,
	// so a move cannot collide.
	{table: "finding_fingerprints", column: "finding_id", tenantCol: "tenant_id"},

	{table: "finding_suppressions", column: "finding_id", idCol: "id",
		keys: []mergeKey{{cols: []string{"suppression_rule_id"}}}},
	{table: "finding_data_flows", column: "finding_id", idCol: "id",
		keys: []mergeKey{{cols: []string{"flow_index"}}}},
	{table: "finding_group_assignments", column: "finding_id", tenantCol: "tenant_id", idCol: "id",
		keys: []mergeKey{{cols: []string{"group_id"}}}},
	{table: "compliance_finding_mappings", column: "finding_id", tenantCol: "tenant_id", idCol: "id",
		keys: []mergeKey{{cols: []string{"control_id"}}}},
	{table: "compensating_control_findings", column: "finding_id", idCol: "ctid",
		keys: []mergeKey{{cols: []string{"control_id"}}}},
	{table: "finding_branch_occurrences", column: "finding_id", tenantCol: "tenant_id", idCol: "id",
		keys: []mergeKey{{cols: []string{"branch_id"}}}},
	{table: "finding_verification_checklists", column: "finding_id", tenantCol: "tenant_id", idCol: "id",
		keys: []mergeKey{{}}},
	{table: "finding_remediation_keys", column: "finding_id", tenantCol: "tenant_id", idCol: "ctid",
		keys: []mergeKey{{}}},
}

// findingMergeKeptRefs reference findings.id and deliberately stay on the
// tombstone.
var findingMergeKeptRefs = map[string]string{
	// The definitions a finding is linked to describe what that finding
	// reported (RFC-044 §5.7); the survivor keeps its own. The tombstone's
	// findings.definition_id names one of these links, so they cannot move.
	"finding_definitions.finding_id": "kept on the tombstone; the survivor keeps its own definitions",
}

// FindingMergeReferenceHandling returns "table.column" for every reference to
// findings.id and what a finding merge does with it. The schema-coverage test
// compares it with the migrated schema.
func FindingMergeReferenceHandling() map[string]string {
	out := make(map[string]string, len(findingMergeRefs)+len(findingMergeKeptRefs))
	for ref, handling := range findingMergeKeptRefs {
		out[ref] = handling
	}
	for _, r := range findingMergeRefs {
		if len(r.keys) == 0 {
			out[r.table+"."+r.column] = "moved to the survivor"
		} else {
			out[r.table+"."+r.column] = "moved to the survivor; rows whose unique key the survivor already has are dropped"
		}
	}
	return out
}

type mergeFinding struct {
	id, assetID, fingerprint, base string
	ruleID, filePath, message      string
	startLine                      int
	createdAt                      time.Time
	identityKey                    []byte // versioned identity tuple, nil for version 1
}

// rekeyMergedFindings re-keys the findings of the merged assets for the kept
// asset and folds each collision into one survivor. It runs before the
// findings are moved, in the merge transaction.
func rekeyMergedFindings(ctx context.Context, tx *sql.Tx, tenantID, keepID string, mergeIDs []string) error {
	moved, err := listMergedFindings(ctx, tx, tenantID, mergeIDs)
	if err != nil {
		return err
	}
	for _, f := range moved {
		if err := rekeyMergedFinding(ctx, tx, tenantID, keepID, f); err != nil {
			return err
		}
	}
	return nil
}

// listMergedFindings reads (and locks) the live findings of the merged assets,
// oldest first.
func listMergedFindings(ctx context.Context, tx *sql.Tx, tenantID string, mergeIDs []string) ([]mergeFinding, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, asset_id, fingerprint, COALESCE(partial_fingerprints->>$3, ''),
		       COALESCE(rule_id, ''), COALESCE(file_path, ''), COALESCE(message, ''),
		       COALESCE(start_line, 0), created_at, identity_key
		FROM findings
		WHERE tenant_id = $1 AND asset_id = ANY($2) AND status <> 'duplicate'
		ORDER BY created_at, id
		FOR UPDATE`, tenantID, pq.Array(mergeIDs), vulnerability.FingerprintBaseKey)
	if err != nil {
		return nil, fmt.Errorf("list merged findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var moved []mergeFinding
	for rows.Next() {
		var f mergeFinding
		if err := rows.Scan(&f.id, &f.assetID, &f.fingerprint, &f.base, &f.ruleID, &f.filePath,
			&f.message, &f.startLine, &f.createdAt, &f.identityKey); err != nil {
			return nil, fmt.Errorf("scan merged finding: %w", err)
		}
		moved = append(moved, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list merged findings: %w", err)
	}
	return moved, nil
}

func rekeyMergedFinding(ctx context.Context, tx *sql.Tx, tenantID, keepID string, f mergeFinding) error {
	newFP, newKey := mergedFindingFingerprint(f, keepID)
	if newFP == "" || newFP == f.fingerprint {
		return nil
	}
	var holderID string
	var holderCreated time.Time
	err := tx.QueryRowContext(ctx,
		`SELECT id, created_at FROM findings WHERE tenant_id = $1 AND fingerprint = $2 FOR UPDATE`,
		tenantID, newFP).Scan(&holderID, &holderCreated)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// The key on the merged-away asset stays an alias of the finding.
		if err := rememberFindingKey(ctx, tx, tenantID, f.id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE findings SET fingerprint = $1, identity_key = COALESCE($4::jsonb, identity_key) WHERE id = $2 AND tenant_id = $3`,
			newFP, f.id, tenantID, nullJSON(newKey)); err != nil {
			return fmt.Errorf("re-key merged finding: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("look up re-keyed fingerprint: %w", err)
	case !f.createdAt.Before(holderCreated):
		// The finding already holding the key is as old or older: it survives.
		return mergeFindingInto(ctx, tx, tenantID, holderID, f.id, causeAssetMerge)
	default:
		// The moved finding is older: it survives and takes the key.
		if err := mergeFindingInto(ctx, tx, tenantID, f.id, holderID, causeAssetMerge); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE findings SET fingerprint = $1, identity_key = COALESCE($4::jsonb, identity_key) WHERE id = $2 AND tenant_id = $3`,
			newFP, f.id, tenantID, nullJSON(newKey)); err != nil {
			return fmt.Errorf("re-key surviving finding: %w", err)
		}
		return nil
	}
}

// mergedFindingFingerprint is f's fingerprint on the kept asset (and, for a
// versioned key, the rewritten identity tuple), or "" when it cannot be
// recomputed safely.
//   - Versioned findings (RFC-043 §6): the identity tuple with the kept asset.
//   - Ingested findings: CompositeFingerprint(keep, base) from the stored base.
//   - Manual findings (32 characters): ManualFingerprint over the stored
//     columns, but only when those columns still reproduce the stored value on
//     the old asset. A finding edited since creation no longer does, and
//     re-keying it could fold it into an unrelated finding.
//   - Anything else (legacy composite without a base, pentest keys, which do
//     not contain the asset): left as it is.
func mergedFindingFingerprint(f mergeFinding, keepID string) (string, []byte) {
	if len(f.identityKey) > 0 {
		k, err := vulnerability.ParseIdentityKey(f.identityKey)
		// Only a tuple scoped to this finding's asset, and that still
		// reproduces the stored key, is safe to rewrite.
		if err != nil || k.Field(vulnerability.IdentityFieldAsset) != f.assetID || k.Fingerprint() != f.fingerprint {
			return "", nil
		}
		moved := k.WithField(vulnerability.IdentityFieldAsset, keepID)
		raw, err := vulnerability.MarshalIdentityKey(moved)
		if err != nil {
			return "", nil
		}
		return moved.Fingerprint(), raw
	}
	if f.base != "" {
		return vulnerability.CompositeFingerprint(keepID, f.base), nil
	}
	if len(f.fingerprint) == 32 &&
		vulnerability.ManualFingerprint(f.assetID, f.ruleID, f.filePath, f.startLine, f.message) == f.fingerprint {
		return vulnerability.ManualFingerprint(keepID, f.ruleID, f.filePath, f.startLine, f.message), nil
	}
	return "", nil
}

// findingStatusRank orders statuses for a merge: the more deliberate decision
// wins. A closed-as-fixed status ranks below every open one, so a loser that
// was fixed never closes a survivor that is still open.
func findingStatusRank(status string) int {
	switch vulnerability.FindingStatus(status) {
	case vulnerability.FindingStatusFalsePositive, vulnerability.FindingStatusAccepted:
		return 5
	case vulnerability.FindingStatusInProgress, vulnerability.FindingStatusFixApplied,
		vulnerability.FindingStatusValidatedFixed:
		return 4
	case vulnerability.FindingStatusConfirmed, vulnerability.FindingStatusInReview:
		return 3
	case vulnerability.FindingStatusNew, vulnerability.FindingStatusDraft:
		return 2
	case vulnerability.FindingStatusResolved:
		return 1
	default:
		return 0
	}
}

// findingMergeCause says why two findings became one, for the activity
// trail of both.
type findingMergeCause struct {
	// Reason is the activity source and the "reason" in its changes.
	Reason string
	// Phrase ends "Marked duplicate of <id> …".
	Phrase string
	// ActorType is "system" or "user"; ActorID is the user for "user".
	ActorType, ActorID string
}

var causeAssetMerge = findingMergeCause{Reason: "asset_merge", Phrase: "by an asset merge", ActorType: "system"}

// mergeFindingInto folds loser into survivor: the survivor inherits the
// loser's state where the loser's is stronger, every row that references the
// loser moves to the survivor, and the loser becomes a tombstone. Used by the
// asset merge, the re-fingerprint job and "mark duplicate of".
func mergeFindingInto(ctx context.Context, tx *sql.Tx, tenantID, survivorID, loserID string, cause findingMergeCause) error {
	var survivorStatus, loserStatus string
	if err := tx.QueryRowContext(ctx,
		`SELECT (SELECT status FROM findings WHERE id = $1 AND tenant_id = $3),
		        (SELECT status FROM findings WHERE id = $2 AND tenant_id = $3)`,
		survivorID, loserID, tenantID).Scan(&survivorStatus, &loserStatus); err != nil {
		return fmt.Errorf("read statuses for finding merge: %w", err)
	}

	if findingStatusRank(loserStatus) > findingStatusRank(survivorStatus) {
		if _, err := tx.ExecContext(ctx, `
			UPDATE findings s SET
				status = l.status, resolution = l.resolution, resolution_method = l.resolution_method,
				resolved_at = l.resolved_at, resolved_by = l.resolved_by,
				verified_at = l.verified_at, verified_by = l.verified_by
			FROM findings l
			WHERE s.id = $1 AND s.tenant_id = $3 AND l.id = $2 AND l.tenant_id = $3`,
			survivorID, loserID, tenantID); err != nil {
			return fmt.Errorf("inherit finding status: %w", err)
		}
	}

	// Tickets and tags are unioned (survivor's order first), the earliest
	// detection and deadline win, the latest sighting wins, an unassigned
	// survivor takes the loser's assignee.
	if _, err := tx.ExecContext(ctx, `
		UPDATE findings s SET
			work_item_uris = COALESCE(s.work_item_uris, '{}') || ARRAY(
				SELECT u FROM unnest(COALESCE(l.work_item_uris, '{}')) AS u
				WHERE NOT u = ANY(COALESCE(s.work_item_uris, '{}'))),
			tags = COALESCE(s.tags, '{}') || ARRAY(
				SELECT t FROM unnest(COALESCE(l.tags, '{}')) AS t
				WHERE NOT t = ANY(COALESCE(s.tags, '{}'))),
			first_detected_at = LEAST(s.first_detected_at, l.first_detected_at),
			last_seen_at = GREATEST(s.last_seen_at, l.last_seen_at),
			sla_deadline = LEAST(s.sla_deadline, l.sla_deadline),
			sla_status = CASE WHEN l.sla_deadline IS NOT NULL
				AND (s.sla_deadline IS NULL OR l.sla_deadline < s.sla_deadline)
				THEN l.sla_status ELSE s.sla_status END,
			assigned_to = COALESCE(s.assigned_to, l.assigned_to),
			assigned_by = CASE WHEN s.assigned_to IS NULL THEN l.assigned_by ELSE s.assigned_by END,
			assigned_at = CASE WHEN s.assigned_to IS NULL THEN l.assigned_at ELSE s.assigned_at END,
			duplicate_count = COALESCE(s.duplicate_count, 0) + COALESCE(l.duplicate_count, 0) + 1
		FROM findings l
		WHERE s.id = $1 AND s.tenant_id = $3 AND l.id = $2 AND l.tenant_id = $3`,
		survivorID, loserID, tenantID); err != nil {
		return fmt.Errorf("inherit finding state: %w", err)
	}

	if err := settleLoserPendingRetest(ctx, tx, tenantID, survivorID, loserID); err != nil {
		return err
	}

	// The loser's key must keep resolving (to the survivor) after the loser
	// gives it up below.
	if err := rememberFindingKey(ctx, tx, tenantID, loserID); err != nil {
		return err
	}

	for _, ref := range findingMergeRefs {
		if err := repointRef(ctx, tx, ref, survivorID, []string{loserID}, tenantID); err != nil {
			return fmt.Errorf("finding merge: %w", err)
		}
	}

	// The tombstone keeps its id (links, tickets and audit references still
	// resolve) and gives up its key so the survivor can hold it.
	if _, err := tx.ExecContext(ctx, `
		UPDATE findings SET
			status = 'duplicate', duplicate_of = $1,
			fingerprint = 'dup:' || id::text,
			resolved_at = COALESCE(resolved_at, NOW())
		WHERE id = $2 AND tenant_id = $3`, survivorID, loserID, tenantID); err != nil {
		return fmt.Errorf("mark merged finding duplicate: %w", err)
	}

	survivorChanges, _ := json.Marshal(map[string]string{
		"merged_from": loserID, "reason": cause.Reason, "loser_status": loserStatus,
	})
	loserChanges, _ := json.Marshal(map[string]string{"duplicate_of": survivorID, "reason": cause.Reason})
	actorType := cause.ActorType
	if actorType == "" {
		actorType = "system"
	}
	var actorID any
	if cause.ActorID != "" {
		actorID = cause.ActorID
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_id, changes, source, message)
		VALUES ($1, $2, 'duplicate_marked', $8, $9, $3, $10, $4),
		       ($1, $5, 'duplicate_marked', $8, $9, $6, $10, $7)`,
		tenantID, survivorID, survivorChanges, "Merged duplicate finding "+loserID+" into this finding",
		loserID, loserChanges, "Marked duplicate of "+survivorID+" "+cause.Phrase,
		actorType, actorID, cause.Reason); err != nil {
		return fmt.Errorf("record finding merge activity: %w", err)
	}
	return nil
}

// settleLoserPendingRetest makes room for the loser's retests on the survivor.
// A finding has at most one pending retest; when both have one, the survivor's
// keeps running and the loser's is closed as "inconclusive" (its result would
// describe the same issue twice). Its history moves with the other rows.
func settleLoserPendingRetest(ctx context.Context, tx *sql.Tx, tenantID, survivorID, loserID string) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE finding_retests SET
			status = 'completed', outcome = 'inconclusive', reason_code = 'no_result', completed_at = NOW(),
			reason = 'finding merged into ' || $1::text
		WHERE tenant_id = $3 AND finding_id = $2 AND status = 'pending'
		  AND EXISTS (SELECT 1 FROM finding_retests
		              WHERE tenant_id = $3 AND finding_id = $1 AND status = 'pending')`,
		survivorID, loserID, tenantID); err != nil {
		return fmt.Errorf("settle merged finding's pending retest: %w", err)
	}
	return nil
}
