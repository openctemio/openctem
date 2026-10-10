package postgres

// Re-fingerprint storage (RFC-043 §6).
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-043-deduplication-and-identity.md
//
// The job reads a tenant's findings that are still on an older identity
// version in id order, recomputes each key and re-keys it. A key that another
// finding already holds means the two are one finding: the earliest-created
// survives through the same merge an asset merge uses (state inherited, every
// reference moved, the other kept as a tombstone). Nothing is deleted. The
// old key stays an alias (trigger), so a late report in the old scheme still
// lands on the right finding.

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

// causeRefingerprint labels merges made by the job.
var causeRefingerprint = findingMergeCause{Reason: "refingerprint", Phrase: "by the fingerprint migration", ActorType: "system"}

// FindingRekeyRepository is the storage of the re-fingerprint job. Every
// statement is scoped to the tenant it is given.
type FindingRekeyRepository struct {
	db *DB
}

// NewFindingRekeyRepository creates the repository.
func NewFindingRekeyRepository(db *DB) *FindingRekeyRepository {
	return &FindingRekeyRepository{db: db}
}

// TenantsBelowVersion lists the tenants that have live findings keyed with a
// version below target.
func (r *FindingRekeyRepository) TenantsBelowVersion(ctx context.Context, target int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT tenant_id FROM findings
		WHERE fingerprint_version < $1 AND status <> 'duplicate'
		ORDER BY tenant_id`, target)
	if err != nil {
		return nil, fmt.Errorf("list tenants to re-key: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, fmt.Errorf("tenant id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ListCandidates returns up to limit live findings of the tenant keyed with a
// version below target and an id above afterID ("" = from the start), in id
// order.
func (r *FindingRekeyRepository) ListCandidates(ctx context.Context, tenantID shared.ID, target int, afterID string, limit int) ([]vulnerability.RekeyCandidate, error) {
	if afterID == "" {
		afterID = "00000000-0000-0000-0000-000000000000"
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id, f.fingerprint, f.created_at, COALESCE(f.asset_id::text, ''), f.source,
		       COALESCE(f.finding_type, ''), f.tool_name, COALESCE(f.rule_id, ''), COALESCE(f.file_path, ''),
		       COALESCE(f.cve_id, ''), COALESCE(c.purl, ''),
		       COALESCE(f.type_details->'secret'->>'fingerprint', ''),
		       COALESCE(f.misconfig_policy_id, ''), COALESCE(f.misconfig_resource_type, ''),
		       COALESCE(f.misconfig_resource_name, ''), COALESCE(f.partial_fingerprints, '{}'::jsonb)
		FROM findings f
		LEFT JOIN software_versions c ON c.id = f.component_id
		WHERE f.tenant_id = $1 AND f.fingerprint_version < $2 AND f.status <> 'duplicate'
		  AND f.id > $3::uuid
		ORDER BY f.id
		LIMIT $4`, tenantID.String(), target, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list findings to re-key: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []vulnerability.RekeyCandidate
	for rows.Next() {
		var c vulnerability.RekeyCandidate
		var partial []byte
		in := &c.Input
		if err := rows.Scan(&c.ID, &c.Fingerprint, &c.CreatedAt, &in.AssetID, &in.Source, &in.FindingType,
			&in.ToolName, &in.RuleID, &in.FilePath, &in.CVEID, &in.ComponentPURL, &in.SecretHMAC,
			&in.MisconfigPolicyID, &in.ResourceType, &in.ResourceName, &partial); err != nil {
			return nil, fmt.Errorf("scan finding to re-key: %w", err)
		}
		_ = json.Unmarshal(partial, &in.PartialFingerprints)
		out = append(out, c)
	}
	return out, rows.Err()
}

// Holders returns, for each key, the live finding of the tenant that owns it
// now: directly, or through an alias.
func (r *FindingRekeyRepository) Holders(ctx context.Context, tenantID shared.ID, keys []string) (map[string]vulnerability.RekeyHolder, error) {
	out := make(map[string]vulnerability.RekeyHolder)
	if len(keys) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT k.key, f.id, COALESCE(f.asset_id::text, ''), f.created_at
		FROM unnest($2::text[]) AS k(key)
		JOIN LATERAL (
			SELECT f.id, f.asset_id, f.created_at FROM findings f
			WHERE f.tenant_id = $1 AND f.fingerprint = k.key
			UNION ALL
			SELECT f.id, f.asset_id, f.created_at FROM finding_fingerprints a
			JOIN findings f ON f.id = a.finding_id AND f.tenant_id = a.tenant_id
			WHERE a.tenant_id = $1 AND a.fingerprint = k.key AND f.status <> 'duplicate'
			LIMIT 1
		) f ON TRUE`, tenantID.String(), pq.Array(keys))
	if err != nil {
		return nil, fmt.Errorf("look up key holders: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var key string
		var h vulnerability.RekeyHolder
		if err := rows.Scan(&key, &h.ID, &h.AssetID, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan key holder: %w", err)
		}
		out[key] = h
	}
	return out, rows.Err()
}

// Rekey moves one finding to its versioned key, in one transaction. When
// another live finding owns the key, the earliest-created of the two survives
// and holds the key; the other becomes its tombstone. A finding that changed
// since it was listed (another key, already re-keyed, merged away) is skipped.
func (r *FindingRekeyRepository) Rekey(ctx context.Context, tenantID shared.ID, findingID, fromFP string, k vulnerability.IdentityKey) (vulnerability.RekeyResult, error) {
	raw, err := vulnerability.MarshalIdentityKey(k)
	if err != nil {
		return vulnerability.RekeyResult{}, err
	}
	newFP := k.Fingerprint()
	tenant := tenantID.String()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return vulnerability.RekeyResult{}, fmt.Errorf("begin re-key: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var created time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT created_at FROM findings
		WHERE id = $1 AND tenant_id = $2 AND fingerprint = $3 AND fingerprint_version < $4 AND status <> 'duplicate'
		FOR UPDATE`, findingID, tenant, fromFP, k.Version).Scan(&created)
	if errors.Is(err, sql.ErrNoRows) {
		return vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeSkipped}, nil
	}
	if err != nil {
		return vulnerability.RekeyResult{}, fmt.Errorf("lock finding to re-key: %w", err)
	}

	holderID, holderAsset, holderCreated, err := lockKeyHolder(ctx, tx, tenant, newFP, findingID)
	if err != nil {
		return vulnerability.RekeyResult{}, err
	}
	if holderID != "" && holderAsset != k.Field(vulnerability.IdentityFieldAsset) {
		// Never merge across assets automatically (data scope).
		return vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeSkipped, Reason: vulnerability.RekeySkipOtherAsset}, nil
	}
	res := vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeRekeyed}
	takeKey := true
	if holderID != "" {
		if created.Before(holderCreated) || (created.Equal(holderCreated) && findingID < holderID) {
			// This finding is older: it survives and takes the key.
			if err := mergeFindingInto(ctx, tx, tenant, findingID, holderID, causeRefingerprint); err != nil {
				return vulnerability.RekeyResult{}, err
			}
			res = vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeMerged, SurvivorID: findingID, LoserID: holderID}
		} else {
			if err := mergeFindingInto(ctx, tx, tenant, holderID, findingID, causeRefingerprint); err != nil {
				return vulnerability.RekeyResult{}, err
			}
			res = vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeMerged, SurvivorID: holderID, LoserID: findingID}
			takeKey = false
		}
	}
	if takeKey {
		if _, err := tx.ExecContext(ctx, `
			UPDATE findings SET fingerprint = $1, fingerprint_version = $2, identity_key = $3::jsonb, updated_at = NOW()
			WHERE id = $4 AND tenant_id = $5`, newFP, k.Version, string(raw), findingID, tenant); err != nil {
			return vulnerability.RekeyResult{}, fmt.Errorf("re-key finding: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return vulnerability.RekeyResult{}, fmt.Errorf("commit re-key: %w", err)
	}
	return res, nil
}

// lockKeyHolder finds and locks the live finding other than self that owns
// key in the tenant, directly or through an alias, with its asset. "" when
// none does.
func lockKeyHolder(ctx context.Context, tx *sql.Tx, tenant, key, self string) (string, string, time.Time, error) {
	var id, asset string
	var created time.Time
	err := tx.QueryRowContext(ctx, `
		SELECT f.id, COALESCE(f.asset_id::text, ''), f.created_at FROM findings f
		WHERE f.tenant_id = $1 AND f.id <> $3 AND f.status <> 'duplicate'
		  AND (f.fingerprint = $2 OR f.id = (
		      SELECT a.finding_id FROM finding_fingerprints a WHERE a.tenant_id = $1 AND a.fingerprint = $2))
		ORDER BY (f.fingerprint = $2) DESC
		LIMIT 1
		FOR UPDATE OF f`, tenant, key, self).Scan(&id, &asset, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", time.Time{}, nil
	}
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("lock key holder: %w", err)
	}
	return id, asset, created, nil
}

// GetRun returns the tenant's checkpoint, or nil.
func (r *FindingRekeyRepository) GetRun(ctx context.Context, tenantID shared.ID) (*vulnerability.RekeyRun, error) {
	var run vulnerability.RekeyRun
	var cursor sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT target_version, status, cursor_id::text, rekeyed, merged, skipped
		FROM finding_rekey_runs WHERE tenant_id = $1`, tenantID.String()).
		Scan(&run.TargetVersion, &run.Status, &cursor, &run.Rekeyed, &run.Merged, &run.Skipped)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read re-key run: %w", err)
	}
	run.CursorID = cursor.String
	return &run, nil
}

// StartRun opens (or re-opens) the tenant's run for target. A running run for
// the same target is resumed from its cursor; anything else starts over.
// While it runs, scan auto-resolve is paused for the tenant.
func (r *FindingRekeyRepository) StartRun(ctx context.Context, tenantID shared.ID, target int) (*vulnerability.RekeyRun, error) {
	if _, err := r.db.ExecContext(ctx, `
		INSERT INTO finding_rekey_runs (tenant_id, target_version, status)
		VALUES ($1, $2, 'running')
		ON CONFLICT (tenant_id) DO UPDATE SET
			status = 'running', finished_at = NULL, updated_at = NOW(),
			started_at = CASE WHEN finding_rekey_runs.status = 'running' AND finding_rekey_runs.target_version = EXCLUDED.target_version
				THEN finding_rekey_runs.started_at ELSE NOW() END,
			cursor_id = CASE WHEN finding_rekey_runs.status = 'running' AND finding_rekey_runs.target_version = EXCLUDED.target_version
				THEN finding_rekey_runs.cursor_id END,
			rekeyed = CASE WHEN finding_rekey_runs.status = 'running' AND finding_rekey_runs.target_version = EXCLUDED.target_version
				THEN finding_rekey_runs.rekeyed ELSE 0 END,
			merged = CASE WHEN finding_rekey_runs.status = 'running' AND finding_rekey_runs.target_version = EXCLUDED.target_version
				THEN finding_rekey_runs.merged ELSE 0 END,
			skipped = CASE WHEN finding_rekey_runs.status = 'running' AND finding_rekey_runs.target_version = EXCLUDED.target_version
				THEN finding_rekey_runs.skipped ELSE 0 END,
			target_version = EXCLUDED.target_version`,
		tenantID.String(), target); err != nil {
		return nil, fmt.Errorf("start re-key run: %w", err)
	}
	return r.GetRun(ctx, tenantID)
}

// SaveProgress stores the cursor and adds to the counters after a batch.
func (r *FindingRekeyRepository) SaveProgress(ctx context.Context, tenantID shared.ID, cursorID string, rekeyed, merged, skipped int) error {
	if _, err := r.db.ExecContext(ctx, `
		UPDATE finding_rekey_runs SET cursor_id = $2::uuid, rekeyed = rekeyed + $3, merged = merged + $4,
			skipped = skipped + $5, updated_at = NOW()
		WHERE tenant_id = $1 AND status = 'running'`,
		tenantID.String(), cursorID, rekeyed, merged, skipped); err != nil {
		return fmt.Errorf("save re-key progress: %w", err)
	}
	return nil
}

// FinishRun closes the run; scan auto-resolve resumes for the tenant.
func (r *FindingRekeyRepository) FinishRun(ctx context.Context, tenantID shared.ID) error {
	if _, err := r.db.ExecContext(ctx, `
		UPDATE finding_rekey_runs SET status = 'completed', finished_at = NOW(), updated_at = NOW()
		WHERE tenant_id = $1`, tenantID.String()); err != nil {
		return fmt.Errorf("finish re-key run: %w", err)
	}
	return nil
}

// rekeyRunPauseWindow bounds the auto-resolve pause: a run that has not
// saved progress for this long (the job crashed, or was stopped with
// -max-batches and not resumed) no longer pauses the tenant. Findings it did
// not reach are still re-keyed on their next sighting, so auto-resolve cannot
// close them by mistake; the pause is a belt, not the only guard.
const rekeyRunPauseWindow = "2 hours"

// autoResolvePaused reports whether a re-fingerprint run is re-keying the
// tenant's findings (decision D11). It fails closed: on an error the caller
// does not auto-resolve.
func autoResolvePaused(ctx context.Context, q interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}, tenantID string) bool {
	var running bool
	if err := q.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM finding_rekey_runs WHERE tenant_id = $1 AND status = 'running'
			AND updated_at > NOW() - INTERVAL '`+rekeyRunPauseWindow+`')`,
		tenantID).Scan(&running); err != nil {
		return true
	}
	return running
}
