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
	"strings"
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

// TenantsToRekey lists the tenants that have live findings keyed with a
// version below target and no completed run to target (or later). The run
// table is read first: a tenant that finished is not looked up in the
// findings table, so the server start does not scan findings of tenants that
// have nothing left to do. A tenant with no run row yet is checked once,
// with an early-exit EXISTS, and gets its row when its run starts.
func (r *FindingRekeyRepository) TenantsToRekey(ctx context.Context, target int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id FROM tenants t
		WHERE NOT EXISTS (SELECT 1 FROM finding_rekey_runs r
		                  WHERE r.tenant_id = t.id AND r.status = 'completed' AND r.target_version >= $1)
		  AND EXISTS (SELECT 1 FROM findings f
		              WHERE f.tenant_id = t.id AND f.fingerprint_version < $1 AND f.status <> 'duplicate')
		ORDER BY t.id`, target)
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
		       COALESCE(f.misconfig_resource_name, ''), COALESCE(f.partial_fingerprints, '{}'::jsonb),
		       f.identity_key
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
			&in.MisconfigPolicyID, &in.ResourceType, &in.ResourceName, &partial, &in.StoredKey); err != nil {
			return nil, fmt.Errorf("scan finding to re-key: %w", err)
		}
		_ = json.Unmarshal(partial, &in.PartialFingerprints)
		in.StoredFingerprint = c.Fingerprint
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
	// The CI run sightings follow the key: every key the two findings give
	// up moves to the key the survivor holds after this transaction.
	movedKeys, finalKey := []string{fromFP}, newFP
	if holderID != "" {
		var holderFP string
		if err := tx.QueryRowContext(ctx, `SELECT fingerprint FROM findings WHERE id = $1 AND tenant_id = $2`,
			holderID, tenant).Scan(&holderFP); err != nil {
			return vulnerability.RekeyResult{}, fmt.Errorf("read key holder: %w", err)
		}
		if created.Before(holderCreated) || (created.Equal(holderCreated) && findingID < holderID) {
			// This finding is older: it survives and takes the key.
			if err := mergeFindingInto(ctx, tx, tenant, findingID, holderID, causeRefingerprint); err != nil {
				return vulnerability.RekeyResult{}, err
			}
			res = vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeMerged, SurvivorID: findingID, LoserID: holderID}
			movedKeys = append(movedKeys, holderFP)
		} else {
			if err := mergeFindingInto(ctx, tx, tenant, holderID, findingID, causeRefingerprint); err != nil {
				return vulnerability.RekeyResult{}, err
			}
			res = vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeMerged, SurvivorID: holderID, LoserID: findingID}
			takeKey = false
			finalKey = holderFP
		}
	}
	if takeKey {
		if _, err := tx.ExecContext(ctx, `
			UPDATE findings SET fingerprint = $1, fingerprint_version = $2, identity_key = $3::jsonb, updated_at = NOW(),
			       identity_algo = $6, identity_fields = $7
			WHERE id = $4 AND tenant_id = $5`, append([]any{newFP, k.Version, string(raw), findingID, tenant},
			identityRecipeArgs(k.Algo(), k.FieldNames())...)...); err != nil {
			return vulnerability.RekeyResult{}, fmt.Errorf("re-key finding: %w", err)
		}
	}
	if err := moveCIRunFindings(ctx, tx, tenant, movedKeys, finalKey); err != nil {
		return vulnerability.RekeyResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return vulnerability.RekeyResult{}, fmt.Errorf("commit re-key: %w", err)
	}
	return res, nil
}

// moveCIRunFindings moves the CI run sightings recorded under the keys from
// to the key to, in tx and in the tenant: a run's findings are joined on the
// finding's current key. A run that already has to keeps one row.
func moveCIRunFindings(ctx context.Context, tx *sql.Tx, tenant string, from []string, to string) error {
	olds := make([]string, 0, len(from))
	for _, k := range from {
		if k != "" && k != to && !strings.HasPrefix(k, "dup:") {
			olds = append(olds, k)
		}
	}
	if len(olds) == 0 || to == "" || strings.HasPrefix(to, "dup:") {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ci_run_findings (tenant_id, run_id, fingerprint)
		SELECT DISTINCT tenant_id, run_id, $3::varchar FROM ci_run_findings
		WHERE tenant_id = $1 AND fingerprint = ANY($2)
		ON CONFLICT (run_id, fingerprint) DO NOTHING`, tenant, pq.Array(olds), to); err != nil {
		return fmt.Errorf("move ci run findings: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM ci_run_findings WHERE tenant_id = $1 AND fingerprint = ANY($2)`, tenant, pq.Array(olds)); err != nil {
		return fmt.Errorf("move ci run findings: %w", err)
	}
	return nil
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

// TenantsAtVersion lists the tenants that have live findings keyed with
// version (the down step's input).
func (r *FindingRekeyRepository) TenantsAtVersion(ctx context.Context, version int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT tenant_id FROM findings
		WHERE fingerprint_version = $1 AND status <> 'duplicate'
		ORDER BY tenant_id`, version)
	if err != nil {
		return nil, fmt.Errorf("list tenants to restore: %w", err)
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

// ListAtVersion returns up to limit live findings of the tenant keyed with
// version and an id above afterID, in id order (ID and Fingerprint only).
func (r *FindingRekeyRepository) ListAtVersion(ctx context.Context, tenantID shared.ID, version int, afterID string, limit int) ([]vulnerability.RekeyCandidate, error) {
	if afterID == "" {
		afterID = "00000000-0000-0000-0000-000000000000"
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, fingerprint, created_at FROM findings
		WHERE tenant_id = $1 AND fingerprint_version = $2 AND status <> 'duplicate' AND id > $3::uuid
		ORDER BY id
		LIMIT $4`, tenantID.String(), version, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list findings to restore: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []vulnerability.RekeyCandidate
	for rows.Next() {
		var c vulnerability.RekeyCandidate
		if err := rows.Scan(&c.ID, &c.Fingerprint, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan finding to restore: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Reasons the down step leaves a finding on its current key.
const (
	restoreSkipNoPrevious = "no_previous_key"
	restoreSkipHeld       = "previous_key_held"
	restoreSkipMismatch   = vulnerability.RecomputeSkipKeyMismatch
)

// Restore moves one finding from its version-3 key back to the key it had
// before, in one transaction: the version-2 key of its tuple when its kind
// had one (the tuple is the same in both versions), else its newest older
// alias (a finding a sighting re-keyed from version 1), with no tuple. The
// version-3 key stays an alias. A finding that changed since it was listed,
// whose tuple no longer reproduces its key, or whose previous key another
// finding holds now is skipped. Merges are not undone: a merged finding is a
// tombstone and its keys stay aliases of the survivor.
func (r *FindingRekeyRepository) Restore(ctx context.Context, tenantID shared.ID, findingID, fromFP string) (vulnerability.RekeyResult, error) {
	tenant := tenantID.String()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return vulnerability.RekeyResult{}, fmt.Errorf("begin restore: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var raw []byte
	err = tx.QueryRowContext(ctx, `
		SELECT identity_key FROM findings
		WHERE id = $1 AND tenant_id = $2 AND fingerprint = $3 AND fingerprint_version = $4 AND status <> 'duplicate'
		FOR UPDATE`, findingID, tenant, fromFP, vulnerability.IdentityVersion).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeSkipped}, nil
	}
	if err != nil {
		return vulnerability.RekeyResult{}, fmt.Errorf("lock finding to restore: %w", err)
	}
	k, err := vulnerability.ParseIdentityKey(raw)
	if err != nil || k.Fingerprint() != fromFP {
		return vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeSkipped, Reason: restoreSkipMismatch}, nil
	}

	var (
		toFP    string
		toVer   int
		toKey   any // NULL or the version-2 tuple
		recipeA = []any{nil, nil}
	)
	if k.HasVersion2Form() {
		k2 := k.AtVersion(2)
		raw2, err := vulnerability.MarshalIdentityKey(k2)
		if err != nil {
			return vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeSkipped, Reason: restoreSkipMismatch}, nil
		}
		toFP, toVer, toKey = k2.Fingerprint(), 2, string(raw2)
		recipeA = identityRecipeArgs(k2.Algo(), k2.FieldNames())
	} else {
		err := tx.QueryRowContext(ctx, `
			SELECT fingerprint, version FROM finding_fingerprints
			WHERE tenant_id = $1 AND finding_id = $2 AND version < $3
			ORDER BY version DESC, created_at DESC, fingerprint
			LIMIT 1`, tenant, findingID, vulnerability.IdentityVersion).Scan(&toFP, &toVer)
		if errors.Is(err, sql.ErrNoRows) {
			return vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeSkipped, Reason: restoreSkipNoPrevious}, nil
		}
		if err != nil {
			return vulnerability.RekeyResult{}, fmt.Errorf("read previous key: %w", err)
		}
	}
	holderID, _, _, err := lockKeyHolder(ctx, tx, tenant, toFP, findingID)
	if err != nil {
		return vulnerability.RekeyResult{}, err
	}
	if holderID != "" {
		return vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeSkipped, Reason: restoreSkipHeld}, nil
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE findings SET fingerprint = $1, fingerprint_version = $2, identity_key = $3::jsonb, updated_at = NOW(),
		       identity_algo = $6, identity_fields = $7
		WHERE id = $4 AND tenant_id = $5`, append([]any{toFP, toVer, toKey, findingID, tenant}, recipeA...)...); err != nil {
		return vulnerability.RekeyResult{}, fmt.Errorf("restore finding key: %w", err)
	}
	if err := moveCIRunFindings(ctx, tx, tenant, []string{fromFP}, toFP); err != nil {
		return vulnerability.RekeyResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return vulnerability.RekeyResult{}, fmt.Errorf("commit restore: %w", err)
	}
	return vulnerability.RekeyResult{Outcome: vulnerability.RekeyOutcomeRekeyed}, nil
}

// rekeyOnStartLockKey is the session advisory lock that lets one server
// replica at a time run the re-key on start.
const rekeyOnStartLockKey int64 = 0x0c7e_f1d6_0003

// WithRekeyLock runs fn while holding the re-key advisory lock on its own
// connection. ran is false (and fn is not called) when another session holds
// the lock: that replica is doing the work.
func (r *FindingRekeyRepository) WithRekeyLock(ctx context.Context, fn func(context.Context) error) (ran bool, err error) {
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return false, fmt.Errorf("re-key lock connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, rekeyOnStartLockKey).Scan(&got); err != nil {
		return false, fmt.Errorf("take re-key lock: %w", err)
	}
	if !got {
		return false, nil
	}
	defer func() {
		// A fresh context: the lock must be released even when ctx ended.
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, rekeyOnStartLockKey)
	}()
	return true, fn(ctx)
}
