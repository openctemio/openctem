package postgres

// Rule sources and their snapshots (docs/architecture/content-sources.md;
// migration content_sources). Organization statements carry the tenant
// predicate; a platform row (tenant_id NULL) is only ever read by them, and
// only when it is offered. Methods ending in Unscoped serve the sync worker
// and the webhook.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	cs "github.com/openctemio/openctem/api/pkg/domain/contentsource"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ContentSourceRepository implements contentsource.Repository.
type ContentSourceRepository struct {
	db *DB
}

// NewContentSourceRepository creates a ContentSourceRepository.
func NewContentSourceRepository(db *DB) *ContentSourceRepository {
	return &ContentSourceRepository{db: db}
}

var _ cs.Repository = (*ContentSourceRepository)(nil)

const contentSourceColumns = `
	id, scope, tenant_id, slug, rule_namespace, name, description, kind, origin, COALESCE(url, ''), COALESCE(ref, ''), path,
	COALESCE(auth_username, ''), COALESCE(credential_encrypted, ''), COALESCE(credential_hint, ''), credential_updated_at,
	COALESCE(ca_pem, ''), COALESCE(license_spdx, ''), license_service_use, promotion_policy, sync_interval_minutes,
	next_sync_at, sync_requested_at, COALESCE(webhook_secret_hash, ''), webhook_secret_set_at, storage_mode,
	COALESCE(availability, ''), official, enabled, current_snapshot_id, previous_snapshot_id,
	last_sync_at, last_sync_status, COALESCE(last_sync_error, ''), COALESCE(last_sync_commit, ''), last_sync_report,
	consecutive_failures, config_changed_by, config_changed_at, created_by, created_at, updated_at`

func scanContentSource(row interface{ Scan(...any) error }) (*cs.Source, error) {
	var (
		s                                       cs.Source
		id, scope, kind, origin, policy, status string
		availability                            string
		tenantID, current, previous             sql.NullString
		changedBy, createdBy                    sql.NullString
		credAt, nextSync, requested, webhookAt  sql.NullTime
		lastSync, changedAt                     sql.NullTime
		report                                  []byte
	)
	if err := row.Scan(&id, &scope, &tenantID, &s.Slug, &s.RuleNamespace, &s.Name, &s.Description, &kind, &origin, &s.URL, &s.Ref, &s.Path,
		&s.AuthUsername, &s.CredentialEncrypted, &s.CredentialHint, &credAt,
		&s.CAPEM, &s.LicenseSPDX, &s.LicenseServiceUse, &policy, &s.SyncIntervalMin,
		&nextSync, &requested, &s.WebhookSecretHash, &webhookAt, &s.StorageMode,
		&availability, &s.Official, &s.Enabled, &current, &previous,
		&lastSync, &status, &s.LastSyncError, &s.LastSyncCommit, &report,
		&s.ConsecutiveFailures, &changedBy, &changedAt, &createdBy, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	s.ID, _ = shared.IDFromString(id)
	s.Scope, s.Kind, s.Origin = cs.Scope(scope), cs.Kind(kind), cs.Origin(origin)
	s.Policy, s.LastSyncStatus, s.Availability = cs.PromotionPolicy(policy), cs.SyncStatus(status), cs.Availability(availability)
	s.TenantID = parseNullID(tenantID)
	s.CurrentSnapshotID, s.PreviousSnapshotID = parseNullID(current), parseNullID(previous)
	s.ConfigChangedBy, s.CreatedBy = parseNullID(changedBy), parseNullID(createdBy)
	s.CredentialUpdatedAt, s.NextSyncAt, s.SyncRequestedAt = nullTimeValue(credAt), nullTimeValue(nextSync), nullTimeValue(requested)
	s.WebhookSecretAt, s.LastSyncAt, s.ConfigChangedAt = nullTimeValue(webhookAt), nullTimeValue(lastSync), nullTimeValue(changedAt)
	s.LastSyncReport = report
	return &s, nil
}

func scanContentSources(rows *sql.Rows) ([]*cs.Source, error) {
	defer rows.Close()
	out := []*cs.Source{}
	for rows.Next() {
		s, err := scanContentSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Create stores a new source.
func (r *ContentSourceRepository) Create(ctx context.Context, s *cs.Source) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO content_sources (id, scope, tenant_id, slug, rule_namespace, name, description, kind, origin, url, ref, path,
			auth_username, credential_encrypted, credential_hint, credential_updated_at, ca_pem, license_spdx,
			license_service_use, promotion_policy, sync_interval_minutes, next_sync_at, storage_mode, availability,
			official, enabled, config_changed_by, config_changed_at, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $31, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21,
			$22, $23, $24, $25, $26, $27, $28, $29, $30)`,
		s.ID.String(), string(s.Scope), nullIDPtr(s.TenantID), s.Slug, s.Name, s.Description, string(s.Kind),
		string(s.Origin), nullString(s.URL), nullString(s.Ref), s.Path,
		nullString(s.AuthUsername), nullString(s.CredentialEncrypted), nullString(s.CredentialHint),
		nullTime(s.CredentialUpdatedAt), nullString(s.CAPEM), nullString(s.LicenseSPDX),
		s.LicenseServiceUse, string(s.Policy), s.SyncIntervalMin, nullTime(s.NextSyncAt), s.StorageMode,
		nullString(string(s.Availability)), s.Official, s.Enabled, nullIDPtr(s.ConfigChangedBy),
		nullTime(s.ConfigChangedAt), nullIDPtr(s.CreatedBy), s.CreatedAt, s.UpdatedAt, s.Namespace())
	if err != nil {
		if isUniqueViolation(err) {
			return cs.ErrSlugTaken
		}
		return fmt.Errorf("create rule source: %w", err)
	}
	return nil
}

func (r *ContentSourceRepository) one(row *sql.Row) (*cs.Source, error) {
	s, err := scanContentSource(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, cs.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get rule source: %w", err)
	}
	return s, nil
}

// Get returns the tenant's own source.
func (r *ContentSourceRepository) Get(ctx context.Context, tenantID, id shared.ID) (*cs.Source, error) {
	return r.one(r.db.QueryRowContext(ctx, `SELECT `+contentSourceColumns+`
		FROM content_sources WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String()))
}

// GetVisible returns the tenant's own source or an offered platform source.
func (r *ContentSourceRepository) GetVisible(ctx context.Context, tenantID, id shared.ID) (*cs.Source, error) {
	return r.one(r.db.QueryRowContext(ctx, `SELECT `+contentSourceColumns+`
		FROM content_sources
		WHERE id = $2 AND (tenant_id = $1 OR (tenant_id IS NULL AND availability <> 'hidden'))`,
		tenantID.String(), id.String()))
}

// ListVisible lists the tenant's sources and the offered platform sources.
func (r *ContentSourceRepository) ListVisible(ctx context.Context, tenantID shared.ID, f cs.ListFilter) ([]*cs.Source, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+contentSourceColumns+`
		FROM content_sources
		WHERE (tenant_id = $1 OR (tenant_id IS NULL AND availability <> 'hidden'))
		  AND ($2::text = '' OR kind = $2)
		  AND ($3::text = '' OR scope = $3)
		ORDER BY (tenant_id IS NOT NULL), name, id
		LIMIT 500`, tenantID.String(), string(f.Kind), string(f.Scope))
	if err != nil {
		return nil, fmt.Errorf("list rule sources: %w", err)
	}
	out, err := scanContentSources(rows)
	if err != nil {
		return nil, fmt.Errorf("list rule sources: %w", err)
	}
	return out, nil
}

// CountForTenant counts the tenant's own sources.
func (r *ContentSourceRepository) CountForTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM content_sources WHERE tenant_id = $1`,
		tenantID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count rule sources: %w", err)
	}
	return n, nil
}

// Update writes the configuration of the tenant's own source.
func (r *ContentSourceRepository) Update(ctx context.Context, s *cs.Source) error {
	if s.TenantID == nil {
		return cs.ErrPlatformReadOnly
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE content_sources SET name = $3, description = $4, url = $5, ref = $6, path = $7,
			auth_username = $8, credential_encrypted = $9, credential_hint = $10, credential_updated_at = $11,
			ca_pem = $12, license_spdx = $13, license_service_use = $14, promotion_policy = $15,
			sync_interval_minutes = $16, next_sync_at = $17, webhook_secret_hash = $18, webhook_secret_set_at = $19,
			enabled = $20, config_changed_by = $21, config_changed_at = $22
		WHERE tenant_id = $1 AND id = $2`,
		s.TenantID.String(), s.ID.String(), s.Name, s.Description, nullString(s.URL), nullString(s.Ref), s.Path,
		nullString(s.AuthUsername), nullString(s.CredentialEncrypted), nullString(s.CredentialHint),
		nullTime(s.CredentialUpdatedAt), nullString(s.CAPEM), nullString(s.LicenseSPDX), s.LicenseServiceUse,
		string(s.Policy), s.SyncIntervalMin, nullTime(s.NextSyncAt), nullString(s.WebhookSecretHash),
		nullTime(s.WebhookSecretAt), s.Enabled, nullIDPtr(s.ConfigChangedBy), nullTime(s.ConfigChangedAt))
	if err != nil {
		return fmt.Errorf("update rule source: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return cs.ErrNotFound
	}
	return nil
}

// Delete deletes the tenant's own source with its snapshots (their packs
// stay in the pack store until the collector or an operator removes them).
func (r *ContentSourceRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM content_sources WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("delete rule source: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return cs.ErrNotFound
	}
	return nil
}

// RequestSync queues a sync of the tenant's own source.
func (r *ContentSourceRepository) RequestSync(ctx context.Context, tenantID, id shared.ID, at time.Time) error {
	res, err := r.db.ExecContext(ctx, `UPDATE content_sources SET sync_requested_at = $3
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String(), at)
	if err != nil {
		return fmt.Errorf("request rule source sync: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return cs.ErrNotFound
	}
	return nil
}

// ClaimDueUnscoped leases due or requested tenant sources.
func (r *ContentSourceRepository) ClaimDueUnscoped(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]*cs.Source, error) {
	rows, err := r.db.QueryContext(ctx, `
		WITH due AS (
			SELECT id FROM content_sources
			WHERE scope = 'tenant' AND enabled AND origin = 'git' AND storage_mode = 'mirror'
			  AND (sync_lease_until IS NULL OR sync_lease_until < $1)
			  AND (sync_requested_at IS NOT NULL
			       OR (sync_interval_minutes > 0 AND next_sync_at IS NOT NULL AND next_sync_at <= $1))
			ORDER BY sync_requested_at NULLS LAST, next_sync_at
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE content_sources SET sync_lease_until = $2
		WHERE id IN (SELECT id FROM due)
		RETURNING `+contentSourceColumns,
		now, now.Add(lease), limit)
	if err != nil {
		return nil, fmt.Errorf("claim rule sources: %w", err)
	}
	out, err := scanContentSources(rows)
	if err != nil {
		return nil, fmt.Errorf("claim rule sources: %w", err)
	}
	return out, nil
}

// GetUnscoped loads any source by id.
func (r *ContentSourceRepository) GetUnscoped(ctx context.Context, id shared.ID) (*cs.Source, error) {
	return r.one(r.db.QueryRowContext(ctx, `SELECT `+contentSourceColumns+`
		FROM content_sources WHERE id = $1`, id.String()))
}

// RequestSyncUnscoped queues a sync unless one was requested within minGap.
func (r *ContentSourceRepository) RequestSyncUnscoped(ctx context.Context, id shared.ID, at time.Time, minGap time.Duration) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE content_sources SET sync_requested_at = $2
		WHERE id = $1 AND enabled AND (sync_requested_at IS NULL OR sync_requested_at < $3)`,
		id.String(), at, at.Add(-minGap))
	if err != nil {
		return false, fmt.Errorf("request rule source sync: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// SaveSyncUnscoped writes a sync's outcome and releases the lease.
func (r *ContentSourceRepository) SaveSyncUnscoped(ctx context.Context, id shared.ID, o cs.SyncOutcome) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE content_sources SET
			last_sync_status = $2, last_sync_error = $3, last_sync_commit = COALESCE($4, last_sync_commit),
			last_sync_report = $5, last_sync_at = $6, next_sync_at = $7, sync_lease_until = NULL,
			sync_requested_at = CASE WHEN $8 THEN NULL ELSE sync_requested_at END,
			consecutive_failures = CASE WHEN $9 THEN 0 WHEN $10 THEN consecutive_failures ELSE consecutive_failures + 1 END
		WHERE id = $1`,
		id.String(), string(o.Status), nullString(truncate(o.Error, 2000)), nullString(o.Commit), nullBytes(o.Report),
		o.At, nullTime(o.NextSyncAt), o.ClearRequest, o.ResetFailures, o.KeepFailures)
	if err != nil {
		return fmt.Errorf("save rule source sync: %w", err)
	}
	return nil
}

const contentSnapshotColumns = `
	id, source_id, scope, tenant_id, upstream_revision, COALESCE(ref, ''), digest, content_pack_id, platform_pack_id,
	size_bytes, file_count, file_index, rules, rule_count, tier, lint, COALESCE(license_spdx, ''), service_use, redistribution, signature,
	diff, checks, review_required, state, synced_by, promoted_by, promoted_at, rejected_by, rejected_at,
	COALESCE(reject_reason, ''), created_at`

func scanContentSnapshot(row interface{ Scan(...any) error }) (*cs.Snapshot, error) {
	var (
		sn                                   cs.Snapshot
		id, sourceID, scope, tier, state     string
		tenantID, packID, platformPackID     sql.NullString
		syncedBy, promotedBy, rejectedBy     sql.NullString
		promotedAt, rejectedAt               sql.NullTime
		fileIndex, rules, lint, diff, checks []byte
		redistribution                       sql.NullBool
	)
	if err := row.Scan(&id, &sourceID, &scope, &tenantID, &sn.UpstreamRevision, &sn.Ref, &sn.Digest, &packID, &platformPackID,
		&sn.SizeBytes, &sn.FileCount, &fileIndex, &rules, &sn.RuleCount, &tier, &lint, &sn.LicenseSPDX, &sn.ServiceUse, &redistribution, &sn.Signature,
		&diff, &checks, &sn.ReviewRequired, &state, &syncedBy, &promotedBy, &promotedAt, &rejectedBy, &rejectedAt,
		&sn.RejectReason, &sn.CreatedAt); err != nil {
		return nil, err
	}
	sn.ID, _ = shared.IDFromString(id)
	sn.SourceID, _ = shared.IDFromString(sourceID)
	sn.Scope, sn.State = cs.Scope(scope), cs.SnapshotState(state)
	sn.Tier = contentpack.Tier(tier)
	sn.TenantID, sn.ContentPackID, sn.PlatformPackID = parseNullID(tenantID), parseNullID(packID), parseNullID(platformPackID)
	sn.SyncedBy, sn.PromotedBy, sn.RejectedBy = parseNullID(syncedBy), parseNullID(promotedBy), parseNullID(rejectedBy)
	sn.PromotedAt, sn.RejectedAt = nullTimeValue(promotedAt), nullTimeValue(rejectedAt)
	sn.Redistribution = nullBoolValue(redistribution)
	for _, d := range []struct {
		raw []byte
		v   any
	}{{fileIndex, &sn.FileIndex}, {rules, &sn.Rules}, {lint, &sn.Lint}, {diff, &sn.Diff}, {checks, &sn.Checks}} {
		if err := json.Unmarshal(d.raw, d.v); err != nil {
			return nil, fmt.Errorf("decode snapshot: %w", err)
		}
	}
	return &sn, nil
}

// CreateSnapshot stores a snapshot.
func (r *ContentSourceRepository) CreateSnapshot(ctx context.Context, sn *cs.Snapshot) error {
	enc := json.Marshal
	fileIndex, err := enc(sn.FileIndex)
	if err != nil {
		return err
	}
	rules, err := enc(sn.Rules)
	if err != nil {
		return err
	}
	lint, err := enc(sn.Lint)
	if err != nil {
		return err
	}
	diff, err := enc(sn.Diff)
	if err != nil {
		return err
	}
	checks, err := enc(sn.Checks)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO content_source_snapshots (id, source_id, scope, tenant_id, upstream_revision, ref, digest,
			content_pack_id, platform_pack_id, size_bytes, file_count, file_index, rules, rule_count, tier, lint,
			license_spdx, signature, diff, checks, review_required, state, synced_by, created_at, service_use, redistribution)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)`,
		sn.ID.String(), sn.SourceID.String(), string(sn.Scope), nullIDPtr(sn.TenantID), sn.UpstreamRevision, nullString(sn.Ref),
		sn.Digest, nullIDPtr(sn.ContentPackID), nullIDPtr(sn.PlatformPackID), sn.SizeBytes, sn.FileCount,
		fileIndex, rules, sn.RuleCount, string(sn.Tier), lint, nullString(sn.LicenseSPDX), sn.Signature,
		diff, checks, sn.ReviewRequired, string(sn.State), nullIDPtr(sn.SyncedBy), sn.CreatedAt, sn.ServiceUse, nullBoolPtr(sn.Redistribution))
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: snapshot of this digest exists", shared.ErrConflict)
		}
		return fmt.Errorf("create snapshot: %w", err)
	}
	return nil
}

func (r *ContentSourceRepository) oneSnapshot(row *sql.Row) (*cs.Snapshot, error) {
	sn, err := scanContentSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, cs.ErrSnapshotNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get snapshot: %w", err)
	}
	return sn, nil
}

// visibleSourcePredicate restricts snapshots to sources visible to $1.
const visibleSourcePredicate = `
	(tenant_id = $1 OR (tenant_id IS NULL AND EXISTS (
		SELECT 1 FROM content_sources p
		WHERE p.id = content_source_snapshots.source_id AND p.tenant_id IS NULL AND p.availability <> 'hidden')))`

// GetSnapshotVisible returns a snapshot of a source visible to tenantID.
func (r *ContentSourceRepository) GetSnapshotVisible(ctx context.Context, tenantID, sourceID, id shared.ID) (*cs.Snapshot, error) {
	return r.oneSnapshot(r.db.QueryRowContext(ctx, `SELECT `+contentSnapshotColumns+`
		FROM content_source_snapshots WHERE source_id = $2 AND id = $3 AND`+visibleSourcePredicate,
		tenantID.String(), sourceID.String(), id.String()))
}

// GetSnapshotUnscoped returns a snapshot by id.
func (r *ContentSourceRepository) GetSnapshotUnscoped(ctx context.Context, id shared.ID) (*cs.Snapshot, error) {
	return r.oneSnapshot(r.db.QueryRowContext(ctx, `SELECT `+contentSnapshotColumns+`
		FROM content_source_snapshots WHERE id = $1`, id.String()))
}

// FindSnapshotByDigestUnscoped returns the source's snapshot of digest.
func (r *ContentSourceRepository) FindSnapshotByDigestUnscoped(ctx context.Context, sourceID shared.ID, digest string) (*cs.Snapshot, error) {
	return r.oneSnapshot(r.db.QueryRowContext(ctx, `SELECT `+contentSnapshotColumns+`
		FROM content_source_snapshots WHERE source_id = $1 AND digest = $2`, sourceID.String(), digest))
}

// ListSnapshotsVisible lists a visible source's snapshots, newest first.
func (r *ContentSourceRepository) ListSnapshotsVisible(ctx context.Context, tenantID, sourceID shared.ID, limit, offset int) ([]*cs.Snapshot, int, error) {
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM content_source_snapshots
		WHERE source_id = $2 AND`+visibleSourcePredicate, tenantID.String(), sourceID.String()).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count snapshots: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+contentSnapshotColumns+`
		FROM content_source_snapshots WHERE source_id = $2 AND`+visibleSourcePredicate+`
		ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4`, tenantID.String(), sourceID.String(), limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list snapshots: %w", err)
	}
	defer rows.Close()
	out := []*cs.Snapshot{}
	for rows.Next() {
		sn, err := scanContentSnapshot(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("list snapshots: %w", err)
		}
		out = append(out, sn)
	}
	return out, total, rows.Err()
}

// SupersedeCandidatesUnscoped supersedes the source's other candidates.
func (r *ContentSourceRepository) SupersedeCandidatesUnscoped(ctx context.Context, sourceID, keep shared.ID) error {
	_, err := r.db.ExecContext(ctx, `UPDATE content_source_snapshots SET state = 'superseded'
		WHERE source_id = $1 AND state = 'candidate' AND id <> $2`, sourceID.String(), keep.String())
	if err != nil {
		return fmt.Errorf("supersede candidates: %w", err)
	}
	return nil
}

// Promote makes a candidate of the tenant's own source current.
func (r *ContentSourceRepository) Promote(ctx context.Context, tenantID, sourceID, snapshotID shared.ID, by *shared.ID, at time.Time,
	check func(*cs.Source, *cs.Snapshot) error) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		src, err := scanContentSource(tx.QueryRowContext(ctx, `SELECT `+contentSourceColumns+`
			FROM content_sources WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID.String(), sourceID.String()))
		if errors.Is(err, sql.ErrNoRows) {
			return cs.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lock rule source: %w", err)
		}
		sn, err := scanContentSnapshot(tx.QueryRowContext(ctx, `SELECT `+contentSnapshotColumns+`
			FROM content_source_snapshots WHERE tenant_id = $1 AND source_id = $2 AND id = $3 FOR UPDATE`,
			tenantID.String(), sourceID.String(), snapshotID.String()))
		if errors.Is(err, sql.ErrNoRows) {
			return cs.ErrSnapshotNotFound
		}
		if err != nil {
			return fmt.Errorf("lock snapshot: %w", err)
		}
		if sn.State != cs.StateCandidate {
			return cs.ErrNotCandidate
		}
		if check != nil {
			if err := check(src, sn); err != nil {
				return err
			}
		}
		return applyPromotionUnscoped(ctx, tx, src, sn.ID, by, at)
	})
}

// PromoteUnscoped is the sync worker's automatic promotion.
func (r *ContentSourceRepository) PromoteUnscoped(ctx context.Context, sourceID, snapshotID shared.ID, at time.Time) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		src, err := scanContentSource(tx.QueryRowContext(ctx, `SELECT `+contentSourceColumns+`
			FROM content_sources WHERE id = $1 FOR UPDATE`, sourceID.String()))
		if err != nil {
			return fmt.Errorf("lock rule source: %w", err)
		}
		var state string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM content_source_snapshots
			WHERE source_id = $1 AND id = $2 FOR UPDATE`, sourceID.String(), snapshotID.String()).Scan(&state); err != nil {
			return fmt.Errorf("lock snapshot: %w", err)
		}
		if cs.SnapshotState(state) != cs.StateCandidate {
			return cs.ErrNotCandidate
		}
		return applyPromotionUnscoped(ctx, tx, src, snapshotID, nil, at)
	})
}

// applyPromotionUnscoped runs inside a transaction that holds the source's
// row lock (taken with the tenant predicate by the caller).
func applyPromotionUnscoped(ctx context.Context, tx *sql.Tx, src *cs.Source, snapshotID shared.ID, by *shared.ID, at time.Time) error {
	if src.PreviousSnapshotID != nil && !src.PreviousSnapshotID.Equals(snapshotID) {
		if _, err := tx.ExecContext(ctx, `UPDATE content_source_snapshots SET state = 'superseded'
			WHERE source_id = $1 AND id = $2`, src.ID.String(), src.PreviousSnapshotID.String()); err != nil {
			return fmt.Errorf("supersede previous snapshot: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE content_source_snapshots
		SET state = 'promoted', promoted_by = $3, promoted_at = $4
		WHERE source_id = $1 AND id = $2`, src.ID.String(), snapshotID.String(), nullIDPtr(by), at); err != nil {
		return fmt.Errorf("promote snapshot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE content_source_snapshots SET state = 'superseded'
		WHERE source_id = $1 AND state = 'candidate' AND id <> $2 AND created_at < $3`,
		src.ID.String(), snapshotID.String(), at); err != nil {
		return fmt.Errorf("supersede older candidates: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE content_sources
		SET previous_snapshot_id = current_snapshot_id, current_snapshot_id = $2
		WHERE id = $1`, src.ID.String(), snapshotID.String()); err != nil {
		return fmt.Errorf("move current snapshot: %w", err)
	}
	return nil
}

// Rollback swaps current and previous of the tenant's own source.
func (r *ContentSourceRepository) Rollback(ctx context.Context, tenantID, sourceID shared.ID) (*cs.Source, error) {
	var out *cs.Source
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		src, err := scanContentSource(tx.QueryRowContext(ctx, `SELECT `+contentSourceColumns+`
			FROM content_sources WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID.String(), sourceID.String()))
		if errors.Is(err, sql.ErrNoRows) {
			return cs.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lock rule source: %w", err)
		}
		if src.PreviousSnapshotID == nil {
			return cs.ErrNoPrevious
		}
		if _, err := tx.ExecContext(ctx, `UPDATE content_sources
			SET current_snapshot_id = previous_snapshot_id, previous_snapshot_id = current_snapshot_id
			WHERE tenant_id = $1 AND id = $2`, tenantID.String(), sourceID.String()); err != nil {
			return fmt.Errorf("roll back rule source: %w", err)
		}
		src.CurrentSnapshotID, src.PreviousSnapshotID = src.PreviousSnapshotID, src.CurrentSnapshotID
		out = src
		return nil
	})
	return out, err
}

// Reject rejects a candidate of the tenant's own source.
func (r *ContentSourceRepository) Reject(ctx context.Context, tenantID, sourceID, snapshotID shared.ID, by *shared.ID, reason string, at time.Time) error {
	res, err := r.db.ExecContext(ctx, `UPDATE content_source_snapshots
		SET state = 'rejected', rejected_by = $4, rejected_at = $5, reject_reason = $6
		WHERE tenant_id = $1 AND source_id = $2 AND id = $3 AND state = 'candidate'`,
		tenantID.String(), sourceID.String(), snapshotID.String(), nullIDPtr(by), at, nullString(reason))
	if err != nil {
		return fmt.Errorf("reject snapshot: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	if _, err := r.GetSnapshotVisible(ctx, tenantID, sourceID, snapshotID); err != nil {
		return err
	}
	return cs.ErrNotCandidate
}

// ListCollectableUnscoped returns superseded or rejected tenant snapshots
// that are neither current nor previous.
func (r *ContentSourceRepository) ListCollectableUnscoped(ctx context.Context, before time.Time, limit int) ([]*cs.Snapshot, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+contentSnapshotColumns+`
		FROM content_source_snapshots
		WHERE scope = 'tenant' AND state IN ('superseded', 'rejected') AND created_at < $1
		  AND NOT EXISTS (SELECT 1 FROM content_sources c WHERE c.id = content_source_snapshots.source_id
		      AND (c.current_snapshot_id = content_source_snapshots.id OR c.previous_snapshot_id = content_source_snapshots.id))
		ORDER BY created_at LIMIT $2`, before, limit)
	if err != nil {
		return nil, fmt.Errorf("list collectable snapshots: %w", err)
	}
	defer rows.Close()
	out := []*cs.Snapshot{}
	for rows.Next() {
		sn, err := scanContentSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}

// DeleteSnapshotUnscoped deletes a snapshot that is still collectable.
func (r *ContentSourceRepository) DeleteSnapshotUnscoped(ctx context.Context, id shared.ID) (bool, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM content_source_snapshots s
		USING content_sources c
		WHERE s.id = $1 AND c.id = s.source_id AND s.state IN ('superseded', 'rejected')
		  AND s.id IS DISTINCT FROM c.current_snapshot_id AND s.id IS DISTINCT FROM c.previous_snapshot_id`, id.String())
	if err != nil {
		return false, fmt.Errorf("delete snapshot: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ListOrphanPacksUnscoped returns old rule source packs without a snapshot.
func (r *ContentSourceRepository) ListOrphanPacksUnscoped(ctx context.Context, before time.Time, limit int) ([]cs.OrphanPack, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT p.tenant_id, p.id FROM content_packs p
		WHERE p.source = 'git' AND p.created_at < $1
		  AND NOT EXISTS (SELECT 1 FROM content_source_snapshots s WHERE s.tenant_id = p.tenant_id AND s.content_pack_id = p.id)
		ORDER BY p.created_at LIMIT $2`, before, limit)
	if err != nil {
		return nil, fmt.Errorf("list orphan rule source packs: %w", err)
	}
	defer rows.Close()
	out := []cs.OrphanPack{}
	for rows.Next() {
		var tid, id string
		if err := rows.Scan(&tid, &id); err != nil {
			return nil, err
		}
		o := cs.OrphanPack{}
		o.TenantID, _ = shared.IDFromString(tid)
		o.PackID, _ = shared.IDFromString(id)
		out = append(out, o)
	}
	return out, rows.Err()
}
