package postgres

// Web evidence of assets (docs/rfcs/RFC-081-web-evidence-screenshots.md).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webevidence"
)

// AssetWebEvidenceRepository stores captures of web assets.
type AssetWebEvidenceRepository struct {
	db *DB
}

// NewAssetWebEvidenceRepository creates the repository.
func NewAssetWebEvidenceRepository(db *DB) *AssetWebEvidenceRepository {
	return &AssetWebEvidenceRepository{db: db}
}

const webEvidenceColumns = `id, tenant_id, asset_id, url, final_url, status_code, title, server, content_type,
	snippet, snippet_truncated, tool, COALESCE(screenshot_key, ''), COALESCE(screenshot_provider, ''),
	COALESCE(screenshot_sha256, ''), COALESCE(screenshot_size, 0), COALESCE(screenshot_width, 0),
	COALESCE(screenshot_height, 0), screenshot_expires_at, captured_at, created_at`

func scanWebEvidence(s interface{ Scan(...any) error }) (webevidence.Record, error) {
	var r webevidence.Record
	var exp sql.NullTime
	err := s.Scan(&r.ID, &r.TenantID, &r.AssetID, &r.URL, &r.FinalURL, &r.StatusCode, &r.Title, &r.Server, &r.ContentType,
		&r.Snippet, &r.SnippetTruncated, &r.Tool, &r.ScreenshotKey, &r.ScreenshotProvider, &r.ScreenshotSHA256,
		&r.ScreenshotSize, &r.ScreenshotWidth, &r.ScreenshotHeight, &exp, &r.CapturedAt, &r.CreatedAt)
	r.ScreenshotExpiresAt = nullTimeValue(exp)
	return r, err
}

// Insert stores one capture of the asset and drops the asset's captures
// beyond the newest webevidence.MaxCapturesPerAsset. A dropped row's
// screenshot is queued for deletion by the table trigger
// (asset_web_evidence_orphans).
func (r *AssetWebEvidenceRepository) Insert(ctx context.Context, rec webevidence.Record) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var key, provider, sha, size, width, height, expires any
	if rec.ScreenshotKey != "" {
		key, provider, sha = rec.ScreenshotKey, rec.ScreenshotProvider, rec.ScreenshotSHA256
		size, width, height = rec.ScreenshotSize, rec.ScreenshotWidth, rec.ScreenshotHeight
		expires = rec.ScreenshotExpiresAt
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO asset_web_evidence (tenant_id, asset_id, url, final_url, status_code, title, server, content_type,
			snippet, snippet_truncated, tool, screenshot_key, screenshot_provider, screenshot_sha256, screenshot_size,
			screenshot_width, screenshot_height, screenshot_expires_at, captured_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
		rec.TenantID, rec.AssetID, rec.URL, rec.FinalURL, rec.StatusCode, rec.Title, rec.Server, rec.ContentType,
		rec.Snippet, rec.SnippetTruncated, rec.Tool, key, provider, sha, size, width, height, expires, rec.CapturedAt); err != nil {
		return fmt.Errorf("insert web evidence: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM asset_web_evidence
		 WHERE tenant_id = $1 AND asset_id = $2
		   AND id IN (SELECT id FROM asset_web_evidence
		               WHERE tenant_id = $1 AND asset_id = $2
		               ORDER BY captured_at DESC, created_at DESC
		               OFFSET $3)`,
		rec.TenantID, rec.AssetID, webevidence.MaxCapturesPerAsset); err != nil {
		return fmt.Errorf("prune web evidence: %w", err)
	}
	return tx.Commit()
}

// List returns the asset's captures, newest first.
func (r *AssetWebEvidenceRepository) List(ctx context.Context, tenantID, assetID shared.ID) ([]webevidence.Record, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+webEvidenceColumns+` FROM asset_web_evidence
		WHERE tenant_id = $1 AND asset_id = $2 ORDER BY captured_at DESC, created_at DESC LIMIT $3`,
		tenantID.String(), assetID.String(), webevidence.MaxCapturesPerAsset)
	if err != nil {
		return nil, fmt.Errorf("list web evidence: %w", err)
	}
	defer rows.Close()
	out := []webevidence.Record{}
	for rows.Next() {
		rec, err := scanWebEvidence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// Get returns one capture of the asset, or shared.ErrNotFound.
func (r *AssetWebEvidenceRepository) Get(ctx context.Context, tenantID, assetID shared.ID, id string) (*webevidence.Record, error) {
	if _, err := shared.IDFromString(id); err != nil {
		return nil, shared.ErrNotFound
	}
	rec, err := scanWebEvidence(r.db.QueryRowContext(ctx, `SELECT `+webEvidenceColumns+` FROM asset_web_evidence
		WHERE tenant_id = $1 AND asset_id = $2 AND id = $3`, tenantID.String(), assetID.String(), id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get web evidence: %w", err)
	}
	return &rec, nil
}

// ExpireScreenshots detaches up to limit screenshots past their expiry and
// returns them for deletion from storage. The capture text stays.
func (r *AssetWebEvidenceRepository) ExpireScreenshots(ctx context.Context, now time.Time, limit int) ([]webevidence.BlobRef, error) {
	rows, err := r.db.QueryContext(ctx, `
		UPDATE asset_web_evidence e
		   SET screenshot_key = NULL, screenshot_provider = NULL, screenshot_sha256 = NULL, screenshot_size = NULL,
		       screenshot_width = NULL, screenshot_height = NULL, screenshot_expires_at = NULL
		 FROM (SELECT id, tenant_id, screenshot_provider, screenshot_key FROM asset_web_evidence
		        WHERE screenshot_key IS NOT NULL AND screenshot_expires_at <= $1
		        ORDER BY screenshot_expires_at LIMIT $2 FOR UPDATE SKIP LOCKED) old
		 WHERE e.id = old.id
		RETURNING old.tenant_id, COALESCE(old.screenshot_provider, ''), old.screenshot_key`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("expire web screenshots: %w", err)
	}
	defer rows.Close()
	var out []webevidence.BlobRef
	for rows.Next() {
		var b webevidence.BlobRef
		if err := rows.Scan(&b.TenantID, &b.Provider, &b.Key); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// TakeOrphans removes up to limit queued screenshots of deleted rows and
// returns them for deletion from storage.
func (r *AssetWebEvidenceRepository) TakeOrphans(ctx context.Context, limit int) ([]webevidence.BlobRef, error) {
	rows, err := r.db.QueryContext(ctx, `
		DELETE FROM asset_web_evidence_orphans o
		 USING (SELECT tenant_id, storage_key FROM asset_web_evidence_orphans
		         ORDER BY queued_at LIMIT $1 FOR UPDATE SKIP LOCKED) q
		 WHERE o.tenant_id = q.tenant_id AND o.storage_key = q.storage_key
		RETURNING o.tenant_id, o.provider, o.storage_key`, limit)
	if err != nil {
		return nil, fmt.Errorf("take web evidence orphans: %w", err)
	}
	defer rows.Close()
	var out []webevidence.BlobRef
	for rows.Next() {
		var b webevidence.BlobRef
		if err := rows.Scan(&b.TenantID, &b.Provider, &b.Key); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DeleteOlderThan deletes captures recorded before the cutoff that no
// longer hold a screenshot.
func (r *AssetWebEvidenceRepository) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	res, err := execWithTimeout(ctx, r.db.DB, timeoutBatch, `DELETE FROM asset_web_evidence WHERE captured_at < $1 AND screenshot_key IS NULL`, before)
	if err != nil {
		return 0, fmt.Errorf("delete old web evidence: %w", err)
	}
	return res.RowsAffected()
}
