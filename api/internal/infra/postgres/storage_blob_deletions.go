package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ attachment.BlobDeletionQueue = (*AttachmentRepository)(nil)

// ListBlobDeletions returns at most limit queued file deletions, oldest
// first, and whether each one's organization still exists.
func (r *AttachmentRepository) ListBlobDeletions(ctx context.Context, limit int) ([]attachment.BlobDeletion, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `SELECT d.id, d.tenant_id, d.storage_provider, d.storage_key,
			EXISTS (SELECT 1 FROM tenants t WHERE t.id = d.tenant_id)
		FROM storage_blob_deletions d ORDER BY d.id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list blob deletions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []attachment.BlobDeletion
	for rows.Next() {
		var (
			d   attachment.BlobDeletion
			tid string
		)
		if err := rows.Scan(&d.ID, &tid, &d.Provider, &d.Key, &d.TenantExists); err != nil {
			return nil, fmt.Errorf("scan blob deletion: %w", err)
		}
		if d.TenantID, err = shared.IDFromString(tid); err != nil {
			continue
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteBlobDeletion removes a handled entry from the queue.
func (r *AttachmentRepository) DeleteBlobDeletion(ctx context.Context, id int64) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM storage_blob_deletions WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete blob deletion: %w", err)
	}
	return nil
}
