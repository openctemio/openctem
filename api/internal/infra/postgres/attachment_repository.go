package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AttachmentRepository handles attachment metadata persistence.
type AttachmentRepository struct {
	db *DB
}

// NewAttachmentRepository creates a new repository.
func NewAttachmentRepository(db *DB) *AttachmentRepository {
	return &AttachmentRepository{db: db}
}

const attachmentCols = `id, tenant_id, filename, content_type, size, storage_key,
	uploaded_by, context_type, context_id, content_hash, storage_provider, created_at,
	scan_status, scan_result`

func (r *AttachmentRepository) Create(ctx context.Context, att *attachment.Attachment) error {
	query := `INSERT INTO attachments (` + attachmentCols + `)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	_, err := r.db.ExecContext(ctx, query,
		att.ID().String(),
		att.TenantID().String(),
		att.Filename(),
		att.ContentType(),
		att.Size(),
		att.StorageKey(),
		att.UploadedBy().String(),
		att.ContextType(),
		att.ContextID(),
		att.ContentHash(),
		att.StorageProvider(),
		att.CreatedAt(),
		string(att.ScanStatus()),
		att.ScanResult(),
	)
	if err != nil {
		return fmt.Errorf("failed to create attachment: %w", err)
	}
	return nil
}

func (r *AttachmentRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*attachment.Attachment, error) {
	query := `SELECT ` + attachmentCols + ` FROM attachments WHERE tenant_id = $1 AND id = $2`
	att, err := scanAttachmentRow(r.db.QueryRowContext(ctx, query, tenantID.String(), id.String()).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, attachment.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get attachment: %w", err)
	}
	return att, nil
}

func (r *AttachmentRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	query := `DELETE FROM attachments WHERE tenant_id = $1 AND id = $2`
	result, err := r.db.ExecContext(ctx, query, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to delete attachment: %w", err)
	}
	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
	if rows == 0 {
		return attachment.ErrNotFound
	}
	return nil
}

func (r *AttachmentRepository) ListByContext(ctx context.Context, tenantID shared.ID, contextType, contextID string) ([]*attachment.Attachment, error) {
	query := `SELECT ` + attachmentCols + ` FROM attachments
		WHERE tenant_id = $1 AND context_type = $2 AND context_id = $3
		ORDER BY created_at ASC`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), contextType, contextID)
	if err != nil {
		return nil, fmt.Errorf("failed to list attachments: %w", err)
	}
	defer rows.Close()

	var result []*attachment.Attachment
	for rows.Next() {
		att, err := scanAttachmentRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		result = append(result, att)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate attachments: %w", err)
	}
	return result, nil
}

// FindByHash checks for duplicate file in the same context.
func (r *AttachmentRepository) FindByHash(ctx context.Context, tenantID shared.ID, contextType, contextID, contentHash string) (*attachment.Attachment, error) {
	if contentHash == "" || contextID == "" {
		return nil, nil
	}
	query := `SELECT ` + attachmentCols + ` FROM attachments
		WHERE tenant_id = $1 AND context_type = $2 AND context_id = $3 AND content_hash = $4
		LIMIT 1`
	att, err := scanAttachmentRow(r.db.QueryRowContext(ctx, query, tenantID.String(), contextType, contextID, contentHash).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No duplicate
		}
		return nil, err
	}
	return att, nil
}

// LinkToContext bulk-updates context for orphan attachments (uploaded before finding existed).
// Security: only updates attachments owned by uploaderID with empty context_id.
func (r *AttachmentRepository) LinkToContext(ctx context.Context, tenantID shared.ID, ids []shared.ID, uploaderID shared.ID, contextType, contextID string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	// One array parameter: an IN list of one parameter per id failed past
	// the bind-parameter limit.
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}
	query := `UPDATE attachments
		SET context_type = $3, context_id = $4
		WHERE tenant_id = $1 AND uploaded_by = $2
		AND (context_id = '' OR context_id IS NULL)
		AND id = ANY($5::uuid[])`
	args := []any{tenantID.String(), uploaderID.String(), contextType, contextID, pq.Array(idStrs)}
	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to link attachments: %w", err)
	}
	return result.RowsAffected()
}

// TotalSize is the number of bytes the tenant's attachments hold (the
// storage quota counts it). Served by idx_attachments_tenant.
func (r *AttachmentRepository) TotalSize(ctx context.Context, tenantID shared.ID) (int64, error) {
	var total int64
	err := r.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(size), 0) FROM attachments WHERE tenant_id = $1`, tenantID.String()).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("sum attachment sizes: %w", err)
	}
	return total, nil
}
