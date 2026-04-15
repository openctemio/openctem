package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/attachment"
	"github.com/openctemio/api/pkg/domain/shared"
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
	uploaded_by, context_type, context_id, content_hash, storage_provider, created_at`

func (r *AttachmentRepository) Create(ctx context.Context, att *attachment.Attachment) error {
	query := `INSERT INTO attachments (` + attachmentCols + `)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

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
	)
	if err != nil {
		return fmt.Errorf("failed to create attachment: %w", err)
	}
	return nil
}

func (r *AttachmentRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*attachment.Attachment, error) {
	query := `SELECT ` + attachmentCols + ` FROM attachments WHERE tenant_id = $1 AND id = $2`

	var (
		idStr, tenantStr, filename, contentType, storageKey string
		uploadedByStr, contextType, contextID               string
		contentHash, storageProvider                        sql.NullString
		size                                                int64
		createdAt                                           time.Time
	)

	err := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String()).Scan(
		&idStr, &tenantStr, &filename, &contentType, &size, &storageKey,
		&uploadedByStr, &contextType, &contextID, &contentHash, &storageProvider, &createdAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, attachment.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get attachment: %w", err)
	}

	parsedID, _ := shared.IDFromString(idStr)
	parsedTenantID, _ := shared.IDFromString(tenantStr)
	parsedUploadedBy, _ := shared.IDFromString(uploadedByStr)

	return attachment.ReconstituteAttachment(
		parsedID, parsedTenantID,
		filename, contentType, size, storageKey,
		parsedUploadedBy, contextType, contextID, contentHash.String, storageProvider.String,
		createdAt,
	), nil
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
		var (
			idStr, tenantStr, filename, contentType, storageKey string
			uploadedByStr, ctxType, ctxID                       string
			hashVal, providerVal                                sql.NullString
			size                                                int64
			createdAt                                           time.Time
		)
		if err := rows.Scan(
			&idStr, &tenantStr, &filename, &contentType, &size, &storageKey,
			&uploadedByStr, &ctxType, &ctxID, &hashVal, &providerVal, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan attachment: %w", err)
		}

		parsedID, _ := shared.IDFromString(idStr)
		parsedTenantID, _ := shared.IDFromString(tenantStr)
		parsedUploadedBy, _ := shared.IDFromString(uploadedByStr)

		result = append(result, attachment.ReconstituteAttachment(
			parsedID, parsedTenantID,
			filename, contentType, size, storageKey,
			parsedUploadedBy, ctxType, ctxID, hashVal.String, providerVal.String,
			createdAt,
		))
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
	var (
		idStr, tenantStr, filename, ct, storageKey string
		uploadedByStr, ctxType, ctxID              string
		hashVal                                    sql.NullString
		size                                       int64
		createdAt                                  time.Time
	)
	var provVal sql.NullString
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), contextType, contextID, contentHash).Scan(
		&idStr, &tenantStr, &filename, &ct, &size, &storageKey,
		&uploadedByStr, &ctxType, &ctxID, &hashVal, &provVal, &createdAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No duplicate
		}
		return nil, err
	}
	parsedID, _ := shared.IDFromString(idStr)
	parsedTenantID, _ := shared.IDFromString(tenantStr)
	parsedUploadedBy, _ := shared.IDFromString(uploadedByStr)
	return attachment.ReconstituteAttachment(
		parsedID, parsedTenantID, filename, ct, size, storageKey,
		parsedUploadedBy, ctxType, ctxID, hashVal.String, provVal.String, createdAt,
	), nil
}

// LinkToContext bulk-updates context for orphan attachments (uploaded before finding existed).
// Security: only updates attachments owned by uploaderID with empty context_id.
func (r *AttachmentRepository) LinkToContext(ctx context.Context, tenantID shared.ID, ids []shared.ID, uploaderID shared.ID, contextType, contextID string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+4)
	args = append(args, tenantID.String(), uploaderID.String(), contextType, contextID)
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+5)
		args = append(args, id.String())
	}
	query := fmt.Sprintf(`UPDATE attachments
		SET context_type = $3, context_id = $4
		WHERE tenant_id = $1 AND uploaded_by = $2
		AND (context_id = '' OR context_id IS NULL)
		AND id IN (%s)`, strings.Join(placeholders, ","))
	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to link attachments: %w", err)
	}
	return result.RowsAffected()
}
