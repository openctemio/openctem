package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Retention queries for attachments (api/docs/rfcs/RFC-084-file-storage.md).
// They run for the system sweep across tenants, but a parent only counts
// when it is in the attachment's own tenant: a finding id of another tenant
// never keeps a file alive, and every delete names the row's tenant.

// attachmentContextUUID is the attachment's context_id as a uuid, or NULL
// when it is not one (a malformed id names no parent, so it is an orphan).
const attachmentContextUUID = `CASE WHEN a.context_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN a.context_id::uuid END`

// attachmentParentMissing is true for an evidence row whose finding or
// campaign no longer exists in its tenant.
const attachmentParentMissing = `(a.context_id <> '' AND (
	(a.context_type IN ('finding', 'retest') AND NOT EXISTS (
		SELECT 1 FROM findings f WHERE f.tenant_id = a.tenant_id AND f.id = ` + attachmentContextUUID + `))
	OR (a.context_type = 'campaign' AND NOT EXISTS (
		SELECT 1 FROM pentest_campaigns c WHERE c.tenant_id = a.tenant_id AND c.id = ` + attachmentContextUUID + `))))`

// attachmentPurgeable is true for a row the policy purges ($1 orphaned
// before, $2 unlinked before; NULL turns a class off; $3 the contexts).
const attachmentPurgeable = `a.context_type = ANY($3) AND (
	(a.orphaned_at IS NOT NULL AND a.orphaned_at < $1 AND ` + attachmentParentMissing + `)
	OR (a.context_id = '' AND a.created_at < $2))`

var _ attachment.RetentionRepository = (*AttachmentRepository)(nil)

// MarkOrphans stamps orphaned_at on evidence whose parent is gone and clears
// it where the parent exists (again).
func (r *AttachmentRepository) MarkOrphans(ctx context.Context, now time.Time) (int64, int64, error) {
	res, err := execWithTimeout(ctx, r.db.DB, timeoutBatch, `UPDATE attachments a SET orphaned_at = $1
		WHERE a.orphaned_at IS NULL AND a.context_type = ANY($2) AND `+attachmentParentMissing,
		now, pq.Array(attachment.RetentionContexts))
	if err != nil {
		return 0, 0, fmt.Errorf("mark orphaned attachments: %w", err)
	}
	marked, _ := res.RowsAffected()
	res, err = execWithTimeout(ctx, r.db.DB, timeoutBatch, `UPDATE attachments a SET orphaned_at = NULL
		WHERE a.orphaned_at IS NOT NULL AND NOT `+attachmentParentMissing)
	if err != nil {
		return marked, 0, fmt.Errorf("clear orphaned attachments: %w", err)
	}
	cleared, _ := res.RowsAffected()
	return marked, cleared, nil
}

func nullCutoff(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: !t.IsZero()}
}

// ListPurgeable returns at most limit rows the policy purges, oldest first.
func (r *AttachmentRepository) ListPurgeable(ctx context.Context, policy attachment.RetentionPolicy, limit int) ([]attachment.PurgeCandidate, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+attachmentColsA+`
		FROM attachments a
		WHERE `+attachmentPurgeable+`
		ORDER BY a.created_at
		LIMIT $4`,
		nullCutoff(policy.OrphanedBefore), nullCutoff(policy.UnlinkedBefore),
		pq.Array(attachment.RetentionContexts), limit)
	if err != nil {
		return nil, fmt.Errorf("list purgeable attachments: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []attachment.PurgeCandidate
	for rows.Next() {
		att, err := scanAttachmentRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		reason := attachment.PurgeParentDeleted
		if att.ContextID() == "" {
			reason = attachment.PurgeNeverLinked
		}
		out = append(out, attachment.PurgeCandidate{Attachment: att, Reason: reason})
	}
	return out, rows.Err()
}

// DeletePurgeable deletes the row only while the policy still purges it.
func (r *AttachmentRepository) DeletePurgeable(ctx context.Context, tenantID, id shared.ID, policy attachment.RetentionPolicy) (bool, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM attachments a
		WHERE a.tenant_id = $4 AND a.id = $5 AND `+attachmentPurgeable,
		nullCutoff(policy.OrphanedBefore), nullCutoff(policy.UnlinkedBefore),
		pq.Array(attachment.RetentionContexts), tenantID.String(), id.String())
	if err != nil {
		return false, fmt.Errorf("delete purgeable attachment: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return n == 1, nil
}

// attachmentColsA is attachmentCols qualified with the alias a.
const attachmentColsA = `a.id, a.tenant_id, a.filename, a.content_type, a.size, a.storage_key,
	a.uploaded_by, a.context_type, a.context_id, a.content_hash, a.storage_provider, a.created_at,
	a.scan_status, a.scan_result`

// scanAttachmentRow reads one row of attachmentCols. sql.ErrNoRows is
// returned as is.
func scanAttachmentRow(scan func(dest ...any) error) (*attachment.Attachment, error) {
	var (
		idStr, tenantStr, filename, contentType, storageKey string
		contextType, contextID, scanStatus, scanResult      string
		uploadedByStr, contentHash, storageProvider         sql.NullString
		size                                                int64
		createdAt                                           time.Time
	)
	if err := scan(&idStr, &tenantStr, &filename, &contentType, &size, &storageKey,
		&uploadedByStr, &contextType, &contextID, &contentHash, &storageProvider, &createdAt,
		&scanStatus, &scanResult); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("scan attachment: %w", err)
	}
	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("attachment id: %w", err)
	}
	tid, err := shared.IDFromString(tenantStr)
	if err != nil {
		return nil, fmt.Errorf("attachment tenant id: %w", err)
	}
	uploadedBy, _ := shared.IDFromString(uploadedByStr.String)
	att := attachment.ReconstituteAttachment(id, tid, filename, contentType, size, storageKey,
		uploadedBy, contextType, contextID, contentHash.String, storageProvider.String, createdAt)
	att.SetScan(attachment.ScanStatus(scanStatus), scanResult)
	return att, nil
}
