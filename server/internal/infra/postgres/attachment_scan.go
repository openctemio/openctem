package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ attachment.ScanRepository = (*AttachmentRepository)(nil)

// ListPendingScans returns at most limit attachments waiting for the malware
// scanner, oldest first (idx_attachments_scan_pending). Across tenants: the
// scan worker is a system job and handles each row in its own tenant.
func (r *AttachmentRepository) ListPendingScans(ctx context.Context, limit int) ([]*attachment.Attachment, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+attachmentCols+` FROM attachments
		WHERE scan_status = 'pending' ORDER BY created_at LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending scans: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*attachment.Attachment
	for rows.Next() {
		att, err := scanAttachmentRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, att)
	}
	return out, rows.Err()
}

// SetScanResult records the scan outcome of a pending row of the tenant.
func (r *AttachmentRepository) SetScanResult(ctx context.Context, tenantID, id shared.ID, status attachment.ScanStatus, result string) (bool, error) {
	if len(result) > 255 {
		result = result[:255]
	}
	res, err := r.db.ExecContext(ctx, `UPDATE attachments SET scan_status = $3, scan_result = $4, scanned_at = now()
		WHERE tenant_id = $1 AND id = $2 AND scan_status = 'pending'`,
		tenantID.String(), id.String(), string(status), result)
	if err != nil {
		return false, fmt.Errorf("record scan result: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return n == 1, nil
}
