package integration

import (
	"context"
	"fmt"
	"io"

	attachmentdom "github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Report templates and stored reports in the organization's file storage
// (api/docs/rfcs/RFC-084-file-storage.md): the same storage resolution as
// attachments (an organization's own bucket, failing closed), so the files
// are erased with the organization.

// ReportFiles is the pentest.FileStore over the attachment storage.
type ReportFiles struct{ svc *AttachmentService }

// NewReportFiles returns the report file store of svc.
func NewReportFiles(svc *AttachmentService) ReportFiles { return ReportFiles{svc: svc} }

var _ pentest.FileStore = ReportFiles{}

// Put stores a report file (at most pentest.MaxStoredReportBytes).
func (f ReportFiles) Put(ctx context.Context, tenantID shared.ID, filename, contentType string, data []byte) (string, string, error) {
	return f.svc.storeBlob(ctx, tenantID.String(), filename, contentType, data, pentest.MaxStoredReportBytes)
}

// Get reads a stored report file, at most maxBytes.
func (f ReportFiles) Get(ctx context.Context, tenantID shared.ID, provider, key string, maxBytes int64) ([]byte, error) {
	rc, err := f.svc.OpenBlob(ctx, tenantID.String(), provider, key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: stored file is larger than %d bytes", attachmentdom.ErrTooLarge, maxBytes)
	}
	return data, nil
}

// Delete removes a stored report file.
func (f ReportFiles) Delete(ctx context.Context, tenantID shared.ID, provider, key string) error {
	return f.svc.DeleteBlob(ctx, tenantID.String(), provider, key)
}

// blobDeletionBatch bounds one pass over the deletion queue.
const blobDeletionBatch = 500

// SetBlobDeletionQueue wires the queue of stored files whose rows were
// deleted; the retention sweep drains it.
func (s *AttachmentService) SetBlobDeletionQueue(q attachmentdom.BlobDeletionQueue) { s.blobQueue = q }

// drainBlobDeletions deletes queued files from their organization's storage.
// A file of an organization that no longer exists was erased with it; an
// organization bucket that cannot be reached keeps the entry for the next
// pass.
func (s *AttachmentService) drainBlobDeletions(ctx context.Context) int {
	if s.blobQueue == nil {
		return 0
	}
	queued, err := s.blobQueue.ListBlobDeletions(ctx, blobDeletionBatch)
	if err != nil {
		s.logger.Warn("stored file deletion queue unreadable", "error", logger.SanitizeError(err))
		return 0
	}
	done := 0
	for _, d := range queued {
		if ctx.Err() != nil {
			break
		}
		if d.TenantExists {
			if err := s.DeleteBlob(ctx, d.TenantID.String(), d.Provider, d.Key); err != nil {
				s.logger.Warn("stored file not deleted; retried on the next sweep",
					"tenant_id", d.TenantID.String(), "error", logger.SanitizeError(err))
				continue
			}
		}
		if err := s.blobQueue.DeleteBlobDeletion(ctx, d.ID); err != nil {
			s.logger.Warn("stored file deletion not dequeued", "error", logger.SanitizeError(err))
			continue
		}
		done++
	}
	return done
}
