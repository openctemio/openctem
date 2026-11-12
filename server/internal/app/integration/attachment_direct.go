package integration

import (
	"context"
	"errors"
	"time"

	attachmentdom "github.com/openctemio/openctem/api/pkg/domain/attachment"
)

// Short-lived direct downloads and storage metrics: design in
// api/docs/rfcs/RFC-084-file-storage.md.

// StorageMetrics counts storage policy outcomes (quota rejections, purges,
// scan results). Optional.
type StorageMetrics interface {
	StorageEvent(event string)
}

// SetMetrics wires the storage policy metrics.
func (s *AttachmentService) SetMetrics(m StorageMetrics) { s.metrics = m }

func (s *AttachmentService) event(name string) {
	if s.metrics != nil {
		s.metrics.StorageEvent(name)
	}
}

// SetDirectDownloads turns signed direct downloads from a bucket on or off
// (STORAGE_DIRECT_DOWNLOAD).
func (s *AttachmentService) SetDirectDownloads(on bool) { s.directDownloads = on }

// DirectDownloadURL returns a signed URL for the attachment's file in its
// bucket, valid for attachment.DirectDownloadTTL, and when it expires. The
// caller has already authorized the attachment (tenant-scoped lookup and
// context checks, as for a download through the API). A flagged file never
// gets one (it downloads through the API, with a confirmation that is
// audited); a storage that cannot sign, or direct downloads turned off,
// answer ErrDirectDownloadUnavailable.
func (s *AttachmentService) DirectDownloadURL(ctx context.Context, att *attachmentdom.Attachment) (string, time.Time, error) {
	if !s.directDownloads {
		return "", time.Time{}, attachmentdom.ErrDirectDownloadUnavailable
	}
	if att.ScanStatus() == attachmentdom.ScanInfected {
		return "", time.Time{}, attachmentdom.ErrInfected
	}
	tenantID := att.TenantID().String()
	store, err := s.resolveStorageByProvider(ctx, tenantID, att.StorageProvider())
	if err != nil {
		return "", time.Time{}, err
	}
	dd, ok := store.(attachmentdom.DirectDownloader)
	if !ok {
		return "", time.Time{}, attachmentdom.ErrDirectDownloadUnavailable
	}
	expires := time.Now().Add(attachmentdom.DirectDownloadTTL)
	url, err := dd.PresignDownload(ctx, tenantID, att.StorageKey(), att.Filename(), att.ContentType(), attachmentdom.DirectDownloadTTL)
	if err != nil {
		if errors.Is(err, attachmentdom.ErrDirectDownloadUnavailable) {
			return "", time.Time{}, err
		}
		s.logger.Warn("signing a direct download failed", "attachment_id", att.ID().String(), "error", err)
		return "", time.Time{}, attachmentdom.ErrDirectDownloadUnavailable
	}
	return url, expires, nil
}
