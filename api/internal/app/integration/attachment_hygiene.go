package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	attachmentdom "github.com/openctemio/openctem/api/pkg/domain/attachment"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Image hygiene and malware scanning of attachments: design in
// api/docs/rfcs/RFC-084-file-storage.md.

// sanitizeImageUpload reads an image upload (bounded by MaxFileSize: images
// are the one kind held in memory, to rewrite them), removes its metadata
// and checks its dimensions. Returns the bytes to store and the SHA-256 of
// the bytes received.
func sanitizeImageUpload(r io.Reader, ct string) (io.Reader, string, error) {
	data, err := io.ReadAll(io.LimitReader(r, attachmentdom.MaxFileSize+1))
	if err != nil {
		return nil, "", fmt.Errorf("read image: %w", err)
	}
	if int64(len(data)) > attachmentdom.MaxFileSize {
		return nil, "", fmt.Errorf("%w: file exceeds %dMB limit", attachmentdom.ErrTooLarge, attachmentdom.MaxFileSize/1024/1024)
	}
	sum := sha256.Sum256(data)
	clean, err := attachmentdom.SanitizeImage(data, ct)
	if err != nil {
		return nil, "", err
	}
	return bytes.NewReader(clean), hex.EncodeToString(sum[:]), nil
}

// scanBatch bounds one scan pass.
const scanBatch = 50

// SetMalwareScanner turns on malware scanning: new uploads start pending and
// ScanPending scans them; infected files are audited in their tenant.
func (s *AttachmentService) SetMalwareScanner(scanner attachmentdom.Scanner, repo attachmentdom.ScanRepository, audit AttachmentAuditLogger) {
	s.scanner, s.scanRepo = scanner, repo
	if audit != nil {
		s.audit = audit
	}
}

// ScanPending scans up to one batch of pending attachments, each read from
// its own tenant's storage. When the scanner cannot be reached the pass stops
// and the files stay pending for the next one. Returns how many it scanned.
func (s *AttachmentService) ScanPending(ctx context.Context) (int, error) {
	if s.scanner == nil || s.scanRepo == nil {
		return 0, nil
	}
	pending, err := s.scanRepo.ListPendingScans(ctx, scanBatch)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, att := range pending {
		if ctx.Err() != nil {
			return done, ctx.Err()
		}
		status, result, err := s.scanOne(ctx, att)
		if errors.Is(err, attachmentdom.ErrScannerUnavailable) {
			return done, err
		}
		ok, err := s.scanRepo.SetScanResult(ctx, att.TenantID(), att.ID(), status, result)
		if err != nil {
			return done, err
		}
		if !ok {
			continue // deleted meanwhile
		}
		done++
		if status == attachmentdom.ScanInfected {
			s.auditInfected(ctx, att, result)
		}
	}
	return done, nil
}

func (s *AttachmentService) scanOne(ctx context.Context, att *attachmentdom.Attachment) (attachmentdom.ScanStatus, string, error) {
	tenantID := att.TenantID().String()
	store, err := s.resolveStorageByProvider(ctx, tenantID, att.StorageProvider())
	if err != nil {
		return attachmentdom.ScanError, "file storage unavailable", nil
	}
	rc, _, err := store.Download(ctx, tenantID, att.StorageKey())
	if err != nil {
		return attachmentdom.ScanError, "file not found in storage", nil
	}
	defer func() { _ = rc.Close() }()
	verdict, err := s.scanner.Scan(ctx, rc)
	switch {
	case errors.Is(err, attachmentdom.ErrScannerUnavailable):
		s.logger.Warn("malware scanner unavailable; files stay pending", "error", logger.SanitizeError(err))
		return "", "", err
	case err != nil:
		return attachmentdom.ScanError, err.Error(), nil
	case verdict.Infected:
		return attachmentdom.ScanInfected, verdict.Signature, nil
	default:
		return attachmentdom.ScanClean, "", nil
	}
}

func (s *AttachmentService) auditInfected(ctx context.Context, att *attachmentdom.Attachment, signature string) {
	s.logger.Warn("malware scanner flagged an attachment",
		"tenant_id", att.TenantID().String(), "attachment_id", att.ID().String(), "signature", signature)
	if s.audit == nil {
		return
	}
	event := auditapp.NewSuccessEvent(auditdom.ActionAttachmentMalwareDetected, auditdom.ResourceTypeAttachment, att.ID().String()).
		WithResourceName(att.Filename()).
		WithMessage("The malware scanner flagged an evidence file; it is kept and downloads only after a confirmation").
		WithMetadata("signature", signature).
		WithMetadata("sha256", att.ContentHash()).
		WithMetadata("context_type", att.ContextType()).
		WithMetadata("context_id", att.ContextID())
	actx := auditapp.AuditContext{TenantID: att.TenantID().String(), ActorEmail: retentionAuditActor}
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("audit malware detection failed", "attachment_id", att.ID().String(), "error", err)
	}
}
