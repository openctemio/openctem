package integration

import (
	"context"
	"errors"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	attachmentdom "github.com/openctemio/openctem/api/pkg/domain/attachment"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Retention of evidence files: design in
// api/docs/rfcs/RFC-084-file-storage.md, operation in
// api/docs/architecture/file-storage.md.

// retentionBatch bounds one sweep; the next tick takes the rest.
const retentionBatch = 500

// retentionAuditActor is the actor recorded for purges.
const retentionAuditActor = "system"

// AttachmentAuditLogger records audit events (the audit service).
type AttachmentAuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// RetentionSettings are the retention periods. Zero turns a class off.
type RetentionSettings struct {
	// OrphanGrace: how long evidence stays after its finding or campaign
	// was found deleted (STORAGE_ORPHAN_GRACE_DAYS).
	OrphanGrace time.Duration
	// UnlinkedRetention: how long an upload never linked to a finding or
	// campaign stays (STORAGE_UNLINKED_RETENTION_HOURS).
	UnlinkedRetention time.Duration
}

// SetRetention wires the retention sweep: its repository, periods and the
// audit log purges are recorded in.
func (s *AttachmentService) SetRetention(repo attachmentdom.RetentionRepository, settings RetentionSettings, audit AttachmentAuditLogger) {
	s.retentionRepo = repo
	s.retention = settings
	s.audit = audit
}

// SweepRetention marks evidence whose parent is gone and purges what the
// retention periods allow: the stored file, then its row, one tenant-scoped
// operation per file, each audited in the file's tenant. A file whose
// storage cannot be reached now is skipped and retried on the next sweep.
// Returns how many files it purged.
func (s *AttachmentService) SweepRetention(ctx context.Context) (int, error) {
	if s.retentionRepo == nil {
		return 0, nil
	}
	now := time.Now().UTC()
	marked, cleared, err := s.retentionRepo.MarkOrphans(ctx, now)
	if err != nil {
		return 0, err
	}
	if marked > 0 || cleared > 0 {
		s.logger.Info("attachment retention: orphan marks", "marked", marked, "cleared", cleared)
	}
	policy := attachmentdom.RetentionPolicy{}
	if s.retention.OrphanGrace > 0 {
		policy.OrphanedBefore = now.Add(-s.retention.OrphanGrace)
	}
	if s.retention.UnlinkedRetention > 0 {
		policy.UnlinkedBefore = now.Add(-s.retention.UnlinkedRetention)
	}
	if policy.OrphanedBefore.IsZero() && policy.UnlinkedBefore.IsZero() {
		return 0, nil
	}
	candidates, err := s.retentionRepo.ListPurgeable(ctx, policy, retentionBatch)
	if err != nil {
		return 0, err
	}
	purged := 0
	for _, c := range candidates {
		if ctx.Err() != nil {
			return purged, ctx.Err()
		}
		ok, err := s.purgeOne(ctx, c, policy)
		if err != nil {
			s.logger.Warn("attachment retention: purge failed",
				"tenant_id", c.Attachment.TenantID().String(), "attachment_id", c.Attachment.ID().String(),
				"error", logger.SanitizeError(err))
			continue
		}
		if ok {
			purged++
		}
	}
	if purged > 0 {
		s.logger.Info("attachment retention: files purged", "count", purged)
	}
	return purged, nil
}

// purgeOne removes one file and its row. The storage is resolved first, so a
// file in an unreachable organization bucket keeps its row and is retried.
// The row goes before the file, and only if it is still purgeable: a file
// linked (or whose parent came back) in the meantime is never deleted.
func (s *AttachmentService) purgeOne(ctx context.Context, c attachmentdom.PurgeCandidate, policy attachmentdom.RetentionPolicy) (bool, error) {
	att := c.Attachment
	tenantID := att.TenantID().String()
	store, err := s.resolveStorageByProvider(ctx, tenantID, att.StorageProvider())
	if err != nil {
		return false, err
	}
	deleted, err := s.retentionRepo.DeletePurgeable(ctx, att.TenantID(), att.ID(), policy)
	if err != nil || !deleted {
		return false, err
	}
	fileErr := store.Delete(ctx, tenantID, att.StorageKey())
	if fileErr != nil && !errors.Is(fileErr, attachmentdom.ErrNotFound) {
		// The row is gone; the bytes stay in the organization's namespace
		// until it is erased. Logged so an operator can remove them.
		s.logger.Error("attachment retention: row purged but file not deleted",
			"tenant_id", tenantID, "attachment_id", att.ID().String(),
			"storage_key", att.StorageKey(), "error", logger.SanitizeError(fileErr))
	}
	s.auditPurge(ctx, c, fileErr == nil || errors.Is(fileErr, attachmentdom.ErrNotFound))
	return true, nil
}

func (s *AttachmentService) auditPurge(ctx context.Context, c attachmentdom.PurgeCandidate, fileDeleted bool) {
	if s.audit == nil {
		return
	}
	att := c.Attachment
	msg := "Evidence file purged: its finding or campaign was deleted"
	if c.Reason == attachmentdom.PurgeNeverLinked {
		msg = "Evidence file purged: it was never linked to a finding or campaign"
	}
	event := auditapp.NewSuccessEvent(auditdom.ActionAttachmentPurged, auditdom.ResourceTypeAttachment, att.ID().String()).
		WithResourceName(att.Filename()).
		WithMessage(msg).
		WithMetadata("reason", string(c.Reason)).
		WithMetadata("content_type", att.ContentType()).
		WithMetadata("size", att.Size()).
		WithMetadata("sha256", att.ContentHash()).
		WithMetadata("context_type", att.ContextType()).
		WithMetadata("context_id", att.ContextID()).
		WithMetadata("file_deleted", fileDeleted)
	actx := auditapp.AuditContext{TenantID: att.TenantID().String(), ActorEmail: retentionAuditActor}
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("attachment retention: audit failed", "attachment_id", att.ID().String(), "error", err)
	}
}
