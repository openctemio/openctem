package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	attachmentdom "github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TenantStorageResolver resolves per-tenant storage configuration.
type TenantStorageResolver interface {
	GetTenantStorageConfig(ctx context.Context, tenantID string) (*attachmentdom.StorageConfig, error)
}

// StorageFactory creates a FileStorage from a StorageConfig.
type StorageFactory func(cfg attachmentdom.StorageConfig) (attachmentdom.FileStorage, error)

// storageCache caches resolved FileStorage per tenant to avoid creating S3 clients per request.
type storageCacheEntry struct {
	storage  attachmentdom.FileStorage
	provider string
	expiry   time.Time
}

const storageCacheTTL = 5 * time.Minute

// AttachmentService handles file upload/download/delete operations.
// It coordinates between the metadata repository (Postgres) and the
// file storage provider (local/S3/MinIO — selected per-tenant or globally).
type AttachmentService struct {
	repo            attachmentdom.Repository
	storage         attachmentdom.FileStorage // Default provider (fallback)
	storageResolver TenantStorageResolver     // Optional: per-tenant config lookup
	storageFactory  StorageFactory            // Optional: creates provider from config
	storageCache    sync.Map                  // tenantID → *storageCacheEntry
	quotaBytes      int64                     // per-tenant total of attachment bytes; 0 = no quota
	quotaSource     QuotaSource
	scanner         attachmentdom.Scanner     // optional malware scanner; nil = off
	scanRepo        attachmentdom.ScanRepository
	retentionRepo   attachmentdom.RetentionRepository
	blobQueue       attachmentdom.BlobDeletionQueue
	metrics         StorageMetrics
	directDownloads bool
	retention       RetentionSettings
	audit           AttachmentAuditLogger
	logger          *logger.Logger
}

// SetTenantQuota bounds the bytes one organization's attachments may hold
// (STORAGE_TENANT_QUOTA_MB). 0 or less: no quota.
func (s *AttachmentService) SetTenantQuota(bytes int64) { s.quotaBytes = bytes }

// QuotaSource answers an organization's storage quota in bytes, or
// unlimited (no quota). A quota of 0 refuses every upload.
type QuotaSource func(ctx context.Context, tenantID shared.ID) (bytes int64, unlimited bool, err error)

// SetTenantQuotaSource makes the quota a decision per upload: the
// organization's storage limit, else the platform default set in the
// console (or STORAGE_TENANT_QUOTA_MB). It replaces the fixed quota.
func (s *AttachmentService) SetTenantQuotaSource(f QuotaSource) { s.quotaSource = f }

// InvalidateTenantStorage drops the cached storage providers of a tenant, so
// a changed storage setting applies to the next upload, not after the cache
// expires.
func (s *AttachmentService) InvalidateTenantStorage(tenantID string) {
	s.storageCache.Range(func(k, _ any) bool {
		if key, ok := k.(string); ok && (key == tenantID || strings.HasPrefix(key, tenantID+":")) {
			s.storageCache.Delete(k)
		}
		return true
	})
}

// NewAttachmentService creates a new service.
// The storage parameter is the DEFAULT provider used when tenants don't have
// a custom storage config.
func NewAttachmentService(
	repo attachmentdom.Repository,
	storage attachmentdom.FileStorage,
	log *logger.Logger,
) *AttachmentService {
	return &AttachmentService{
		repo:    repo,
		storage: storage,
		logger:  log.With("service", "attachment"),
	}
}

// SetTenantStorageResolver enables per-tenant storage configuration.
// When set, each upload/download first checks tenant config before falling back to default.
func (s *AttachmentService) SetTenantStorageResolver(resolver TenantStorageResolver, factory StorageFactory) {
	s.storageResolver = resolver
	s.storageFactory = factory
}

// resolveStorage returns the FileStorage new files of a tenant go to, and its
// provider name. A tenant without its own bucket uses the server-wide
// storage ("local"). A tenant that chose its own bucket gets that bucket or
// an error, never the server-wide storage: its files must not land on a
// shared disk because its bucket's keys broke or its setting is unreadable.
func (s *AttachmentService) resolveStorage(ctx context.Context, tenantID string) (attachmentdom.FileStorage, string, error) {
	if s.storageResolver == nil || s.storageFactory == nil {
		return s.storage, attachmentdom.ProviderLocal, nil
	}
	if v, ok := s.storageCache.Load(tenantID); ok {
		entry := v.(*storageCacheEntry)
		if time.Now().Before(entry.expiry) {
			return entry.storage, entry.provider, nil
		}
		s.storageCache.Delete(tenantID)
	}
	cfg, err := s.storageResolver.GetTenantStorageConfig(ctx, tenantID)
	if err != nil {
		s.logger.Warn("tenant storage setting unreadable", "tenant_id", tenantID, "error", err)
		return nil, "", attachmentdom.ErrStorageUnavailable
	}
	if cfg == nil || cfg.Provider == "" || cfg.Provider == attachmentdom.ProviderLocal {
		return s.storage, attachmentdom.ProviderLocal, nil
	}
	provider, err := s.storageFactory(*cfg)
	if err != nil {
		s.logger.Warn("tenant storage provider cannot be built",
			"tenant_id", tenantID, "provider", cfg.Provider, "error", err)
		return nil, "", attachmentdom.ErrStorageUnavailable
	}
	s.storageCache.Store(tenantID, &storageCacheEntry{
		storage: provider, provider: cfg.Provider, expiry: time.Now().Add(storageCacheTTL),
	})
	return provider, cfg.Provider, nil
}

// resolveStorageByProvider returns the FileStorage a file recorded with the
// given provider lives on. A file in the tenant's own bucket is read from
// that bucket or not at all: when the setting is gone (or no longer names
// a bucket) the answer is ErrStorageUnavailable, never the server-wide
// storage.
func (s *AttachmentService) resolveStorageByProvider(ctx context.Context, tenantID, provider string) (attachmentdom.FileStorage, error) {
	if provider == "" || provider == attachmentdom.ProviderLocal {
		return s.storage, nil
	}
	if s.storageFactory == nil || s.storageResolver == nil {
		s.logger.Warn("file stored in a tenant bucket but no storage factory configured",
			"tenant_id", tenantID, "provider", provider)
		return nil, attachmentdom.ErrStorageUnavailable
	}
	cacheKey := tenantID + ":" + provider
	if v, ok := s.storageCache.Load(cacheKey); ok {
		entry := v.(*storageCacheEntry)
		if time.Now().Before(entry.expiry) {
			return entry.storage, nil
		}
		s.storageCache.Delete(cacheKey)
	}
	cfg, err := s.storageResolver.GetTenantStorageConfig(ctx, tenantID)
	if err != nil || cfg == nil || cfg.Provider == "" || cfg.Provider == attachmentdom.ProviderLocal {
		s.logger.Warn("file stored in a tenant bucket that is no longer configured",
			"tenant_id", tenantID, "provider", provider)
		return nil, attachmentdom.ErrStorageUnavailable
	}
	p, err := s.storageFactory(*cfg)
	if err != nil {
		s.logger.Warn("tenant storage provider cannot be built",
			"tenant_id", tenantID, "provider", provider, "error", err)
		return nil, attachmentdom.ErrStorageUnavailable
	}
	s.storageCache.Store(cacheKey, &storageCacheEntry{
		storage: p, provider: provider, expiry: time.Now().Add(storageCacheTTL),
	})
	return p, nil
}

// errFileTooLarge stops a streamed upload that passes the file size limit.
var errFileTooLarge = errors.New("file exceeds the size limit")

// cappedReader counts what passes through and fails once more than max
// bytes went by, so the size limit holds whatever the client declared.
type cappedReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, errFileTooLarge
	}
	return n, err
}

// checkQuota refuses an upload of size bytes that would take the tenant's
// attachments over the quota.
func (s *AttachmentService) checkQuota(ctx context.Context, tenantID shared.ID, size int64) error {
	quota := s.quotaBytes
	if s.quotaSource != nil {
		q, unlimited, err := s.quotaSource(ctx, tenantID)
		if err != nil {
			// Fail closed: an unknown quota is not "no quota".
			return fmt.Errorf("read storage quota: %w", err)
		}
		if unlimited {
			return nil
		}
		quota = q
	} else if quota <= 0 {
		return nil
	}
	used, err := s.repo.TotalSize(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("read storage usage: %w", err)
	}
	if used+size > quota {
		s.event("quota_rejected")
		return fmt.Errorf("%w: %d MiB used of %d MiB", attachmentdom.ErrQuotaExceeded, used>>20, quota>>20)
	}
	return nil
}

// UploadInput contains the parameters for uploading a file.
type UploadInput struct {
	TenantID    string
	Filename    string
	ContentType string
	Size        int64
	Reader      io.Reader
	UploadedBy  string
	ContextType string // "finding", "retest", "campaign", or ""
	ContextID   string // UUID of the context entity, or ""
}

// Upload validates, stores the file, and creates a metadata record.
// The content is streamed to the storage (hashed and counted on the way,
// never held in memory); the recorded size is what was read, not what the
// client declared. Returns the attachment with its download URL.
//
//nolint:cyclop // validation, quota, store, dedup and record, one step each
func (s *AttachmentService) Upload(ctx context.Context, input UploadInput) (*attachmentdom.Attachment, error) {
	tooLarge := fmt.Errorf("%w: file exceeds %dMB limit", attachmentdom.ErrTooLarge, attachmentdom.MaxFileSize/1024/1024)
	if input.Size > attachmentdom.MaxFileSize {
		return nil, tooLarge
	}

	ct := strings.ToLower(strings.TrimSpace(input.ContentType))
	if !attachmentdom.AllowedContentTypes[ct] {
		return nil, fmt.Errorf("%w: %s is not an allowed file type", attachmentdom.ErrUnsupported, ct)
	}

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant_id", shared.ErrValidation)
	}
	uploadedBy, err := shared.IDFromString(input.UploadedBy)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid uploaded_by", shared.ErrValidation)
	}
	// Refuse early on the declared size; checked again on the bytes read.
	if err := s.checkQuota(ctx, tenantID, max(input.Size, 0)); err != nil {
		return nil, err
	}

	// Images lose their metadata (EXIF/GPS, XMP, comments) and are refused
	// past the pixel limit; the hash of the bytes received is kept for the
	// audit event.
	originalHash := ""
	if attachmentdom.IsImageType(ct) {
		reader, orig, err := sanitizeImageUpload(input.Reader, ct)
		if err != nil {
			return nil, err
		}
		input.Reader, originalHash = reader, orig
	}

	store, providerName, err := s.resolveStorage(ctx, input.TenantID)
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	counted := &cappedReader{r: input.Reader, max: attachmentdom.MaxFileSize}
	storageKey, err := store.Upload(ctx, input.TenantID, input.Filename, ct, io.TeeReader(counted, hasher))
	if counted.n > attachmentdom.MaxFileSize {
		if err == nil {
			_ = store.Delete(ctx, input.TenantID, storageKey)
		}
		return nil, tooLarge
	}
	if err != nil {
		return nil, fmt.Errorf("failed to upload file: %w", err)
	}
	size := counted.n
	contentHash := hex.EncodeToString(hasher.Sum(nil))

	// Dedup: the same file already in this context is returned instead.
	if input.ContextType != "" && input.ContextID != "" {
		existing, _ := s.repo.FindByHash(ctx, tenantID, input.ContextType, input.ContextID, contentHash)
		if existing != nil {
			_ = store.Delete(ctx, input.TenantID, storageKey)
			s.logger.Info("duplicate file skipped",
				"filename", input.Filename, "hash", contentHash[:12],
				"existing_id", existing.ID().String())
			return existing, nil
		}
	}
	if err := s.checkQuota(ctx, tenantID, size); err != nil {
		_ = store.Delete(ctx, input.TenantID, storageKey)
		return nil, err
	}

	att := attachmentdom.NewAttachment(
		tenantID, input.Filename, ct, size, storageKey,
		uploadedBy, input.ContextType, input.ContextID,
	)
	att.SetContentHash(contentHash)
	att.SetStorageProvider(providerName)
	if originalHash != "" && originalHash != contentHash {
		att.SetOriginalContentHash(originalHash)
	}
	if s.scanner != nil {
		att.SetScan(attachmentdom.ScanPending, "")
	}

	if err := s.repo.Create(ctx, att); err != nil {
		_ = store.Delete(ctx, input.TenantID, storageKey)
		return nil, fmt.Errorf("failed to save attachment metadata: %w", err)
	}

	s.logger.Info("attachment uploaded",
		"id", att.ID().String(),
		"filename", att.Filename(),
		"size", att.Size(),
		"content_type", ct,
		"tenant_id", input.TenantID,
	)

	return att, nil
}

// Download retrieves file content by attachment ID.
// Returns the reader (caller must close), content type, and filename.
func (s *AttachmentService) Download(ctx context.Context, tenantID, attachmentID string) (io.ReadCloser, string, string, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: invalid tenant_id", shared.ErrValidation)
	}
	aid, err := shared.IDFromString(attachmentID)
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: invalid attachment_id", shared.ErrValidation)
	}

	att, err := s.repo.GetByID(ctx, tid, aid)
	if err != nil {
		return nil, "", "", err
	}

	store, err := s.resolveStorageByProvider(ctx, tenantID, att.StorageProvider())
	if err != nil {
		return nil, "", "", err
	}
	reader, _, err := store.Download(ctx, tenantID, att.StorageKey())
	if err != nil {
		return nil, "", "", err
	}

	return reader, att.ContentType(), att.Filename(), nil
}

// ReadAttachment returns an attachment's record and at most maxBytes of its
// content, tenant-scoped. A larger file answers ErrTooLarge. Used to embed
// evidence images in reports.
func (s *AttachmentService) ReadAttachment(ctx context.Context, tenantID, attachmentID string, maxBytes int64) (*attachmentdom.Attachment, []byte, error) {
	att, err := s.GetByID(ctx, tenantID, attachmentID)
	if err != nil {
		return nil, nil, err
	}
	if att.Size() > maxBytes {
		return nil, nil, attachmentdom.ErrTooLarge
	}
	if att.ScanStatus() == attachmentdom.ScanInfected {
		return nil, nil, attachmentdom.ErrInfected
	}
	store, err := s.resolveStorageByProvider(ctx, tenantID, att.StorageProvider())
	if err != nil {
		return nil, nil, err
	}
	reader, _, err := store.Download(ctx, tenantID, att.StorageKey())
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = reader.Close() }()
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, nil, attachmentdom.ErrTooLarge
	}
	return att, data, nil
}

// Delete removes both the file and its metadata record.
func (s *AttachmentService) Delete(ctx context.Context, tenantID, attachmentID string) error {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant_id", shared.ErrValidation)
	}
	aid, err := shared.IDFromString(attachmentID)
	if err != nil {
		return fmt.Errorf("%w: invalid attachment_id", shared.ErrValidation)
	}

	att, err := s.repo.GetByID(ctx, tid, aid)
	if err != nil {
		return err
	}

	// Delete from storage first (idempotent). A file whose bucket cannot be
	// reached keeps its row, so the deletion can be retried.
	store, err := s.resolveStorageByProvider(ctx, tenantID, att.StorageProvider())
	if err != nil {
		return err
	}
	if err := store.Delete(ctx, tenantID, att.StorageKey()); err != nil {
		return fmt.Errorf("delete stored file: %w", err)
	}

	// Delete metadata
	return s.repo.Delete(ctx, tid, aid)
}

// EraseTenant deletes every stored file of the tenant: its whole namespace on
// the server-wide storage and, when the tenant points attachments at its own
// S3/MinIO bucket, its namespace there too. Organization deletion calls it
// before and after removing the tenant's rows. It fails if any backend cannot
// be erased (or the tenant's storage setting cannot be read), so the caller
// can refuse the deletion and keep the obligation. Idempotent.
func (s *AttachmentService) EraseTenant(ctx context.Context, tenantID string) (int, error) {
	if err := attachmentdom.ValidateTenantNamespace(tenantID); err != nil {
		return 0, err
	}
	// Drop cached providers of this tenant, whatever happens next.
	s.InvalidateTenantStorage(tenantID)

	erased, err := s.storage.EraseTenant(ctx, tenantID)
	if err != nil {
		return erased, fmt.Errorf("erase server storage: %w", err)
	}
	if s.storageResolver == nil || s.storageFactory == nil {
		return erased, nil
	}
	cfg, err := s.storageResolver.GetTenantStorageConfig(ctx, tenantID)
	if err != nil {
		return erased, fmt.Errorf("read tenant storage setting: %w", err)
	}
	if cfg == nil || cfg.Provider == "" || cfg.Provider == attachmentdom.ProviderLocal {
		return erased, nil
	}
	own, err := s.storageFactory(*cfg)
	if err != nil {
		return erased, fmt.Errorf("open tenant storage %s: %w", cfg.Provider, err)
	}
	n, err := own.EraseTenant(ctx, tenantID)
	erased += n
	if err != nil {
		return erased, fmt.Errorf("erase tenant storage %s: %w", cfg.Provider, err)
	}
	return erased, nil
}

// ListByContext returns all attachments linked to a specific context.
func (s *AttachmentService) ListByContext(ctx context.Context, tenantID shared.ID, contextType, contextID string) ([]*attachmentdom.Attachment, error) {
	return s.repo.ListByContext(ctx, tenantID, contextType, contextID)
}

// LinkToContext links orphan attachments (uploaded with empty context_id) to a finding.
// Security: only the uploader can link their own attachments.
func (s *AttachmentService) LinkToContext(ctx context.Context, tenantID, uploaderID string, attachmentIDs []string, contextType, contextID string) (int64, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid tenant_id", shared.ErrValidation)
	}
	uid, err := shared.IDFromString(uploaderID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid uploader_id", shared.ErrValidation)
	}
	ids := make([]shared.ID, 0, len(attachmentIDs))
	for _, idStr := range attachmentIDs {
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return s.repo.LinkToContext(ctx, tid, ids, uid, contextType, contextID)
}

// GetByID retrieves attachment metadata (for URL generation, etc).
func (s *AttachmentService) GetByID(ctx context.Context, tenantID, attachmentID string) (*attachmentdom.Attachment, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant_id", shared.ErrValidation)
	}
	aid, err := shared.IDFromString(attachmentID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid attachment_id", shared.ErrValidation)
	}
	return s.repo.GetByID(ctx, tid, aid)
}

// StoreBlob stores platform-generated content (no attachment row) in the
// tenant's storage and returns its key and provider. Used for web evidence
// screenshots (RFC-081): they are served by their own data-scoped route,
// never by /api/v1/attachments.
func (s *AttachmentService) StoreBlob(ctx context.Context, tenantID, filename, contentType string, data []byte) (string, string, error) {
	return s.storeBlob(ctx, tenantID, filename, contentType, data, attachmentdom.MaxFileSize)
}

func (s *AttachmentService) storeBlob(ctx context.Context, tenantID, filename, contentType string, data []byte, maxBytes int64) (string, string, error) {
	if _, err := shared.IDFromString(tenantID); err != nil {
		return "", "", fmt.Errorf("%w: invalid tenant_id", shared.ErrValidation)
	}
	if int64(len(data)) > maxBytes {
		return "", "", attachmentdom.ErrTooLarge
	}
	store, provider, err := s.resolveStorage(ctx, tenantID)
	if err != nil {
		return "", "", err
	}
	key, err := store.Upload(ctx, tenantID, filename, contentType, bytes.NewReader(data))
	if err != nil {
		return "", "", fmt.Errorf("store blob: %w", err)
	}
	return key, provider, nil
}

// OpenBlob opens content stored with StoreBlob.
func (s *AttachmentService) OpenBlob(ctx context.Context, tenantID, provider, key string) (io.ReadCloser, error) {
	store, err := s.resolveStorageByProvider(ctx, tenantID, provider)
	if err != nil {
		return nil, err
	}
	rc, _, err := store.Download(ctx, tenantID, key)
	return rc, err
}

// DeleteBlob deletes content stored with StoreBlob (idempotent).
func (s *AttachmentService) DeleteBlob(ctx context.Context, tenantID, provider, key string) error {
	store, err := s.resolveStorageByProvider(ctx, tenantID, provider)
	if err != nil {
		return err
	}
	return store.Delete(ctx, tenantID, key)
}
