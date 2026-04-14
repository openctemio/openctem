package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/domain/attachment"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// TenantStorageResolver resolves per-tenant storage configuration.
type TenantStorageResolver interface {
	GetTenantStorageConfig(ctx context.Context, tenantID string) (*attachment.StorageConfig, error)
}

// StorageFactory creates a FileStorage from a StorageConfig.
type StorageFactory func(cfg attachment.StorageConfig) (attachment.FileStorage, error)

// storageCache caches resolved FileStorage per tenant to avoid creating S3 clients per request.
type storageCacheEntry struct {
	storage  attachment.FileStorage
	provider string
	expiry   time.Time
}

const storageCacheTTL = 5 * time.Minute

// AttachmentService handles file upload/download/delete operations.
// It coordinates between the metadata repository (Postgres) and the
// file storage provider (local/S3/MinIO — selected per-tenant or globally).
type AttachmentService struct {
	repo            attachment.Repository
	storage         attachment.FileStorage  // Default provider (fallback)
	storageResolver TenantStorageResolver   // Optional: per-tenant config lookup
	storageFactory  StorageFactory          // Optional: creates provider from config
	storageCache    sync.Map                // tenantID → *storageCacheEntry
	logger          *logger.Logger
}

// NewAttachmentService creates a new service.
// The storage parameter is the DEFAULT provider used when tenants don't have
// a custom storage config.
func NewAttachmentService(
	repo attachment.Repository,
	storage attachment.FileStorage,
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

// resolveStorage returns the FileStorage and provider name for a given tenant.
// Falls back to the default provider if no tenant-specific config exists.
func (s *AttachmentService) resolveStorage(ctx context.Context, tenantID string) (attachment.FileStorage, string) {
	if s.storageResolver == nil || s.storageFactory == nil {
		return s.storage, "local"
	}
	// Check cache first
	if v, ok := s.storageCache.Load(tenantID); ok {
		entry := v.(*storageCacheEntry)
		if time.Now().Before(entry.expiry) {
			return entry.storage, entry.provider
		}
		s.storageCache.Delete(tenantID)
	}
	cfg, err := s.storageResolver.GetTenantStorageConfig(ctx, tenantID)
	if err != nil || cfg == nil {
		return s.storage, "local"
	}
	provider, err := s.storageFactory(*cfg)
	if err != nil {
		s.logger.Warn("failed to create tenant storage provider, using default",
			"tenant_id", tenantID, "provider", cfg.Provider, "error", err)
		return s.storage, "local"
	}
	// Cache the resolved provider
	s.storageCache.Store(tenantID, &storageCacheEntry{
		storage: provider, provider: cfg.Provider, expiry: time.Now().Add(storageCacheTTL),
	})
	return provider, cfg.Provider
}

// resolveStorageByProvider creates a FileStorage for a specific provider name.
// Used by Download/Delete to access files on the provider they were uploaded to.
func (s *AttachmentService) resolveStorageByProvider(ctx context.Context, tenantID, provider string) attachment.FileStorage {
	if provider == "" || provider == "local" {
		return s.storage
	}
	if s.storageFactory == nil || s.storageResolver == nil {
		s.logger.Warn("file stored on cloud but no storage factory configured",
			"tenant_id", tenantID, "provider", provider)
		return s.storage
	}
	// Check cache first
	cacheKey := tenantID + ":" + provider
	if v, ok := s.storageCache.Load(cacheKey); ok {
		entry := v.(*storageCacheEntry)
		if time.Now().Before(entry.expiry) {
			return entry.storage
		}
		s.storageCache.Delete(cacheKey)
	}
	cfg, err := s.storageResolver.GetTenantStorageConfig(ctx, tenantID)
	if err != nil || cfg == nil {
		s.logger.Warn("file stored on cloud but tenant storage config removed — file may be inaccessible",
			"tenant_id", tenantID, "provider", provider)
		return s.storage
	}
	p, err := s.storageFactory(*cfg)
	if err != nil {
		s.logger.Warn("failed to create storage provider for download",
			"tenant_id", tenantID, "provider", provider, "error", err)
		return s.storage
	}
	s.storageCache.Store(cacheKey, &storageCacheEntry{
		storage: p, provider: provider, expiry: time.Now().Add(storageCacheTTL),
	})
	return p
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
// Returns the attachment with its download URL.
func (s *AttachmentService) Upload(ctx context.Context, input UploadInput) (*attachment.Attachment, error) {
	// Validate
	if input.Size > attachment.MaxFileSize {
		return nil, fmt.Errorf("%w: file exceeds %dMB limit", attachment.ErrTooLarge, attachment.MaxFileSize/1024/1024)
	}

	ct := strings.ToLower(strings.TrimSpace(input.ContentType))
	if !attachment.AllowedContentTypes[ct] {
		return nil, fmt.Errorf("%w: %s is not an allowed file type", attachment.ErrUnsupported, ct)
	}

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant_id", shared.ErrValidation)
	}
	uploadedBy, err := shared.IDFromString(input.UploadedBy)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid uploaded_by", shared.ErrValidation)
	}

	// Read file into buffer for hashing + upload (file ≤ 10MB so safe in memory)
	buf, err := io.ReadAll(input.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Compute SHA-256 hash for dedup
	hash := sha256.Sum256(buf)
	contentHash := hex.EncodeToString(hash[:])

	// Dedup: check if same file already exists in this context (finding)
	if input.ContextType != "" && input.ContextID != "" {
		existing, _ := s.repo.FindByHash(ctx, tenantID, input.ContextType, input.ContextID, contentHash)
		if existing != nil {
			s.logger.Info("duplicate file skipped",
				"filename", input.Filename, "hash", contentHash[:12],
				"existing_id", existing.ID().String())
			return existing, nil // Return existing — no re-upload
		}
	}

	// Store file bytes via the storage provider (tenant-specific or default)
	store, providerName := s.resolveStorage(ctx, input.TenantID)
	storageKey, err := store.Upload(ctx, input.TenantID, input.Filename, ct, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("failed to upload file: %w", err)
	}

	// Create metadata record
	att := attachment.NewAttachment(
		tenantID, input.Filename, ct, input.Size, storageKey,
		uploadedBy, input.ContextType, input.ContextID,
	)
	att.SetContentHash(contentHash)
	att.SetStorageProvider(providerName)

	if err := s.repo.Create(ctx, att); err != nil {
		// Cleanup storage on DB failure
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

	store := s.resolveStorageByProvider(ctx, tenantID, att.StorageProvider())
	reader, _, err := store.Download(ctx, tenantID, att.StorageKey())
	if err != nil {
		return nil, "", "", err
	}

	return reader, att.ContentType(), att.Filename(), nil
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

	// Delete from storage first (idempotent)
	store := s.resolveStorageByProvider(ctx, tenantID, att.StorageProvider())
	_ = store.Delete(ctx, tenantID, att.StorageKey())

	// Delete metadata
	return s.repo.Delete(ctx, tid, aid)
}

// ListByContext returns all attachments linked to a specific context.
func (s *AttachmentService) ListByContext(ctx context.Context, tenantID shared.ID, contextType, contextID string) ([]*attachment.Attachment, error) {
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
func (s *AttachmentService) GetByID(ctx context.Context, tenantID, attachmentID string) (*attachment.Attachment, error) {
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
