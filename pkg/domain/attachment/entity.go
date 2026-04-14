// Package attachment provides the domain model for file attachments.
//
// Attachments are tenant-scoped files uploaded by users and referenced from
// markdown fields (finding descriptions, retest notes, PoC code, etc.).
// The actual file bytes are stored via a pluggable FileStorage interface so
// each tenant can use a different backend (local disk, S3, MinIO, GCS, ...).
package attachment

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Attachment tracks metadata about an uploaded file. The binary content lives
// in the storage backend identified by StorageKey; this entity is the DB row.
type Attachment struct {
	id          shared.ID
	tenantID    shared.ID
	filename    string // original user-supplied filename (sanitized)
	contentType string // MIME type, e.g. "image/png"
	size        int64  // bytes
	storageKey  string // opaque key used by the FileStorage provider
	uploadedBy  shared.ID
	// Optional context linking: which entity this attachment belongs to.
	// Allows cascade cleanup when a finding/retest is deleted.
	contextType string    // "finding", "retest", "campaign", "" (general)
	contextID   string    // entity UUID (or empty for general uploads)
	contentHash     string // SHA-256 hash for dedup within a finding
	storageProvider string // "local", "s3", "minio" — where the file physically lives
	createdAt       time.Time
}

// NewAttachment creates a new Attachment metadata record.
func NewAttachment(
	tenantID shared.ID,
	filename, contentType string,
	size int64,
	storageKey string,
	uploadedBy shared.ID,
	contextType, contextID string,
) *Attachment {
	return &Attachment{
		id:          shared.NewID(),
		tenantID:    tenantID,
		filename:    filename,
		contentType: contentType,
		size:        size,
		storageKey:  storageKey,
		uploadedBy:  uploadedBy,
		contextType: contextType,
		contextID:   contextID,
		createdAt:   time.Now().UTC(),
	}
}

// ReconstituteAttachment recreates an Attachment from persistence.
func ReconstituteAttachment(
	id, tenantID shared.ID,
	filename, contentType string,
	size int64,
	storageKey string,
	uploadedBy shared.ID,
	contextType, contextID, contentHash, storageProvider string,
	createdAt time.Time,
) *Attachment {
	return &Attachment{
		id:              id,
		tenantID:        tenantID,
		filename:        filename,
		contentType:     contentType,
		size:            size,
		storageKey:      storageKey,
		uploadedBy:      uploadedBy,
		contextType:     contextType,
		contextID:       contextID,
		contentHash:     contentHash,
		storageProvider: storageProvider,
		createdAt:       createdAt,
	}
}

// Getters
func (a *Attachment) ID() shared.ID      { return a.id }
func (a *Attachment) TenantID() shared.ID { return a.tenantID }
func (a *Attachment) Filename() string    { return a.filename }
func (a *Attachment) ContentType() string { return a.contentType }
func (a *Attachment) Size() int64         { return a.size }
func (a *Attachment) StorageKey() string  { return a.storageKey }
func (a *Attachment) UploadedBy() shared.ID { return a.uploadedBy }
func (a *Attachment) ContextType() string { return a.contextType }
func (a *Attachment) ContextID() string    { return a.contextID }
func (a *Attachment) ContentHash() string     { return a.contentHash }
func (a *Attachment) StorageProvider() string  { return a.storageProvider }
func (a *Attachment) CreatedAt() time.Time    { return a.createdAt }

// SetContentHash sets the SHA-256 hash for dedup.
func (a *Attachment) SetContentHash(hash string) { a.contentHash = hash }

// SetStorageProvider records which backend stores this file.
func (a *Attachment) SetStorageProvider(provider string) { a.storageProvider = provider }

// URL returns the API-served download URL for this attachment.
func (a *Attachment) URL() string {
	return fmt.Sprintf("/api/v1/attachments/%s", a.id.String())
}

// MarkdownImageLink returns the markdown syntax to embed this attachment.
// For images it uses ![alt](url), for other files [filename](url).
func (a *Attachment) MarkdownLink() string {
	url := a.URL()
	if isImageContentType(a.contentType) {
		return fmt.Sprintf("![%s](%s)", a.filename, url)
	}
	return fmt.Sprintf("[%s](%s)", a.filename, url)
}

func isImageContentType(ct string) bool {
	switch ct {
	case "image/png", "image/jpeg", "image/gif", "image/webp":
		return true
	}
	return false
}
