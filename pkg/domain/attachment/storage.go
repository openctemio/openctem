package attachment

import (
	"context"
	"fmt"
	"io"
)

// FileStorage is the pluggable interface for file persistence.
// Each tenant can use a different implementation (local, S3, MinIO, GCS, ...)
// configured via tenant_settings.storage JSONB.
//
// Implementations MUST:
//   - Namespace files by tenantID to prevent cross-tenant access
//   - Return ErrNotFound for missing keys (not generic errors)
//   - Be safe for concurrent use
type FileStorage interface {
	// Upload stores file content and returns an opaque storage key.
	// The key is used for Download/Delete and stored in the attachments table.
	Upload(ctx context.Context, tenantID, filename, contentType string, reader io.Reader) (storageKey string, err error)

	// Download returns a reader for the file content.
	// Caller is responsible for closing the reader.
	Download(ctx context.Context, tenantID, storageKey string) (io.ReadCloser, string, error)

	// Delete removes a file from storage. Idempotent — no error if already gone.
	Delete(ctx context.Context, tenantID, storageKey string) error
}

// StorageConfig holds provider-specific configuration.
// Stored in tenant_settings.storage JSONB so each tenant can use a different backend.
type StorageConfig struct {
	Provider  string `json:"provider"`   // "local", "s3", "minio", "gcs"
	Bucket    string `json:"bucket"`     // S3/MinIO bucket name
	Region    string `json:"region"`     // AWS region
	Endpoint  string `json:"endpoint"`   // Custom endpoint (MinIO)
	BasePath  string `json:"base_path"`  // Local filesystem base path
	AccessKey string `json:"access_key"` // Encrypted via tenant credentials
	SecretKey string `json:"secret_key"` // Encrypted via tenant credentials
}

// DefaultStorageConfig returns a local filesystem config for development.
func DefaultStorageConfig() StorageConfig {
	return StorageConfig{
		Provider: "local",
		BasePath: "/data/attachments",
	}
}

// Errors
var (
	ErrNotFound    = fmt.Errorf("attachment not found")
	ErrTooLarge    = fmt.Errorf("file too large")
	ErrUnsupported = fmt.Errorf("unsupported file type")
)

// Validation constants
const (
	MaxFileSize     = 10 * 1024 * 1024  // 10MB per file
	MaxTotalPerItem = 50 * 1024 * 1024  // 50MB total per finding/retest
)

// AllowedContentTypes is the whitelist of MIME types accepted for upload.
var AllowedContentTypes = map[string]bool{
	// Images
	"image/png":     true,
	"image/jpeg":    true,
	"image/gif":     true,
	"image/webp":    true,
	// SVG removed: can contain inline <script> tags → stored XSS risk
	// Documents
	"application/pdf": true,
	"text/plain":      true,
	"text/markdown":   true,
	"text/csv":        true,
	// Archives (pentest artifacts)
	"application/zip":    true,
	"application/x-gzip": true,
	// HTTP archives
	"application/har+json": true,
	"application/json":     true,
	// Videos (screen recordings)
	"video/mp4":  true,
	"video/webm": true,
}
