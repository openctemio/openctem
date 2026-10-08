package attachment

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"regexp"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
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

	// EraseTenant deletes every object stored for the tenant, its whole
	// namespace (including files no attachment row names), and returns how
	// many it removed. Idempotent. tenantID must be a canonical tenant id;
	// anything else is refused, so a bad value can never widen the delete to
	// another tenant or the whole store.
	EraseTenant(ctx context.Context, tenantID string) (int, error)
}

// ValidateTenantNamespace checks that tenantID is a canonical tenant id (a
// lowercase UUID), the only value a storage namespace may be erased by.
func ValidateTenantNamespace(tenantID string) error {
	id, err := shared.IDFromString(tenantID)
	if err != nil || id.IsZero() || id.String() != tenantID {
		return fmt.Errorf("refusing to erase storage namespace %q: not a tenant id", tenantID)
	}
	return nil
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

// Storage providers a tenant may select.
const (
	ProviderLocal = "local" // the operator's storage (STORAGE_LOCAL_PATH)
	ProviderS3    = "s3"
	ProviderMinIO = "minio"
)

var (
	tenantRegionPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	tenantBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

// ValidateTenantChoice checks a storage configuration submitted by a tenant
// administrator. A tenant chooses between the operator's storage ("local",
// whose location is operator configuration and cannot be set here) and its
// own S3-compatible bucket with its own keys. Where an endpoint resolves to is
// checked separately by the SSRF guard.
func (c StorageConfig) ValidateTenantChoice() error {
	switch c.Provider {
	case ProviderLocal:
		if c.BasePath != "" {
			return fmt.Errorf("base_path cannot be set by a tenant: the storage location is server configuration (STORAGE_LOCAL_PATH)")
		}
		return nil
	case ProviderS3, ProviderMinIO:
	default:
		return fmt.Errorf("provider must be 'local', 's3', or 'minio'")
	}
	if c.BasePath != "" {
		return fmt.Errorf("base_path does not apply to %s", c.Provider)
	}
	if !tenantBucketPattern.MatchString(c.Bucket) {
		return fmt.Errorf("a valid bucket name is required")
	}
	if c.Region != "" && !tenantRegionPattern.MatchString(c.Region) {
		return fmt.Errorf("region is invalid")
	}
	if c.AccessKey == "" || c.SecretKey == "" {
		return fmt.Errorf("access_key and secret_key are required")
	}
	if c.Provider == ProviderMinIO && c.Endpoint == "" {
		return fmt.Errorf("endpoint is required for minio")
	}
	if c.Endpoint != "" {
		u, err := url.Parse(c.Endpoint)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
			return fmt.Errorf("endpoint must be an http or https URL")
		}
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("endpoint must not contain credentials, a query or a fragment")
		}
	}
	return nil
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
	MaxFileSize     = 10 * 1024 * 1024 // 10MB per file
	MaxTotalPerItem = 50 * 1024 * 1024 // 50MB total per finding/retest
)

// AllowedContentTypes is the whitelist of MIME types accepted for upload.
var AllowedContentTypes = map[string]bool{
	// Images
	"image/png":  true,
	"image/jpeg": true,
	"image/gif":  true,
	"image/webp": true,
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
