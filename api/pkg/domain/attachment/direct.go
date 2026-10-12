package attachment

import (
	"context"
	"errors"
	"time"
)

// Short-lived direct downloads from a bucket
// (api/docs/rfcs/RFC-084-file-storage.md §3.4).

// DirectDownloadTTL is how long a signed download URL works.
const DirectDownloadTTL = 60 * time.Second

// ErrDirectDownloadUnavailable: the file cannot be handed out as a signed URL
// (turned off, a storage that cannot sign, a plain-HTTP endpoint); the
// caller downloads it through the API instead.
var ErrDirectDownloadUnavailable = errors.New("direct download unavailable")

// DirectDownloader is a storage that signs a short-lived GET for one object
// of a tenant. The URL is bound to that object (the tenant's namespace and
// the key), forces the given download name and type, and expires after ttl.
type DirectDownloader interface {
	PresignDownload(ctx context.Context, tenantID, storageKey, filename, contentType string, ttl time.Duration) (string, error)
}
