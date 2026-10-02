package storage

import (
	"fmt"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// s3HTTPClient builds the HTTP client every S3 request of a tenant-configured
// bucket goes through: the SSRF-guarded client, so the endpoint (or a
// redirect from it) cannot reach loopback, link-local/IMDS or — unless the
// operator allows private ranges — internal networks. A variable for tests.
var s3HTTPClient = func() *http.Client { return httpsec.SafeHTTPClient(5 * time.Minute) }

// checkS3Endpoint rejects a tenant endpoint before a client is built. A
// variable for tests.
var checkS3Endpoint = func(endpoint string) error {
	_, err := httpsec.ValidateURL(endpoint)
	return err
}

// NewTenantStorageFactory returns the factory the attachment service uses to
// build the backend a tenant selected in its storage settings.
//
// Where files live on the API server is operator configuration
// (STORAGE_PROVIDER / STORAGE_LOCAL_PATH), never tenant input: "local" always
// means the operator's local storage, whatever base_path a stored config
// carries. A tenant may instead point attachments at its own S3/MinIO bucket,
// with its own keys, through the SSRF-guarded client.
func NewTenantStorageFactory(operatorLocal attachment.FileStorage) func(cfg attachment.StorageConfig) (attachment.FileStorage, error) {
	return func(cfg attachment.StorageConfig) (attachment.FileStorage, error) {
		switch cfg.Provider {
		case attachment.ProviderLocal:
			return operatorLocal, nil
		case attachment.ProviderS3, attachment.ProviderMinIO:
			return NewS3Storage(cfg.Bucket, cfg.Region, cfg.Endpoint, cfg.AccessKey, cfg.SecretKey)
		default:
			return nil, fmt.Errorf("unsupported tenant storage provider: %s", cfg.Provider)
		}
	}
}
