package handler

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/attachment"
)

// A tenant admin could store {"provider":"local","base_path":"/anywhere"}
// (directories created and uploads written wherever it pointed) or an S3
// endpoint on loopback / IMDS / an internal service (blind SSRF on every
// upload, download and delete).
func TestTenantStorageConfigFromRequest_RejectsServerPathsAndInternalEndpoints(t *testing.T) {
	keys := func(c attachment.StorageConfig) attachment.StorageConfig {
		c.AccessKey, c.SecretKey = "AK", "SK"
		return c
	}
	bad := map[string]attachment.StorageConfig{
		"local base_path":      {Provider: "local", BasePath: "/etc/cron.d"},
		"loopback endpoint":    keys(attachment.StorageConfig{Provider: "minio", Bucket: "ev", Endpoint: "http://127.0.0.1:9000"}),
		"metadata endpoint":    keys(attachment.StorageConfig{Provider: "s3", Bucket: "ev", Endpoint: "http://169.254.169.254"}),
		"localhost endpoint":   keys(attachment.StorageConfig{Provider: "minio", Bucket: "ev", Endpoint: "http://localhost:9000"}),
		"s3 without keys":      {Provider: "s3", Bucket: "ev"},
		"unsupported provider": {Provider: "gcs"},
		"base_path on s3":      keys(attachment.StorageConfig{Provider: "s3", Bucket: "ev", BasePath: "/tmp"}),
	}
	for name, req := range bad {
		if _, err := tenantStorageConfigFromRequest(req, nil); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func TestTenantStorageConfigFromRequest_Legitimate(t *testing.T) {
	got, err := tenantStorageConfigFromRequest(attachment.StorageConfig{Provider: "local", Bucket: "ignored"}, nil)
	if err != nil || got != (attachment.StorageConfig{Provider: "local"}) {
		t.Fatalf("local: got %+v, %v", got, err)
	}

	got, err = tenantStorageConfigFromRequest(attachment.StorageConfig{Provider: "s3", Bucket: "evidence", Region: "eu-west-1", AccessKey: "AK", SecretKey: "SK"}, nil)
	if err != nil || got.Bucket != "evidence" {
		t.Fatalf("aws s3: got %+v, %v", got, err)
	}

	// Editing the same provider without re-entering keys keeps the stored keys.
	existing := &attachment.StorageConfig{Provider: "s3", Bucket: "evidence", AccessKey: "OLDAK", SecretKey: "OLDSK"}
	got, err = tenantStorageConfigFromRequest(attachment.StorageConfig{Provider: "s3", Bucket: "evidence2", Region: "eu-west-1"}, existing)
	if err != nil || got.AccessKey != "OLDAK" || got.SecretKey != "OLDSK" || got.Bucket != "evidence2" {
		t.Fatalf("edit keeping keys: got %+v, %v", got, err)
	}
}
