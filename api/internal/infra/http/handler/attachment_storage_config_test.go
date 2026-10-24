package handler

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
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
	got, err = tenantStorageConfigFromRequest(attachment.StorageConfig{Provider: "s3", Bucket: "evidence"}, existing)
	if err != nil || got.AccessKey != "OLDAK" || got.SecretKey != "OLDSK" {
		t.Fatalf("edit keeping keys: got %+v, %v", got, err)
	}
}

// Stored keys follow only an unchanged location: a new endpoint, bucket,
// region or provider needs its own keys, and is refused without them.
func TestTenantStorageConfigFromRequest_LocationChangeNeedsNewKeys(t *testing.T) {
	existing := &attachment.StorageConfig{Provider: "minio", Bucket: "evidence", Region: "eu-west-1",
		Endpoint: "https://8.8.8.8:9000", AccessKey: "OLDAK", SecretKey: "OLDSK"}
	for name, req := range map[string]attachment.StorageConfig{
		"endpoint": {Provider: "minio", Bucket: "evidence", Region: "eu-west-1", Endpoint: "https://8.8.4.4:9000"},
		"bucket":   {Provider: "minio", Bucket: "evidence2", Region: "eu-west-1", Endpoint: "https://8.8.8.8:9000"},
		"region":   {Provider: "minio", Bucket: "evidence", Region: "us-east-1", Endpoint: "https://8.8.8.8:9000"},
		"provider": {Provider: "s3", Bucket: "evidence", Region: "eu-west-1"},
	} {
		got, err := tenantStorageConfigFromRequest(req, existing)
		if err == nil {
			t.Errorf("%s change without keys must be refused, got %+v", name, got)
		}
		req.AccessKey, req.SecretKey = "NEWAK", "NEWSK"
		got, err = tenantStorageConfigFromRequest(req, existing)
		if err != nil || got.AccessKey != "NEWAK" || got.SecretKey != "NEWSK" {
			t.Errorf("%s change with keys: got %+v, %v", name, got, err)
		}
	}
	same := attachment.StorageConfig{Provider: "minio", Bucket: "evidence", Region: "eu-west-1", Endpoint: "https://8.8.8.8:9000/"}
	got, err := tenantStorageConfigFromRequest(same, existing)
	if err != nil || got.AccessKey != "OLDAK" || got.SecretKey != "OLDSK" {
		t.Errorf("same location keeps keys: got %+v, %v", got, err)
	}
}
