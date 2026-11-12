package config

import (
	"strings"
	"testing"
)

func TestValidateStorage_R2RefusesSSE(t *testing.T) {
	for _, ep := range []string{
		"https://abc123.r2.cloudflarestorage.com",
		"https://abc123.eu.r2.cloudflarestorage.com",
		"https://abc123.fedramp.r2.cloudflarestorage.com",
	} {
		for _, tc := range []struct{ sse, kms string }{{"AES256", ""}, {"aws:kms", "k"}} {
			c := &Config{}
			c.Storage.Provider, c.Storage.Bucket = "s3", "b"
			c.Storage.AccessKey, c.Storage.SecretKey = "a", "s"
			c.Storage.Endpoint, c.Storage.SSE, c.Storage.SSEKMSKeyID = ep, tc.sse, tc.kms
			err := c.validateStorage()
			if err == nil || !strings.Contains(err.Error(), "R2 always encrypts at rest") {
				t.Fatalf("%s sse=%s: err = %v", ep, tc.sse, err)
			}
		}
		c := &Config{}
		c.Storage.Provider, c.Storage.Bucket = "s3", "b"
		c.Storage.AccessKey, c.Storage.SecretKey = "a", "s"
		c.Storage.Endpoint = ep
		if err := c.validateStorage(); err != nil {
			t.Fatalf("%s without SSE refused: %v", ep, err)
		}
	}
	// SSE stays valid on other S3-compatible endpoints.
	c := &Config{}
	c.Storage.Provider, c.Storage.Bucket = "s3", "b"
	c.Storage.AccessKey, c.Storage.SecretKey = "a", "s"
	c.Storage.Endpoint, c.Storage.SSE = "https://minio.internal:9000", "AES256"
	if err := c.validateStorage(); err != nil {
		t.Fatalf("minio with SSE refused: %v", err)
	}
}
