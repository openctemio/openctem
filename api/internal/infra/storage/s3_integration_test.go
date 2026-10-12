package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The S3 driver against a real S3-compatible server (a scratch MinIO,
// SeaweedFS or similar). Skipped unless OPENCTEM_TEST_S3_ENDPOINT,
// OPENCTEM_TEST_S3_ACCESS_KEY and OPENCTEM_TEST_S3_SECRET_KEY are set; each
// run uses a fresh bucket.
func s3IntegrationStore(t *testing.T) *S3Storage {
	t.Helper()
	endpoint := os.Getenv("OPENCTEM_TEST_S3_ENDPOINT")
	ak, sk := os.Getenv("OPENCTEM_TEST_S3_ACCESS_KEY"), os.Getenv("OPENCTEM_TEST_S3_SECRET_KEY")
	if endpoint == "" || ak == "" || sk == "" {
		t.Skip("OPENCTEM_TEST_S3_ENDPOINT / _ACCESS_KEY / _SECRET_KEY not set")
	}
	bucket := "openctem-it-" + strings.ReplaceAll(shared.NewID().String(), "-", "")[:20]
	s, err := NewOperatorS3Storage(bucket, "us-east-1", endpoint, ak, sk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	return s
}

func readAll(t *testing.T, rc io.ReadCloser) string {
	t.Helper()
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestS3Integration_StreamedRoundTripAndTenantIsolation(t *testing.T) {
	s := s3IntegrationStore(t)
	ctx := context.Background()
	tenantA, tenantB := shared.NewID().String(), shared.NewID().String()

	body := strings.Repeat("evidence-", 600_000) // ~5.4 MB, streamed (not seekable)
	keyA, err := s.Upload(ctx, tenantA, "trace.har", "application/har+json", io.MultiReader(strings.NewReader(body)))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	rc, ct, err := s.Download(ctx, tenantA, keyA)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if got := readAll(t, rc); got != body {
		t.Fatalf("read back %d bytes, want %d", len(got), len(body))
	}
	if ct != "application/har+json" {
		t.Fatalf("content type %q", ct)
	}

	// Tenant B cannot reach tenant A's object with A's key.
	if _, _, err := s.Download(ctx, tenantB, keyA); !errors.Is(err, attachment.ErrNotFound) {
		t.Fatalf("cross-tenant download: want ErrNotFound, got %v", err)
	}

	keyB, err := s.Upload(ctx, tenantB, "b.txt", "text/plain", strings.NewReader("tenant b"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Upload(ctx, tenantA, "a2.txt", "text/plain", strings.NewReader("tenant a")); err != nil {
		t.Fatal(err)
	}

	n, err := s.EraseTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if n != 2 {
		t.Fatalf("erased %d objects, want 2", n)
	}
	if _, _, err := s.Download(ctx, tenantA, keyA); !errors.Is(err, attachment.ErrNotFound) {
		t.Fatalf("tenant A's object survived the erase: %v", err)
	}
	rc, _, err = s.Download(ctx, tenantB, keyB)
	if err != nil {
		t.Fatalf("tenant B's object was erased with A: %v", err)
	}
	if got := readAll(t, rc); got != "tenant b" {
		t.Fatalf("tenant B read %q", got)
	}
	if err := s.Delete(ctx, tenantB, keyB); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, tenantB, keyB); err != nil {
		t.Fatalf("delete is not idempotent: %v", err)
	}
}
