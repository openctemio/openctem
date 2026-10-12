package storage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

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

// local -> S3 -> local keeps every namespace, key and byte (and skips what is
// already there); a signed GET made by the driver is accepted by the server
// and answers with the forced download headers.
func TestS3Integration_MigrateRoundTripAndSignedGet(t *testing.T) {
	s := s3IntegrationStore(t)
	ctx := context.Background()
	tenant := shared.NewID().String()
	src := NewLocalStorage(t.TempDir())
	key, err := src.Upload(ctx, tenant, "evidence.png", "image/png", strings.NewReader(strings.Repeat("px", 70000)))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Migrate(ctx, src, s, MigrateOptions{})
	if err != nil || res.Copied != 1 || res.Failed != 0 {
		t.Fatalf("local -> s3: %+v %v", res, err)
	}
	if res, _ := Migrate(ctx, src, s, MigrateOptions{Verify: true}); res.Skipped != 1 {
		t.Fatalf("second run: %+v", res)
	}
	back := NewLocalStorage(t.TempDir())
	if res, err := Migrate(ctx, s, back, MigrateOptions{}); err != nil || res.Copied != 1 {
		t.Fatalf("s3 -> local: %+v %v", res, err)
	}
	rc, _, err := back.Download(ctx, tenant, key)
	if err != nil || readAll(t, rc) != strings.Repeat("px", 70000) {
		t.Fatalf("round trip: %v", err)
	}

	signed, err := s.presignGet(ctx, tenant+"/"+key, "evidence.png", "image/png", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(signed) //nolint:gosec,noctx // test server URL
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || len(body) != 140000 {
		t.Fatalf("signed GET: %d (%d bytes)", resp.StatusCode, len(body))
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Errorf("Content-Disposition %q", cd)
	}
	tampered := strings.Replace(signed, key, key+"x", 1)
	if r2, err := http.Get(tampered); err == nil { //nolint:gosec,noctx // test server URL
		_ = r2.Body.Close()
		if r2.StatusCode == http.StatusOK {
			t.Error("a URL signed for one object opened another")
		}
	}
}
