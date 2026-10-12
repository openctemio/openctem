package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
)

const (
	tenantOne = "0190f1a0-0000-7000-8000-000000000001"
	tenantTwo = "0190f1a0-0000-7000-8000-000000000002"
)

// A copy keeps namespace and key, verifies each object, skips what is
// already there, honors the tenant filter, never follows symlinks or copies
// temporary uploads, and leaves the source alone.
func TestMigrate_LocalToLocal(t *testing.T) {
	ctx := context.Background()
	srcDir, dstDir := t.TempDir(), t.TempDir()
	src, dst := NewLocalStorage(srcDir), NewLocalStorage(dstDir)
	k1, err := src.Upload(ctx, tenantOne, "a.png", "image/png", strings.NewReader("one"))
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := src.Upload(ctx, tenantTwo, "b.pdf", "application/pdf", strings.NewReader("two two"))
	// Noise that must not be copied.
	_ = os.WriteFile(filepath.Join(srcDir, tenantOne, ".upload-123"), []byte("partial"), 0o600)
	outside := t.TempDir()
	_ = os.WriteFile(filepath.Join(outside, "secret"), []byte("host file"), 0o600)
	_ = os.Symlink(filepath.Join(outside, "secret"), filepath.Join(srcDir, tenantOne, "link"))
	_ = os.Symlink(outside, filepath.Join(srcDir, "escape"))

	res, err := Migrate(ctx, src, dst, MigrateOptions{Namespace: tenantOne, DryRun: true})
	if err != nil || res.Copied != 1 {
		t.Fatalf("dry run: %+v %v", res, err)
	}
	if _, found, _ := dst.StatObject(ctx, tenantOne, k1); found {
		t.Fatal("dry run wrote")
	}
	res, err = Migrate(ctx, src, dst, MigrateOptions{Namespace: tenantOne})
	if err != nil || res.Copied != 1 || res.Failed != 0 {
		t.Fatalf("tenant copy: %+v %v", res, err)
	}
	if _, found, _ := dst.StatObject(ctx, tenantTwo, k2); found {
		t.Fatal("tenant filter ignored")
	}
	res, err = Migrate(ctx, src, dst, MigrateOptions{})
	if err != nil || res.Copied != 1 || res.Skipped != 1 {
		t.Fatalf("full copy: %+v %v", res, err)
	}
	rc, _, err := dst.Download(ctx, tenantOne, k1)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(got) != "one" {
		t.Fatalf("copied bytes %q", got)
	}
	for _, p := range []string{filepath.Join(dstDir, tenantOne, ".upload-123"), filepath.Join(dstDir, tenantOne, "link"), filepath.Join(dstDir, "escape")} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s copied", p)
		}
	}
	// A destination object of the same size but other bytes: kept without
	// -verify, replaced with it.
	if err := dst.PutObject(ctx, tenantOne, k1, strings.NewReader("eno")); err != nil {
		t.Fatal(err)
	}
	if res, _ := Migrate(ctx, src, dst, MigrateOptions{}); res.Skipped != 2 {
		t.Fatalf("without verify: %+v", res)
	}
	if res, _ := Migrate(ctx, src, dst, MigrateOptions{Verify: true}); res.Copied != 1 {
		t.Fatalf("with verify: %+v", res)
	}
}

func TestObjectKeysCannotLeaveTheirNamespace(t *testing.T) {
	ctx := context.Background()
	s := NewLocalStorage(t.TempDir())
	for _, key := range []string{"../x", "a/b", `a\b`, "..", ".upload-x", ""} {
		if err := s.PutObject(ctx, tenantOne, key, strings.NewReader("x")); err == nil {
			t.Errorf("key %q accepted", key)
		}
	}
	for _, ns := range []string{"..", "a/b", ""} {
		if err := s.PutObject(ctx, ns, "k", strings.NewReader("x")); err == nil {
			t.Errorf("namespace %q accepted", ns)
		}
	}
}

// fakeSSE records the encryption headers of writes.
type fakeSSE struct {
	headers []http.Header
}

func (f *fakeSSE) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		f.headers = append(f.headers, r.Header.Clone())
	}
	w.WriteHeader(http.StatusOK)
}

func TestS3_ServerSideEncryptionHeaders(t *testing.T) {
	f := &fakeSSE{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	s, err := NewOperatorS3Storage("attachments", "", srv.URL, "AKIA", "secret")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.SetServerSideEncryption("aws:kms", "arn:aws:kms:eu-west-1:111122223333:key/abc"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Upload(ctx, tenantOne, "a.txt", "text/plain", strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetServerSideEncryption("AES256", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.PutObject(ctx, tenantOne, "k", strings.NewReader("y")); err != nil {
		t.Fatal(err)
	}
	if len(f.headers) != 2 {
		t.Fatalf("writes %d", len(f.headers))
	}
	if h := f.headers[0]; h.Get("X-Amz-Server-Side-Encryption") != "aws:kms" ||
		h.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id") != "arn:aws:kms:eu-west-1:111122223333:key/abc" {
		t.Errorf("kms write headers: %v", h)
	}
	if h := f.headers[1]; h.Get("X-Amz-Server-Side-Encryption") != "AES256" {
		t.Errorf("AES256 write headers: %v", h)
	}
	for _, bad := range [][2]string{{"aes", ""}, {"AES256", "key"}, {"", "key"}} {
		if err := s.SetServerSideEncryption(bad[0], bad[1]); err == nil {
			t.Errorf("SSE %v accepted", bad)
		}
	}
}

// A signed URL names exactly the tenant's object, expires in the asked time,
// forces an attachment download with the file's name and type, and is only
// made for an HTTPS endpoint.
func TestS3_PresignDownload(t *testing.T) {
	ctx := context.Background()
	s, err := NewOperatorS3Storage("attachments", "eu-west-1", "https://s3.example.com", "AKIAOPERATOR", "secret")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.PresignDownload(ctx, tenantOne, "0190_report.pdf", `report "final".pdf`, "application/pdf", 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "https" || u.Host != "s3.example.com" || u.Path != "/attachments/"+tenantOne+"/0190_report.pdf" {
		t.Errorf("signed URL target %s", raw)
	}
	if q.Get("X-Amz-Expires") != "60" || q.Get("X-Amz-Signature") == "" {
		t.Errorf("expiry/signature: %v", q)
	}
	if cd := q.Get("response-content-disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, "final") {
		t.Errorf("disposition %q", cd)
	}
	if q.Get("response-content-type") != "application/pdf" {
		t.Errorf("type %q", q.Get("response-content-type"))
	}
	for _, key := range []string{"../other", tenantTwo + "/k", ""} {
		if _, err := s.PresignDownload(ctx, tenantOne, key, "f", "text/plain", time.Minute); err == nil {
			t.Errorf("key %q signed", key)
		}
	}
	if _, err := s.PresignDownload(ctx, "..", "k", "f", "text/plain", time.Minute); err == nil {
		t.Error("bad namespace signed")
	}
	if _, err := s.PresignDownload(ctx, tenantOne, "k", "f", "text/plain", time.Hour); err == nil {
		t.Error("an hour-long URL signed")
	}
	plain, _ := NewOperatorS3Storage("attachments", "", "http://minio.internal:9000", "AKIA", "secret")
	if _, err := plain.PresignDownload(ctx, tenantOne, "k", "f", "text/plain", time.Minute); !errors.Is(err, attachment.ErrDirectDownloadUnavailable) {
		t.Errorf("plain HTTP endpoint: %v", err)
	}
	// Through the metrics wrapper: still signs; a local store cannot.
	if _, err := Instrument(s, BackendServer).(attachment.DirectDownloader).PresignDownload(ctx, tenantOne, "k", "f", "text/plain", time.Minute); err != nil {
		t.Errorf("instrumented sign: %v", err)
	}
	if _, err := Instrument(NewLocalStorage(t.TempDir()), BackendServer).(attachment.DirectDownloader).PresignDownload(ctx, tenantOne, "k", "f", "text/plain", time.Minute); !errors.Is(err, attachment.ErrDirectDownloadUnavailable) {
		t.Errorf("local sign: %v", err)
	}
}

func TestInstrument_CountsBytesAndOutcomes(t *testing.T) {
	ctx := context.Background()
	s := Instrument(NewLocalStorage(t.TempDir()), "test")
	before := testutil.ToFloat64(storageBytesWritten.WithLabelValues("test"))
	if _, err := s.Upload(ctx, tenantOne, "a", "text/plain", bytes.NewReader(make([]byte, 1234))); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(storageBytesWritten.WithLabelValues("test")) - before; got != 1234 {
		t.Errorf("bytes written %v", got)
	}
	if _, _, err := s.Download(ctx, tenantOne, "missing"); err == nil {
		t.Fatal("missing file downloaded")
	}
	if testutil.ToFloat64(storageOps.WithLabelValues("download", "test", "error")) < 1 {
		t.Error("failed download not counted")
	}
}
