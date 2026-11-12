package storage

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Erasing tenant A removes A's directory, files no attachment row names
// included, and leaves tenant B's files and anything else under the base path.
func TestLocalStorage_EraseTenant_OnlyThatTenant(t *testing.T) {
	base := t.TempDir()
	s := NewLocalStorage(base)
	ctx := context.Background()
	tenantA, tenantB := shared.NewID().String(), shared.NewID().String()

	for i := 0; i < 2; i++ {
		if _, err := s.Upload(ctx, tenantA, "a.txt", "text/plain", strings.NewReader("a")); err != nil {
			t.Fatal(err)
		}
	}
	keyB, err := s.Upload(ctx, tenantB, "b.txt", "text/plain", strings.NewReader("b"))
	if err != nil {
		t.Fatal(err)
	}
	// An orphan (no row names it) and a sibling whose name starts with A's id.
	if err := os.WriteFile(filepath.Join(base, tenantA, "orphan"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(base, tenantA+".bak")
	if err := os.WriteFile(sibling, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	n, err := s.EraseTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("EraseTenant: %v", err)
	}
	if n != 3 {
		t.Errorf("erased %d files, want 3", n)
	}
	if _, err := os.Stat(filepath.Join(base, tenantA)); !os.IsNotExist(err) {
		t.Errorf("tenant A directory still exists (err=%v)", err)
	}
	rc, _, err := s.Download(ctx, tenantB, keyB)
	if err != nil {
		t.Fatalf("tenant B's file is gone: %v", err)
	}
	_ = rc.Close()
	if _, err := os.Stat(sibling); err != nil {
		t.Errorf("a path outside tenant A's directory was removed: %v", err)
	}

	// Idempotent: a second run finds nothing.
	if n, err := s.EraseTenant(ctx, tenantA); err != nil || n != 0 {
		t.Errorf("second erase: %d, %v", n, err)
	}
}

// A tenant directory replaced by a symlink to another tenant's directory is
// unlinked, never followed.
func TestLocalStorage_EraseTenant_DoesNotFollowSymlink(t *testing.T) {
	base := t.TempDir()
	s := NewLocalStorage(base)
	ctx := context.Background()
	tenantA, tenantB := shared.NewID().String(), shared.NewID().String()
	keyB, err := s.Upload(ctx, tenantB, "b.txt", "text/plain", strings.NewReader("b"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, tenantB), filepath.Join(base, tenantA)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EraseTenant(ctx, tenantA); err != nil {
		t.Fatalf("EraseTenant: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(base, tenantA)); !os.IsNotExist(err) {
		t.Errorf("symlink not removed (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(base, tenantB, keyB)); err != nil {
		t.Errorf("tenant B's file was deleted through the symlink: %v", err)
	}
}

func TestStorage_EraseTenant_RefusesNonTenantNamespace(t *testing.T) {
	base := t.TempDir()
	keep := filepath.Join(base, "keep")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewLocalStorage(base)
	f := &listingS3{fakeS3: fakeS3{objects: map[string]string{"/bucket/keep": "x"}}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	s3s, err := NewOperatorS3Storage("bucket", "", srv.URL, "AKIA", "secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", ".", "..", "/", "a/b", "tenant-1", "00000000-0000-0000-0000-000000000000", strings.ToUpper(shared.NewID().String())} {
		if _, err := s.EraseTenant(context.Background(), bad); err == nil {
			t.Errorf("local: namespace %q accepted", bad)
		}
		if _, err := s3s.EraseTenant(context.Background(), bad); err == nil {
			t.Errorf("s3: namespace %q accepted", bad)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("base path content removed: %v", err)
	}
	if len(f.objects) != 1 {
		t.Errorf("bucket content removed: %v", f.objects)
	}
}

// listingS3 adds ListObjectsV2 (GET /bucket?list-type=2&prefix=) to fakeS3.
// It returns every object of the bucket when ignorePrefix is set, to prove
// the client re-checks the prefix itself.
type listingS3 struct {
	fakeS3
	ignorePrefix bool
	failList     bool
	mu2          sync.Mutex
}

func (f *listingS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Query().Get("list-type") != "2" {
		f.fakeS3.ServeHTTP(w, r)
		return
	}
	f.mu2.Lock()
	defer f.mu2.Unlock()
	if f.failList {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `<Error><Code>ServiceUnavailable</Code></Error>`)
		return
	}
	bucketPath := strings.TrimSuffix(r.URL.Path, "/") + "/"
	prefix := r.URL.Query().Get("prefix")
	type content struct {
		Key string `xml:"Key"`
	}
	out := struct {
		XMLName     xml.Name  `xml:"ListBucketResult"`
		IsTruncated bool      `xml:"IsTruncated"`
		Contents    []content `xml:"Contents"`
	}{}
	f.mu.Lock()
	for p := range f.objects {
		key := strings.TrimPrefix(p, bucketPath)
		if f.ignorePrefix || strings.HasPrefix(key, prefix) {
			out.Contents = append(out.Contents, content{Key: key})
		}
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/xml")
	_ = xml.NewEncoder(w).Encode(out)
}

// Erasing tenant A in a bucket deletes only keys under "A/", even when the
// endpoint's listing ignores the prefix.
func TestS3Storage_EraseTenant_OnlyThatTenant(t *testing.T) {
	for _, ignorePrefix := range []bool{false, true} {
		f := &listingS3{fakeS3: fakeS3{objects: map[string]string{}}, ignorePrefix: ignorePrefix}
		srv := httptest.NewServer(f)
		s, err := NewOperatorS3Storage("bucket", "", srv.URL, "AKIA", "secret")
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		tenantA, tenantB := shared.NewID().String(), shared.NewID().String()
		for _, tid := range []string{tenantA, tenantA, tenantB} {
			if _, err := s.Upload(ctx, tid, "f.txt", "text/plain", strings.NewReader("x")); err != nil {
				t.Fatal(err)
			}
		}
		f.objects["/bucket/"+tenantA+".bak/x"] = "keep" // shares A's id, not its namespace

		n, err := s.EraseTenant(ctx, tenantA)
		if err != nil {
			t.Fatalf("EraseTenant: %v", err)
		}
		if n != 2 {
			t.Errorf("ignorePrefix=%v: erased %d objects, want 2", ignorePrefix, n)
		}
		for p := range f.objects {
			if strings.HasPrefix(p, "/bucket/"+tenantA+"/") {
				t.Errorf("ignorePrefix=%v: tenant A object left: %s", ignorePrefix, p)
			}
		}
		if len(f.objects) != 2 {
			t.Errorf("ignorePrefix=%v: other objects removed; left %v", ignorePrefix, f.objects)
		}
		srv.Close()
	}
}

// A bucket that cannot be listed fails the erasure (the caller then refuses
// the organization deletion).
func TestS3Storage_EraseTenant_ListFailure(t *testing.T) {
	f := &listingS3{fakeS3: fakeS3{objects: map[string]string{}}, failList: true}
	srv := httptest.NewServer(f)
	defer srv.Close()
	s, err := NewOperatorS3Storage("bucket", "", srv.URL, "AKIA", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EraseTenant(context.Background(), shared.NewID().String()); err == nil {
		t.Fatal("EraseTenant succeeded although the bucket could not be listed")
	}
}
