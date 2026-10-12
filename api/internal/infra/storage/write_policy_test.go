package storage

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// failingReader yields some bytes, then fails like a dropped upload.
type failingReader struct{ sent bool }

func (f *failingReader) Read(p []byte) (int, error) {
	if f.sent {
		return 0, errors.New("connection reset")
	}
	f.sent = true
	return copy(p, "partial content"), nil
}

// A failed upload leaves nothing in the tenant directory: no file under a
// key and no temporary file.
func TestLocalStorage_FailedUploadLeavesNothing(t *testing.T) {
	base := t.TempDir()
	s := NewLocalStorage(base)
	tenant := shared.NewID().String()
	if _, err := s.Upload(context.Background(), tenant, "a.txt", "text/plain", &failingReader{}); err == nil {
		t.Fatal("upload of a failing reader succeeded")
	}
	entries, err := os.ReadDir(filepath.Join(base, tenant))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a failed upload left %d entries: %v", len(entries), entries)
	}
}

// Stored files and tenant directories are private to the API's user.
func TestLocalStorage_PrivatePermissions(t *testing.T) {
	base := t.TempDir()
	s := NewLocalStorage(base)
	tenant := shared.NewID().String()
	key, err := s.Upload(context.Background(), tenant, "a.txt", "text/plain", strings.NewReader("evidence"))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.Stat(filepath.Join(base, tenant))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dir.Mode().Perm(); perm != 0o700 {
		t.Fatalf("tenant dir mode %o, want 700", perm)
	}
	f, err := os.Stat(filepath.Join(base, tenant, key))
	if err != nil {
		t.Fatal(err)
	}
	if perm := f.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file mode %o, want 600", perm)
	}
	rc, _, err := s.Download(context.Background(), tenant, key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "evidence" {
		t.Fatalf("read back %q", b)
	}
}

// A namespace that could leave the base directory (or the bucket prefix) is
// refused by both drivers; the content pack platform namespace is accepted.
func TestUpload_RefusesEscapingNamespace(t *testing.T) {
	f := &fakeS3{objects: map[string]string{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	s3s, err := NewOperatorS3Storage("attachments", "", srv.URL, "AKIAOPERATOR", "operator-secret")
	if err != nil {
		t.Fatal(err)
	}
	local := NewLocalStorage(t.TempDir())
	for _, ns := range []string{"", ".", "..", "../etc", "a/b", `a\b`, "a\x00b"} {
		if _, err := local.Upload(context.Background(), ns, "x.txt", "text/plain", strings.NewReader("x")); err == nil {
			t.Errorf("local: namespace %q accepted", ns)
		}
		if _, err := s3s.Upload(context.Background(), ns, "x.txt", "text/plain", strings.NewReader("x")); err == nil {
			t.Errorf("s3: namespace %q accepted", ns)
		}
	}
	if _, err := local.Upload(context.Background(), "platform-content", "p.tar", "application/x-tar", strings.NewReader("x")); err != nil {
		t.Fatalf("platform namespace refused: %v", err)
	}
	if len(f.objects) != 0 {
		t.Fatalf("an escaping namespace reached the bucket: %v", f.objects)
	}
}

// A streamed (non-seekable) body is uploaded whole: it is spooled so the
// request can be signed, and the temporary file is removed.
func TestS3Storage_UploadsStreamedBody(t *testing.T) {
	f := &fakeS3{objects: map[string]string{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	s, err := NewOperatorS3Storage("attachments", "", srv.URL, "AKIAOPERATOR", "operator-secret")
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	body := strings.Repeat("e", 3<<20)
	tenant := shared.NewID().String()
	key, err := s.Upload(context.Background(), tenant, "big.txt", "text/plain", io.MultiReader(strings.NewReader(body)))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if got := f.objects["/attachments/"+tenant+"/"+key]; got != body {
		t.Fatalf("stored %d bytes, want %d", len(got), len(body))
	}
	left, _ := os.ReadDir(tmp)
	if len(left) != 0 {
		t.Fatalf("spool file left behind: %v", left)
	}
}
