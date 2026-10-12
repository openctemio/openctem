package storage

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeS3 is a minimal in-memory S3 endpoint (path-style PUT/GET/DELETE).
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string]string
	auth    []string
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	switch r.Method {
	case http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		f.objects[r.URL.Path] = string(b)
	case http.MethodGet:
		v, ok := f.objects[r.URL.Path]
		if !ok {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code></Error>`)
			return
		}
		_, _ = io.WriteString(w, v)
	case http.MethodDelete:
		delete(f.objects, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}
}

// The operator's bucket may live at a private address (an in-cluster MinIO):
// unlike a tenant bucket it is configuration, not tenant input. Round trip
// through a loopback endpoint, signed with the operator key.
func TestOperatorS3Storage_RoundTripPrivateEndpoint(t *testing.T) {
	f := &fakeS3{objects: map[string]string{}}
	srv := httptest.NewServer(f)
	defer srv.Close()

	s, err := NewOperatorS3Storage("attachments", "", srv.URL, "AKIAOPERATOR", "operator-secret")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key, err := s.Upload(ctx, "tenant-1", "evidence.txt", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if _, ok := f.objects["/attachments/tenant-1/"+key]; !ok {
		t.Fatalf("object not stored under bucket/tenant/key; have %v", f.objects)
	}
	rc, _, err := s.Download(ctx, "tenant-1", key)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "hello" {
		t.Fatalf("downloaded %q", b)
	}
	if err := s.Delete(ctx, "tenant-1", key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	for _, a := range f.auth {
		if !strings.Contains(a, "Credential=AKIAOPERATOR/") {
			t.Fatalf("request not signed with the operator key: %q", a)
		}
	}
}

func TestOperatorS3Storage_RequiresBucketAndKeys(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIASERVERAMBIENT01")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "server-secret")
	for _, c := range [][4]string{
		{"", "", "AKIA", "secret"},
		{"b", "", "", ""},
		{"b", "", "AKIA", ""},
	} {
		if _, err := NewOperatorS3Storage(c[0], "", c[1], c[2], c[3]); err == nil {
			t.Fatalf("NewOperatorS3Storage%v: want error", c)
		}
	}
}
