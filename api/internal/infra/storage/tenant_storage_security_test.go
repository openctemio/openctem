package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
)

// TestNewS3Storage_EndpointIsSSRFGuarded: the tenant-chosen endpoint went to
// the SDK unchecked, so a tenant admin could make the API server PUT/GET/
// DELETE against loopback, cloud metadata or internal services.
func TestNewS3Storage_EndpointIsSSRFGuarded(t *testing.T) {
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	for _, ep := range []string{internal.URL, "http://169.254.169.254", "http://localhost:9000"} {
		s, err := NewS3Storage("bucket", "us-east-1", ep, "AKIATENANT", "tenant-secret")
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, err = s.Upload(ctx, "tenant-1", "a.txt", "text/plain", strings.NewReader("x"))
			cancel()
		}
		if err == nil {
			t.Fatalf("endpoint %s must be refused", ep)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("internal endpoint received %d request(s)", n)
	}
}

// TestNewS3Storage_RequiresTenantKeys: never fall back to ambient credentials.
func TestNewS3Storage_RequiresTenantKeys(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIASERVERAMBIENT01")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "server-secret")
	if _, err := NewS3Storage("bucket", "us-east-1", "", "", ""); err == nil {
		t.Fatal("S3 storage without tenant keys must be refused")
	}
}

// TestNewS3Storage_TenantEndpointWorks: the legitimate path still signs with
// the tenant key and reaches the tenant endpoint.
func TestNewS3Storage_TenantEndpointWorks(t *testing.T) {
	var auth atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	prevClient, prevCheck := s3HTTPClient, checkS3Endpoint
	s3HTTPClient = func() *http.Client { return &http.Client{Timeout: 5 * time.Second} }
	checkS3Endpoint = func(string) error { return nil }
	defer func() { s3HTTPClient, checkS3Endpoint = prevClient, prevCheck }()

	s, err := NewS3Storage("bucket", "us-east-1", upstream.URL, "AKIATENANT", "tenant-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Upload(context.Background(), "tenant-1", "a.txt", "text/plain", strings.NewReader("x")); err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if a, _ := auth.Load().(string); !strings.Contains(a, "Credential=AKIATENANT/") {
		t.Fatalf("request not signed with the tenant key: %q", a)
	}
}

// TestTenantStorageFactory_LocalIgnoresTenantPath: a tenant config of
// {"provider":"local","base_path":"/anywhere"} made the server create
// directories and write uploads wherever the tenant said.
func TestTenantStorageFactory_LocalIgnoresTenantPath(t *testing.T) {
	operatorDir := t.TempDir()
	tenantChosen := filepath.Join(t.TempDir(), "chosen-by-tenant")

	factory := NewTenantStorageFactory(NewLocalStorage(operatorDir))
	s, err := factory(attachment.StorageConfig{Provider: "local", BasePath: tenantChosen})
	if err != nil {
		t.Fatal(err)
	}
	key, err := s.Upload(context.Background(), "tenant-1", "evidence.txt", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tenantChosen); !os.IsNotExist(err) {
		t.Fatalf("tenant-chosen base_path was created on the server (stat err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(operatorDir, "tenant-1", key)); err != nil {
		t.Fatalf("upload did not land in the operator directory: %v", err)
	}
}

func TestTenantStorageFactory_RejectsUnknownProvider(t *testing.T) {
	factory := NewTenantStorageFactory(NewLocalStorage(t.TempDir()))
	if _, err := factory(attachment.StorageConfig{Provider: "gcs"}); err == nil {
		t.Fatal("unknown provider must be refused")
	}
}
