package fetchers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingS3 is a stand-in S3 endpoint that records the Authorization header
// of every request and answers ListObjectsV2 with an empty bucket.
type recordingS3 struct {
	mu    sync.Mutex
	auths []string
	srv   *httptest.Server
}

func newRecordingS3(t *testing.T) *recordingS3 {
	t.Helper()
	r := &recordingS3{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.auths = append(r.auths, req.Header.Get("Authorization"))
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>b</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>`))
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recordingS3) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.auths...)
}

// ambientAWS puts a fake server identity in the environment, the way an EC2
// instance role / ECS task role / env-configured key reaches the SDK's
// default credential chain.
func ambientAWS(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIASERVERAMBIENT01")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "server-secret")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func listOnce(ctx context.Context, cfg S3Config) ([]string, error) {
	f, err := NewS3Fetcher(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ListFiles(ctx, nil)
}

// TestS3Fetcher_NeverUsesAmbientCredentials: with an auth_type other than
// "keys" the fetcher loaded the SDK default chain, so a tenant source signed
// requests with the API server's own AWS identity (confused deputy: the
// tenant names any bucket the server's role can read).
func TestS3Fetcher_NeverUsesAmbientCredentials(t *testing.T) {
	ambientAWS(t)
	rec := newRecordingS3(t)
	useUnguardedS3Transport(t) // reach the local stand-in; the SSRF guard is tested separately

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, authType := range []string{"", "none", "sts_role"} {
		_, err := listOnce(ctx, S3Config{Bucket: "operator-private", Region: "us-east-1", Endpoint: rec.srv.URL, AuthType: authType, RoleARN: "arn:aws:iam::111111111111:role/x"})
		for _, a := range rec.requests() {
			if strings.Contains(a, "AKIASERVERAMBIENT01") {
				t.Fatalf("auth_type %q: request signed with the server's ambient AWS key: %s", authType, a)
			}
		}
		if err == nil {
			t.Fatalf("auth_type %q without tenant keys must be refused", authType)
		}
	}
}

// TestS3Fetcher_EndpointIsSSRFGuarded: the tenant endpoint was handed to the
// SDK unchecked, so a template source could make the API server send
// (signed) requests to loopback / link-local / internal services.
func TestS3Fetcher_EndpointIsSSRFGuarded(t *testing.T) {
	rec := newRecordingS3(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, ep := range []string{rec.srv.URL, "http://169.254.169.254", "http://localhost:9000"} {
		_, err := listOnce(ctx, S3Config{Bucket: "b", Region: "us-east-1", Endpoint: ep, AuthType: "keys", AccessKey: "AKIATENANT", SecretKey: "tenant-secret"})
		if err == nil {
			t.Fatalf("endpoint %s must be refused", ep)
		}
	}
	if n := len(rec.requests()); n != 0 {
		t.Fatalf("internal endpoint received %d request(s)", n)
	}
}

// TestS3Fetcher_TenantKeysWork is the legitimate case: explicit tenant keys
// sign the request to the tenant's endpoint.
func TestS3Fetcher_TenantKeysWork(t *testing.T) {
	ambientAWS(t)
	rec := newRecordingS3(t)
	useUnguardedS3Transport(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := listOnce(ctx, S3Config{Bucket: "b", Region: "us-east-1", Endpoint: rec.srv.URL, AuthType: "keys", AccessKey: "AKIATENANT", SecretKey: "tenant-secret"}); err != nil {
		t.Fatalf("list with tenant keys failed: %v", err)
	}
	reqs := rec.requests()
	if len(reqs) == 0 || !strings.Contains(reqs[0], "Credential=AKIATENANT/") {
		t.Fatalf("request not signed with the tenant key: %v", reqs)
	}
}

// useUnguardedS3Transport lets a test reach its local stand-in endpoint.
func useUnguardedS3Transport(t *testing.T) {
	t.Helper()
	prevClient, prevCheck := s3HTTPClient, checkS3Endpoint
	s3HTTPClient = func() *http.Client { return &http.Client{Timeout: 5 * time.Second} }
	checkS3Endpoint = func(string) error { return nil }
	t.Cleanup(func() { s3HTTPClient, checkS3Endpoint = prevClient, prevCheck })
}
