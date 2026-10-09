package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// fakeSignerAPI serves GET /v1/keys and GET /v1/keyset.
type fakeSignerAPI struct {
	mu     sync.Mutex
	pub    ed25519.PublicKey
	keyset []byte // nil: 404
}

func (f *fakeSignerAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case keysPath:
		_ = json.NewEncoder(w).Encode(jobsign.KeysResponse{PayloadType: jobsign.PayloadType, Keys: []jobsign.PublicKey{jobsign.NewPublicKey(f.pub)}})
	case keysetPath:
		if f.keyset == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(f.keyset)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newTestClient(t *testing.T, f *fakeSignerAPI) (*Client, *time.Time) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	c := NewClient("/nonexistent", time.Second)
	c.http, c.baseURL = srv.Client(), srv.URL
	c.now = func() time.Time { return now }
	return c, &now
}

func TestClient_HelloCarriesTheKeySet(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	env, _, err := jobsign.SignKeySet(root, 1, time.Now(), 24*time.Hour, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSignerAPI{pub: pub, keyset: env}
	c, now := newTestClient(t, f)

	h := c.Hello(context.Background())
	if len(h.Keys) != 1 || !bytes.Equal(h.KeySet, env) {
		t.Fatalf("hello signed_jobs keys %v keyset %s", h.Keys, h.KeySet)
	}
	v1 := c.KeySetVersion()
	if len(v1) != 16 {
		t.Fatalf("key set version %q", v1)
	}
	b, _ := json.Marshal(h)
	if !bytes.Contains(b, []byte(`"keyset":{"payloadType":"`+jobsign.KeySetPayloadType)) {
		t.Fatalf("hello JSON %s", b)
	}

	// A new key set is picked up after the cache expires; one that is not
	// signed by its root is not passed on (the last good one is kept).
	env2, _, _ := jobsign.SignKeySet(root, 2, time.Now(), 24*time.Hour, []ed25519.PublicKey{pub})
	f.mu.Lock()
	f.keyset = env2
	f.mu.Unlock()
	*now = now.Add(keysTTL + time.Second)
	if h := c.Hello(context.Background()); !bytes.Equal(h.KeySet, env2) {
		t.Fatalf("key set not refreshed: %s", h.KeySet)
	}
	if c.KeySetVersion() == v1 {
		t.Fatal("key set version did not change with the key set")
	}
	f.mu.Lock()
	f.keyset = bytes.Replace(env2, []byte(`"sig":"`), []byte(`"sig":"AAAA`), 1)
	f.mu.Unlock()
	*now = now.Add(keysTTL + time.Second)
	if h := c.Hello(context.Background()); !bytes.Equal(h.KeySet, env2) {
		t.Fatalf("a broken key set replaced the good one: %s", h.KeySet)
	}

	// The signer stops serving one: hello carries none.
	f.mu.Lock()
	f.keyset = nil
	f.mu.Unlock()
	*now = now.Add(keysTTL + time.Second)
	if h := c.Hello(context.Background()); h.KeySet != nil {
		t.Fatalf("hello keyset %s after the signer dropped it", h.KeySet)
	}
	if v := c.KeySetVersion(); v != "" {
		t.Fatalf("key set version %q without a key set", v)
	}
	b, _ = json.Marshal(c.Hello(context.Background()))
	if bytes.Contains(b, []byte(`"keyset"`)) {
		t.Fatalf("hello JSON %s", b)
	}
}
