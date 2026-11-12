package signer

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

func signKeySet(t *testing.T, root ed25519.PrivateKey, version uint64, issued time.Time, keys ...ed25519.PrivateKey) []byte {
	t.Helper()
	pubs := make([]ed25519.PublicKey, 0, len(keys))
	for _, k := range keys {
		p, _ := k.Public().(ed25519.PublicKey)
		pubs = append(pubs, p)
	}
	env, _, err := jobsign.SignKeySet(root, version, issued, 30*24*time.Hour, pubs)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func getKeySet(s *Service) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, KeySetPath, nil))
	return rec
}

func TestKeySet_ServedOnceLoaded(t *testing.T) {
	key, root := newKey(t), newKey(t)
	s := newService(t, t.TempDir(), key, nil)
	if rec := getKeySet(s); rec.Code != http.StatusNotFound {
		t.Fatalf("no key set: status %d", rec.Code)
	}
	env := signKeySet(t, root, 1, tNow, key, newKey(t))
	path := filepath.Join(t.TempDir(), "keyset.json")
	if err := os.WriteFile(path, append(env, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := s.LoadKeySetFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if ks.Version != 1 || len(ks.Keys) != 2 {
		t.Fatalf("key set %+v", ks)
	}
	rec := getKeySet(s)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), env) {
		t.Fatalf("GET %s: %d %s", KeySetPath, rec.Code, rec.Body.String())
	}
	if _, _, err := jobsign.VerifyKeySet(rec.Body.Bytes(), jobsign.KeyID(root.Public().(ed25519.PublicKey)), tNow); err != nil {
		t.Fatalf("served key set does not verify: %v", err)
	}
}

func TestKeySet_Refusals(t *testing.T) {
	key, root := newKey(t), newKey(t)
	s := newService(t, t.TempDir(), key, nil)

	// A key set that does not list the signer's own key.
	if _, err := s.LoadKeySet(signKeySet(t, root, 1, tNow, newKey(t))); !errors.Is(err, ErrKeySetOmitsSigner) {
		t.Fatalf("key set without the signer's key: %v", err)
	}
	// Expired.
	if _, err := s.LoadKeySet(signKeySet(t, root, 1, tNow.Add(-31*24*time.Hour), key)); err == nil {
		t.Fatal("an expired key set loaded")
	}
	// A changed byte: not signed by its root.
	env := signKeySet(t, root, 3, tNow, key)
	bad := bytes.Replace(env, []byte(`"sig":"`), []byte(`"sig":"AA`), 1)
	if _, err := s.LoadKeySet(bad); err == nil {
		t.Fatal("a key set with a broken signature loaded")
	}
	if raw, _ := s.KeySet(); raw != nil {
		t.Fatal("a refused key set was installed")
	}

	// Version order: 3 loads; 2 and a different 3 do not; the same 3 does.
	if _, err := s.LoadKeySet(env); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadKeySet(signKeySet(t, root, 2, tNow, key)); err == nil {
		t.Fatal("a lower version replaced the key set")
	}
	if _, err := s.LoadKeySet(signKeySet(t, root, 3, tNow.Add(time.Second), key)); err == nil {
		t.Fatal("a different key set with the same version replaced it")
	}
	if _, err := s.LoadKeySet(env); err != nil {
		t.Fatalf("reloading the same key set: %v", err)
	}
	if _, doc := s.KeySet(); doc.Version != 3 {
		t.Fatalf("loaded version %d", doc.Version)
	}
}
