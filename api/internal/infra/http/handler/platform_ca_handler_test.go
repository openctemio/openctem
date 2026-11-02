package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func platformCARootPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Test Internal CA - ECC Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func servePlatformCA(src *sensorapp.PlatformCASource) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	// No auth, no tenant in the context: the route is public.
	req := httptest.NewRequest(http.MethodGet, sensorapp.PlatformCAPath, nil)
	NewPlatformCAHandler(src, logger.NewNop()).Serve(rec, req)
	return rec
}

func TestPlatformCAHandler_ServesCertificatesOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.crt")
	root := platformCARootPEM(t)
	// Text around the block (an exported file with a comment) is dropped.
	if err := os.WriteFile(path, append([]byte("# exported root\n"), root...), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := servePlatformCA(sensorapp.NewPlatformCASource(path))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("content type %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("cache control %q", cc)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff missing")
	}
	if rec.Body.String() != string(root) {
		t.Errorf("body is not the root re-encoded:\n%s", rec.Body.String())
	}
	// Everything in the body is a certificate.
	rest := rec.Body.Bytes()
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			t.Errorf("served a %s block", b.Type)
		}
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		t.Errorf("trailing data served: %q", rest)
	}
}

func TestPlatformCAHandler_NotFoundWhenOff(t *testing.T) {
	for name, src := range map[string]*sensorapp.PlatformCASource{
		"nil":     nil,
		"unset":   sensorapp.NewPlatformCASource(""),
		"missing": sensorapp.NewPlatformCASource(filepath.Join(t.TempDir(), "absent.crt")),
	} {
		rec := servePlatformCA(src)
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "BEGIN") {
			t.Errorf("%s: status %d body %q", name, rec.Code, rec.Body.String())
		}
	}
}

// SECURITY: a CA file that holds a private key is refused as a whole; the
// route answers 404 and the key never leaves the API.
func TestPlatformCAHandler_RefusesAFileWithAPrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.pem")
	key := []byte("-----BEGIN EC PRIVATE KEY-----\nc2VjcmV0LWtleS1tYXRlcmlhbA==\n-----END EC PRIVATE KEY-----\n")
	if err := os.WriteFile(path, append(platformCARootPEM(t), key...), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := servePlatformCA(sensorapp.NewPlatformCASource(path))
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "PRIVATE") ||
		strings.Contains(rec.Body.String(), "c2VjcmV0") || strings.Contains(rec.Body.String(), "BEGIN") {
		t.Errorf("status %d body %q", rec.Code, rec.Body.String())
	}
}
