package http

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePair(t *testing.T, dir, cn string, mod time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		DNSNames: []string{cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{certFile, keyFile} {
		if err := os.Chtimes(f, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	return certFile, keyFile
}

func servedCN(t *testing.T, r *certReloader) string {
	t.Helper()
	c, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestCertReloaderPicksUpARenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	certFile, keyFile := writePair(t, dir, "old.test", base)
	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.now = func() time.Time { return now }

	writePair(t, dir, "new.test", base.Add(time.Minute))
	if got := servedCN(t, r); got != "old.test" {
		t.Fatalf("before the recheck interval: %q, want old.test", got)
	}
	now = now.Add(certRecheck)
	if got := servedCN(t, r); got != "new.test" {
		t.Fatalf("after renewal: %q, want new.test", got)
	}

	// A half-written renewal keeps the previous certificate.
	if err := os.WriteFile(keyFile, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyFile, base.Add(2*time.Minute), base.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(certRecheck)
	if got := servedCN(t, r); got != "new.test" {
		t.Fatalf("broken renewal: %q, want the previous new.test", got)
	}
}

func TestPublicTLSConfigRefusesMissingOrMismatchedFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := publicTLSConfig(filepath.Join(dir, "none.crt"), filepath.Join(dir, "none.key")); err == nil {
		t.Fatal("missing files accepted")
	}
	certFile, _ := writePair(t, dir, "a.test", time.Now())
	other := t.TempDir()
	_, keyFile := writePair(t, other, "b.test", time.Now())
	if _, err := publicTLSConfig(certFile, keyFile); err == nil {
		t.Fatal("a key that does not match the certificate was accepted")
	}
	_, keyA := writePair(t, dir, "a.test", time.Now())
	cfg, err := publicTLSConfig(certFile, keyA)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion < 0x0303 || len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != "h2" {
		t.Fatalf("public TLS config: min %x protos %v", cfg.MinVersion, cfg.NextProtos)
	}
}
