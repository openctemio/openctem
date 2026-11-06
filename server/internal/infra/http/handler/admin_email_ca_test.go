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
	"strings"
	"testing"
	"time"
)

func caPEMForTest(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Corp CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAdminEmailHandler_InternalCA(t *testing.T) {
	const path = "/api/v1/admin/settings/email"
	body := func(ca any) map[string]any {
		return map[string]any{"enabled": true, "host": "mail.corp.example", "port": 587, "from": "noreply@corp.example",
			"starttls": true, "version": 0, "totp_code": "123456", "ca_pem": ca}
	}
	t.Run("write-only: GET says set and the fingerprint, never the bundle", func(t *testing.T) {
		h := newEmailHandler(t, nil)
		rec := httptest.NewRecorder()
		h.Update(rec, emailRequest(t, http.MethodPut, path, body(caPEMForTest(t))))
		if rec.Code != http.StatusOK {
			t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
		}
		rec = httptest.NewRecorder()
		h.Get(rec, emailRequest(t, http.MethodGet, path, nil))
		out := rec.Body.String()
		if strings.Contains(out, "BEGIN CERTIFICATE") || strings.Contains(out, "ca_pem") ||
			!strings.Contains(out, `"ca_set":true`) || !strings.Contains(out, `"ca_fingerprint":"`) {
			t.Fatalf("GET: %s", out)
		}
	})
	t.Run("a private key or junk is a 400", func(t *testing.T) {
		for _, bad := range []string{"-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----", "hello"} {
			rec := httptest.NewRecorder()
			newEmailHandler(t, nil).Update(rec, emailRequest(t, http.MethodPut, path, body(bad)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%q: %d", bad, rec.Code)
			}
		}
	})
	t.Run("a failed test e-mail names the reason", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newEmailHandler(t, nil).SendTest(rec, emailRequest(t, http.MethodPost, path+"/test", nil))
		if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), `"reason":"not_configured"`) {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
	})
}
