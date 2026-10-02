package email

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTLSConfig_Floor(t *testing.T) {
	cfg := TLSConfig("smtp.example.com", false)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x, want TLS 1.2", cfg.MinVersion)
	}
	if cfg.ServerName != "smtp.example.com" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("verification must stay on unless the operator opts out")
	}
	if !TLSConfig("h", true).InsecureSkipVerify {
		t.Fatal("skipVerify opt-out is not honored")
	}
}

// A relay that only speaks TLS 1.0/1.1 is refused; a TLS 1.2 relay works.
func TestTLSConfig_RefusesLegacyProtocols(t *testing.T) {
	dial := func(serverMax uint16) error {
		srv := httptest.NewUnstartedServer(http.NotFoundHandler())
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: serverMax} //nolint:gosec // G402: deliberately legacy test server
		srv.StartTLS()
		defer srv.Close()
		addr := strings.TrimPrefix(srv.URL, "https://")
		// skipVerify: the test server's certificate is self-signed.
		conn, err := tls.Dial("tcp", addr, TLSConfig("127.0.0.1", true))
		if err == nil {
			_ = conn.Close()
		}
		return err
	}
	if err := dial(tls.VersionTLS11); err == nil {
		t.Fatal("handshake with a TLS 1.1-only server must fail")
	}
	if err := dial(tls.VersionTLS12); err != nil {
		t.Fatalf("handshake with a TLS 1.2 server failed: %v", err)
	}
}
