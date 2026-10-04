package handler

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// The audit log records who did what from where. A client that is not a
// trusted proxy must not be able to choose the recorded IP by sending
// X-Forwarded-For / X-Real-IP (S-4). Every handler-built audit context goes
// through the same trusted-proxy rule.
func TestAuditContexts_IgnoreForwardingHeadersFromUntrustedPeer(t *testing.T) {
	SetAuthTrustedProxies(nil)
	t.Cleanup(func() { SetAuthTrustedProxies(nil) })

	req := httptest.NewRequest("POST", "/api/v1/sensors", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "5.6.7.8")

	const want = "203.0.113.9"
	got := map[string]string{
		"sensor":            (&SensorHandler{}).buildAuditContext(req).ActorIP,
		"asset":             (&AssetHandler{}).buildAuditContext(req).ActorIP,
		"credential_import": (&CredentialImportHandler{}).buildAuditContext(req).ActorIP,
		"finding_evidence":  (&VulnerabilityHandler{}).buildAuditContext(req).ActorIP,
		"remediation":       (&RemediationCampaignHandler{}).buildAuditContext(req).ActorIP,
		"mcp":               auditClientIP(req),
		"scan_zone":         buildScanZoneAuditContext(req).ActorIP,
	}
	for name, ip := range got {
		if ip != want {
			t.Errorf("%s audit IP = %q, want the TCP peer %q (forwarding headers from an untrusted peer must be ignored)", name, ip, want)
		}
	}
}

func TestAuditContexts_HonorForwardingHeadersFromTrustedProxy(t *testing.T) {
	SetAuthTrustedProxies(httpsec.NewTrustedProxySet([]string{"10.0.0.0/8"}))
	t.Cleanup(func() { SetAuthTrustedProxies(nil) })

	req := httptest.NewRequest("POST", "/api/v1/sensors", nil)
	req.RemoteAddr = "10.1.2.3:4444"
	req.Header.Set("X-Real-IP", "198.51.100.7")

	if ip := (&SensorHandler{}).buildAuditContext(req).ActorIP; ip != "198.51.100.7" {
		t.Errorf("audit IP behind a trusted proxy = %q, want the forwarded client 198.51.100.7", ip)
	}
	if ip := buildScanZoneAuditContext(req).ActorIP; ip != "198.51.100.7" {
		t.Errorf("scan zone audit IP behind a trusted proxy = %q, want the forwarded client 198.51.100.7", ip)
	}
}

// The scan zone handler used to copy the raw X-Forwarded-For header into the
// audit log, so any caller chose the recorded IP (and a multi-hop chain was
// stored whole). It must behave exactly like every other audit path.
func TestScanZoneAuditContext_ForgedForwardedFor(t *testing.T) {
	t.Cleanup(func() { SetAuthTrustedProxies(nil) })

	t.Run("untrusted peer records the socket peer", func(t *testing.T) {
		SetAuthTrustedProxies(httpsec.NewTrustedProxySet([]string{"10.0.0.10"}))
		req := httptest.NewRequest("POST", "/api/v1/scan-zones", nil)
		req.RemoteAddr = "203.0.113.9:4444"
		req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.10")
		req.Header.Set("X-Real-IP", "5.6.7.8")
		if ip := buildScanZoneAuditContext(req).ActorIP; ip != "203.0.113.9" {
			t.Errorf("ActorIP = %q, want the TCP peer 203.0.113.9", ip)
		}
	})

	t.Run("trusted appending proxy records the client it saw, not the forged entry", func(t *testing.T) {
		SetAuthTrustedProxies(httpsec.NewTrustedProxySet([]string{"10.0.0.10"}))
		req := httptest.NewRequest("POST", "/api/v1/scan-zones", nil)
		req.RemoteAddr = "10.0.0.10:4444"
		req.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.9")
		if ip := buildScanZoneAuditContext(req).ActorIP; ip != "198.51.100.9" {
			t.Errorf("ActorIP = %q, want the proxy-appended client 198.51.100.9", ip)
		}
	})
}

// Password logins carry an email but no preferred username; the audit actor
// must still be named (it was blank, and the UI showed "System").
func TestAuditActorEmail_PrefersEmailFallsBackToUsername(t *testing.T) {
	ctx := context.WithValue(context.Background(), middleware.EmailKey, "owner@example.com")
	if got := auditActorEmail(ctx); got != "owner@example.com" {
		t.Errorf("auditActorEmail = %q, want the login email", got)
	}
	ctx = context.WithValue(context.Background(), middleware.UsernameKey, "oidc-user")
	if got := auditActorEmail(ctx); got != "oidc-user" {
		t.Errorf("auditActorEmail without email = %q, want the username", got)
	}
}
