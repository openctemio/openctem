package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A scanner that reports the raw secret as its "masked value" must not get it
// returned by GET /findings/{id}: only the 4+4 preview and the fingerprint.
func TestGetFinding_NeverReturnsTheRawSecret(t *testing.T) {
	const raw = "fake-token-51HxyzABCDEFGHIJKLMNOPQRSTUV1234Qx"
	tenant, asset := shared.NewID(), shared.NewID()
	f, err := vulnerability.NewFinding(tenant, asset, vulnerability.FindingSourceSecret, "betterleaks",
		vulnerability.SeverityCritical, "Stripe key committed")
	if err != nil {
		t.Fatal(err)
	}
	f.SetFindingType(vulnerability.FindingTypeSecret)
	f.SetSecretType("api_key")
	f.SetSecretService("Stripe")
	f.SetSecretMaskedValue(raw)
	f.SetSecretFingerprint(vulnerability.NewSecretFingerprinter([]byte("server-secret")).Fingerprint(tenant, raw))

	svc := finding.NewVulnerabilityService(&detailVulnRepo{}, &detailFindingRepo{f: f}, logger.NewNop())
	h := NewVulnerabilityHandler(svc, nil, logger.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+f.ID().String(), nil)
	req.SetPathValue("id", f.ID().String())
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
	ctx = context.WithValue(ctx, middleware.IsAdminKey, true)
	rr := httptest.NewRecorder()
	h.GetFinding(rr, req.WithContext(ctx))

	body := rr.Body.String()
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, body)
	}
	for _, leak := range []string{raw, raw[4 : len(raw)-4], "ABCDEFGH"} {
		if strings.Contains(body, leak) {
			t.Fatalf("response contains the secret (%q): %s", leak, body)
		}
	}
	if !strings.Contains(body, `"secret_masked_value":"fake…34Qx"`) || !strings.Contains(body, `"secret_fingerprint":"`) {
		t.Fatalf("preview or fingerprint missing: %s", body)
	}
}
