package unit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// The console states remediation windows from the API only. These tests pin
// the effective-policy contract: the tenant's own policy, else the platform
// defaults, and never another tenant's policy.

func TestGetEffectiveTenantPolicy_TenantDefault(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)
	tenantID := shared.NewID()
	own := makeTestPolicy(tenantID, "Ours", true)
	repo.policies[own.ID().String()] = own

	ep, err := svc.GetEffectiveTenantPolicy(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep.PlatformDefault || ep.Policy.ID() != own.ID() {
		t.Fatalf("want the tenant default policy, got platform=%v id=%s", ep.PlatformDefault, ep.Policy.ID())
	}
}

func TestGetEffectiveTenantPolicy_PlatformDefaultsWhenNone(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)

	ep, err := svc.GetEffectiveTenantPolicy(context.Background(), shared.NewID().String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ep.PlatformDefault {
		t.Fatal("want the platform defaults when no policy is configured")
	}
	for class, days := range sladom.DefaultPriorityDays {
		if got := ep.Policy.GetDaysForPriorityClass(class); got != days {
			t.Errorf("%s: got %d days, want %d", class, got, days)
		}
	}
}

func TestGetEffectiveTenantPolicy_IgnoresOtherTenantsPolicy(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)
	other := makeTestPolicy(shared.NewID(), "Theirs", true)
	repo.policies[other.ID().String()] = other

	ep, err := svc.GetEffectiveTenantPolicy(context.Background(), shared.NewID().String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ep.PlatformDefault || ep.Policy.ID() == other.ID() {
		t.Fatal("another tenant's default policy must never be returned")
	}
}

func TestGetEffectiveTenantPolicy_RepositoryErrorIsNotMasked(t *testing.T) {
	repo := newMockSLARepo()
	repo.getDefault = errors.New("db down")
	svc := newTestSLAService(repo)

	if _, err := svc.GetEffectiveTenantPolicy(context.Background(), shared.NewID().String()); err == nil {
		t.Fatal("a repository failure must not be reported as the platform defaults")
	}
}

func TestGetEffectiveTenantPolicy_InvalidTenant(t *testing.T) {
	svc := newTestSLAService(newMockSLARepo())
	_, err := svc.GetEffectiveTenantPolicy(context.Background(), "bad-uuid")
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
}

func TestGetEffectiveAssetPolicy_OverrideThenPlatform(t *testing.T) {
	repo := newMockSLARepo()
	svc := newTestSLAService(repo)
	tenantID := shared.NewID()
	assetID := shared.NewID()
	override := makeTestPolicyWithAsset(tenantID, assetID, "Asset")
	repo.policies[override.ID().String()] = override

	ep, err := svc.GetEffectiveAssetPolicy(context.Background(), tenantID.String(), assetID.String())
	if err != nil || ep.PlatformDefault || ep.Policy.ID() != override.ID() {
		t.Fatalf("want the asset override, got %+v err=%v", ep, err)
	}

	// The same asset id seen from another tenant gets no override.
	ep, err = svc.GetEffectiveAssetPolicy(context.Background(), shared.NewID().String(), assetID.String())
	if err != nil || !ep.PlatformDefault {
		t.Fatalf("want the platform defaults for another tenant, got %+v err=%v", ep, err)
	}
}

func TestSLAHandler_GetDefault_PlatformDefaults(t *testing.T) {
	h := handler.NewSLAHandler(newTestSLAService(newMockSLARepo()), validator.New(), logger.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sla-policies/default", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, shared.NewID().String()))
	rec := httptest.NewRecorder()

	h.GetDefault(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp handler.SLAPolicyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.IsPlatformDefault || resp.ID != "" {
		t.Fatalf("want is_platform_default with no id, got %+v", resp)
	}
	if resp.P0Days != sladom.DefaultPriorityDays["P0"] || resp.P3Days != sladom.DefaultPriorityDays["P3"] {
		t.Fatalf("priority windows %d..%d do not match the platform defaults", resp.P0Days, resp.P3Days)
	}
}

func TestSLAHandler_GetDefault_TenantPolicy(t *testing.T) {
	repo := newMockSLARepo()
	tenantID := shared.NewID()
	own := makeTestPolicy(tenantID, "Ours", true)
	repo.policies[own.ID().String()] = own
	h := handler.NewSLAHandler(newTestSLAService(repo), validator.New(), logger.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sla-policies/default", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, tenantID.String()))
	rec := httptest.NewRecorder()

	h.GetDefault(rec, req)

	var resp handler.SLAPolicyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.IsPlatformDefault || resp.ID != own.ID().String() {
		t.Fatalf("want the tenant policy, got %+v", resp)
	}
}
