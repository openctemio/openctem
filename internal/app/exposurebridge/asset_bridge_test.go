package exposurebridge_test

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app/exposurebridge"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
)

func newAsset(t *testing.T, tenantID shared.ID, name string, at asset.AssetType, subType string, props map[string]any) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset(name, at, asset.CriticalityMedium)
	if err != nil {
		t.Fatalf("NewAsset: %v", err)
	}
	a.SetTenantID(tenantID)
	if subType != "" {
		a.SetSubType(subType)
	}
	if props != nil {
		a.SetProperties(props)
	}
	return a
}

func firstEventOfType(repo *fakeExposureRepo, et exposure.EventType) *exposure.ExposureEvent {
	for _, e := range repo.byID {
		if e.EventType() == et {
			return e
		}
	}
	return nil
}

func TestAssetBridge_ProjectsOpenPort(t *testing.T) {
	repo := newFakeExposureRepo()
	bridge := exposurebridge.NewAssetBridge(repo, nil, testLogger())

	tenantID := shared.NewID()
	// JSONB round-trips numbers as float64 — mimic that.
	a := newAsset(t, tenantID, "10.0.0.1:22", asset.AssetTypeService, "open_port", map[string]any{
		"port":     float64(22),
		"protocol": "tcp",
		"service":  "ssh",
		"host":     "10.0.0.1",
	})

	if err := bridge.ProjectAssets(context.Background(), tenantID, []*asset.Asset{a}); err != nil {
		t.Fatalf("ProjectAssets: %v", err)
	}

	ev := firstEventOfType(repo, exposure.EventTypePortOpen)
	if ev == nil {
		t.Fatalf("expected a port_open event, got %d events", len(repo.byID))
	}
	if ev.Source() != exposurebridge.SourceReconScan {
		t.Errorf("source = %q, want %q", ev.Source(), exposurebridge.SourceReconScan)
	}
	if ev.AssetID() == nil || ev.AssetID().String() != a.ID().String() {
		t.Errorf("asset link = %v, want %s", ev.AssetID(), a.ID().String())
	}
	if got := ev.Details()["port"]; got != 22 {
		t.Errorf("port detail = %v, want 22", got)
	}
	if got := ev.Details()["service"]; got != "ssh" {
		t.Errorf("service detail = %v, want ssh", got)
	}
}

func TestAssetBridge_PortReIngestDedupes(t *testing.T) {
	repo := newFakeExposureRepo()
	bridge := exposurebridge.NewAssetBridge(repo, nil, testLogger())

	tenantID := shared.NewID()
	props := map[string]any{"port": float64(443), "protocol": "tcp", "service": "https"}
	a := newAsset(t, tenantID, "10.0.0.2:443", asset.AssetTypeService, "open_port", props)

	if err := bridge.ProjectAssets(context.Background(), tenantID, []*asset.Asset{a}); err != nil {
		t.Fatalf("ProjectAssets #1: %v", err)
	}
	// Re-scan: same asset, same port → one event, one mark-seen update.
	if err := bridge.ProjectAssets(context.Background(), tenantID, []*asset.Asset{a}); err != nil {
		t.Fatalf("ProjectAssets #2: %v", err)
	}

	if repo.createCalls != 1 {
		t.Errorf("expected exactly 1 create across re-ingest, got %d", repo.createCalls)
	}
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 mark-seen update on re-ingest, got %d", repo.updateCalls)
	}
	if len(repo.byID) != 1 {
		t.Errorf("expected 1 exposure event after re-ingest, got %d", len(repo.byID))
	}
}

func TestAssetBridge_ProjectsExpiredCertificateAndWeakTLS(t *testing.T) {
	repo := newFakeExposureRepo()
	bridge := exposurebridge.NewAssetBridge(repo, nil, testLogger())

	tenantID := shared.NewID()
	past := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	a := newAsset(t, tenantID, "cert:example.com", asset.AssetTypeCertificate, "", map[string]any{
		"certificate": map[string]any{
			"subject_cn":  "example.com",
			"not_after":   past,
			"self_signed": true,
			"expired":     true,
		},
	})

	if err := bridge.ProjectAssets(context.Background(), tenantID, []*asset.Asset{a}); err != nil {
		t.Fatalf("ProjectAssets: %v", err)
	}

	// One expired event + one ssl_issue (self-signed) event.
	if firstEventOfType(repo, exposure.EventTypeCertificateExpired) == nil {
		t.Errorf("expected a certificate_expired event")
	}
	ssl := firstEventOfType(repo, exposure.EventTypeSSLIssue)
	if ssl == nil {
		t.Fatalf("expected an ssl_issue event")
	}
	if ssl.Severity() != exposure.SeverityMedium {
		t.Errorf("ssl_issue severity = %q, want medium", ssl.Severity())
	}
	if len(repo.byID) != 2 {
		t.Errorf("expected 2 exposure events (expired + ssl_issue), got %d", len(repo.byID))
	}
}

func TestAssetBridge_ProjectsExpiringCertificate(t *testing.T) {
	repo := newFakeExposureRepo()
	bridge := exposurebridge.NewAssetBridge(repo, nil, testLogger())

	tenantID := shared.NewID()
	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.RFC3339)
	a := newAsset(t, tenantID, "cert:soon.example.com", asset.AssetTypeCertificate, "", map[string]any{
		"certificate": map[string]any{
			"subject_cn": "soon.example.com",
			"not_after":  soon,
		},
	})

	if err := bridge.ProjectAssets(context.Background(), tenantID, []*asset.Asset{a}); err != nil {
		t.Fatalf("ProjectAssets: %v", err)
	}
	ev := firstEventOfType(repo, exposure.EventTypeCertificateExpiring)
	if ev == nil {
		t.Fatalf("expected a certificate_expiring event")
	}
	if ev.Severity() != exposure.SeverityMedium {
		t.Errorf("expiring severity = %q, want medium", ev.Severity())
	}
}

func TestAssetBridge_HealthyCertificateEmitsNothing(t *testing.T) {
	repo := newFakeExposureRepo()
	bridge := exposurebridge.NewAssetBridge(repo, nil, testLogger())

	tenantID := shared.NewID()
	future := time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	a := newAsset(t, tenantID, "cert:good.example.com", asset.AssetTypeCertificate, "", map[string]any{
		"certificate": map[string]any{
			"subject_cn":          "good.example.com",
			"not_after":           future,
			"self_signed":         false,
			"key_algorithm":       "RSA",
			"key_size":            float64(4096),
			"signature_algorithm": "SHA256-RSA",
		},
	})

	if err := bridge.ProjectAssets(context.Background(), tenantID, []*asset.Asset{a}); err != nil {
		t.Fatalf("ProjectAssets: %v", err)
	}
	if len(repo.byID) != 0 {
		t.Errorf("healthy certificate must emit no exposure, got %d", len(repo.byID))
	}
}

func TestAssetBridge_IgnoresIrrelevantAssetTypes(t *testing.T) {
	repo := newFakeExposureRepo()
	bridge := exposurebridge.NewAssetBridge(repo, nil, testLogger())

	tenantID := shared.NewID()
	a := newAsset(t, tenantID, "example.com", asset.AssetTypeDomain, "", nil)

	if err := bridge.ProjectAssets(context.Background(), tenantID, []*asset.Asset{a}); err != nil {
		t.Fatalf("ProjectAssets: %v", err)
	}
	if repo.createCalls != 0 || len(repo.byID) != 0 {
		t.Errorf("non port/service/cert asset must not project (creates=%d, events=%d)", repo.createCalls, len(repo.byID))
	}
}

func TestAssetBridge_SkipsCrossTenantAsset(t *testing.T) {
	repo := newFakeExposureRepo()
	bridge := exposurebridge.NewAssetBridge(repo, nil, testLogger())

	ingestTenant := shared.NewID()
	otherTenant := shared.NewID()
	// An asset whose tenant does not match the ingest tenant must never be
	// projected — tenant comes from the asset, guarded against the batch tenant.
	a := newAsset(t, otherTenant, "10.0.0.9:3389", asset.AssetTypeService, "open_port", map[string]any{
		"port": float64(3389), "protocol": "tcp", "service": "rdp",
	})

	if err := bridge.ProjectAssets(context.Background(), ingestTenant, []*asset.Asset{a}); err != nil {
		t.Fatalf("ProjectAssets: %v", err)
	}
	if repo.createCalls != 0 || len(repo.byID) != 0 {
		t.Errorf("cross-tenant asset must not project (creates=%d, events=%d)", repo.createCalls, len(repo.byID))
	}
}
