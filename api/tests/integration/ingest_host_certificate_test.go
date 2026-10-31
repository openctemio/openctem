package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/exposurebridge"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// resetHostReport is what the sensor reports for a host that completed the
// TLS handshake and reset the HTTP request: the service with status 0 and
// the certificate it served (another party's expired default certificate).
func resetHostReport(fp string, leaf *ctis.CertificateTechnical, status int) *ctis.Report {
	return &ctis.Report{
		Version:  "1.0",
		Tool:     &ctis.Tool{Name: "httpx"},
		Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC()},
		Assets: []ctis.Asset{
			{
				ID: "http-promo", Type: ctis.AssetTypeHTTPService, Value: "https://promo.example.com", Name: "promo.example.com",
				Technical:     &ctis.AssetTechnical{Service: &ctis.ServiceTechnical{Port: 443, Protocol: "https", TLS: true, Transport: "tcp"}},
				Properties:    ctis.Properties{"tls_fingerprint": fp, "status_code": status},
				RelatedAssets: []string{"cert-" + fp[:16]},
			},
			{
				ID: "cert-" + fp[:16], Type: ctis.AssetTypeCertificate, Value: fp, Name: fp,
				Technical:  &ctis.AssetTechnical{Certificate: leaf},
				Properties: ctis.Properties{"fingerprint": fp, "subject_cn": leaf.SubjectCN},
			},
		},
	}
}

// A host that resets every request still gets its certificate exposures on
// the service (from the handshake), a re-scan that sees a good certificate
// resolves them, and another tenant's identical scan touches only its own.
func TestIngest_HostCertificateExposures(t *testing.T) {
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		svc.SetRelationshipRepository(postgres.NewAssetRelationshipRepository(db))
		bridge := exposurebridge.NewAssetBridge(postgres.NewExposureRepository(db), postgres.NewExposureStateHistoryRepository(db), logger.NewNop())
		bridge.SetAutoResolver(postgres.NewEASMDNSRepository(db))
		svc.SetAssetExposureProjector(bridge)
	})
	ctx := context.Background()
	ingestAs := func(tn v2Tenant, rep *ctis.Report) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		bind := ingest.Binding{Kind: ingest.BindingCommand, Targets: []string{"promo.example.com"}}
		out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	states := func(tn v2Tenant) map[string]string {
		t.Helper()
		rows, err := r.db.QueryContext(ctx, `
			SELECT e.event_type || ':' || COALESCE(e.details->>'issue', ''), e.state
			FROM exposure_events e JOIN assets a ON a.id = e.asset_id AND a.tenant_id = e.tenant_id
			WHERE e.tenant_id = $1 AND e.source = 'recon_scan' AND a.asset_type = 'service'
			  AND e.event_type IN ('certificate_expired', 'certificate_expiring', 'ssl_issue')`, tn.tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var k, s string
			if err := rows.Scan(&k, &s); err != nil {
				t.Fatal(err)
			}
			out[k] = s
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	const badFP = "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddee"
	const goodFP = "bb11223344556677889900aabbccddeeff00112233445566778899aabbccddee"
	nb, na := time.Now().Add(-800*24*time.Hour).UTC(), time.Now().Add(-400*24*time.Hour).UTC()
	bad := &ctis.CertificateTechnical{SubjectCN: "ssl.default.hosting.example.net", SANs: []string{"ssl.default.hosting.example.net"},
		IssuerCN: "Example CA", NotBefore: &nb, NotAfter: &na, Fingerprint: badFP, Expired: true}
	gnb, gna := time.Now().Add(-24*time.Hour).UTC(), time.Now().Add(200*24*time.Hour).UTC()
	good := &ctis.CertificateTechnical{SubjectCN: "promo.example.com", SANs: []string{"promo.example.com"},
		IssuerCN: "Example CA", NotBefore: &gnb, NotAfter: &gna, Fingerprint: goodFP}

	a, b := r.newTenant("httpx"), r.newTenant("httpx")
	ingestAs(a, resetHostReport(badFP, bad, 0))
	ingestAs(b, resetHostReport(badFP, bad, 0))
	got := states(a)
	if got["certificate_expired:"] != "active" || got["ssl_issue:foreign_certificate"] != "active" || len(got) != 2 {
		t.Fatalf("tenant A after the reset host: %v", got)
	}
	var takeover string
	if err := r.db.QueryRowContext(ctx, `SELECT details->>'takeover_candidate' FROM exposure_events
		WHERE tenant_id = $1 AND details->>'issue' = 'foreign_certificate'`, a.tenant.String()).Scan(&takeover); err != nil || takeover != "true" {
		t.Fatalf("takeover candidate %q %v", takeover, err)
	}

	// Re-scan: same certificate, nothing new.
	ingestAs(a, resetHostReport(badFP, bad, 0))
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM exposure_events WHERE tenant_id = $1 AND source = 'recon_scan'
		AND event_type IN ('certificate_expired', 'ssl_issue')`, a.tenant.String()).Scan(&n); err != nil || n != 2 {
		t.Fatalf("after a re-scan: %d host certificate exposures (%v)", n, err)
	}

	// The host now serves a good certificate: tenant A's exposures resolve,
	// tenant B's stay open.
	ingestAs(a, resetHostReport(goodFP, good, 200))
	got = states(a)
	if got["certificate_expired:"] != "resolved" || got["ssl_issue:foreign_certificate"] != "resolved" {
		t.Fatalf("tenant A after a good certificate: %v", got)
	}
	if gb := states(b); gb["certificate_expired:"] != "active" || gb["ssl_issue:foreign_certificate"] != "active" {
		t.Fatalf("tenant B changed by tenant A's scan: %v", gb)
	}
}
