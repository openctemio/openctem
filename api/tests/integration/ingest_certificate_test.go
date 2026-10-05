package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

const certFP = "85ca6ab068e9bcce88b6c4aa3c47f7d17228134a457f870d3800e6223a0df07a"

// certProbeReport is what the recon converter writes for an httpx probe with
// -tls-grab (ctis ConvertReconToCTIS): the http_service links the leaf
// certificate, named by its SHA-256 fingerprint.
func certProbeReport(leaf *ctis.CertificateTechnical) *ctis.Report {
	return &ctis.Report{
		Version:  "1.0",
		Tool:     &ctis.Tool{Name: "httpx"},
		Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC()},
		Assets: []ctis.Asset{
			{
				ID: "http-example", Type: ctis.AssetTypeHTTPService, Value: "https://example.com", Name: "https://example.com",
				Technical:     &ctis.AssetTechnical{Service: &ctis.ServiceTechnical{Port: 443, Protocol: "https", TLS: true, Transport: "tcp"}},
				Properties:    ctis.Properties{"tls_fingerprint": certFP, "cdn": "cloudflare", "hosted_by": "cloudflare", "jarm": "27d40d40d00040d1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c"},
				RelatedAssets: []string{"cert-" + certFP[:16]},
			},
			{
				ID: "cert-" + certFP[:16], Type: ctis.AssetTypeCertificate, Value: certFP, Name: certFP,
				Technical:  &ctis.AssetTechnical{Certificate: leaf},
				Properties: ctis.Properties{"fingerprint": certFP, "subject_cn": leaf.SubjectCN},
			},
		},
	}
}

func testLeafCert() *ctis.CertificateTechnical {
	na := time.Now().Add(20 * 24 * time.Hour).UTC().Truncate(time.Second)
	nb := time.Now().Add(-60 * 24 * time.Hour).UTC().Truncate(time.Second)
	return &ctis.CertificateTechnical{
		SubjectCN: "example.com", SANs: []string{"example.com", "*.example.com"},
		IssuerCN: "Cloudflare TLS Issuing ECC CA 3", IssuerOrg: "SSL Corporation",
		NotBefore: &nb, NotAfter: &na, Fingerprint: certFP, Wildcard: true,
	}
}

// research/22 E5: an HTTPS probe's leaf certificate becomes one certificate
// asset linked to the service (serves_certificate) with its expiry; a
// re-scan creates no duplicate; another tenant's identical certificate is
// that tenant's own asset; the server-chosen text is bounded.
func TestIngest_HTTPProbeCertificate(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	db := &postgres.DB{DB: r.db}
	r.svc.SetRelationshipRepository(postgres.NewAssetRelationshipRepository(db))
	ctx := context.Background()

	ingestAs := func(tn v2Tenant, rep *ctis.Report) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		bind := ingest.Binding{Kind: ingest.BindingCommand, Targets: []string{"example.com"}}
		out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	certs := func(tn v2Tenant) []string {
		t.Helper()
		rows, err := r.db.QueryContext(ctx, `SELECT id FROM assets WHERE tenant_id = $1 AND asset_type = 'certificate'`, tn.tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return ids
	}
	edges := func(tn v2Tenant) [][2]string {
		t.Helper()
		rows, err := r.db.QueryContext(ctx, `
			SELECT s.asset_type, t.id FROM asset_relationships rel
			JOIN assets s ON s.id = rel.source_asset_id AND s.tenant_id = rel.tenant_id
			JOIN assets t ON t.id = rel.target_asset_id AND t.tenant_id = rel.tenant_id
			WHERE rel.tenant_id = $1 AND rel.relationship_type = 'serves_certificate'`, tn.tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out [][2]string
		for rows.Next() {
			var e [2]string
			if err := rows.Scan(&e[0], &e[1]); err != nil {
				t.Fatal(err)
			}
			out = append(out, e)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	a := r.newTenant("httpx")
	ingestAs(a, certProbeReport(testLeafCert()))
	aCerts := certs(a)
	if len(aCerts) != 1 {
		t.Fatalf("tenant A: %d certificate assets, want 1", len(aCerts))
	}
	var name, notAfter, subject string
	if err := r.db.QueryRowContext(ctx, `SELECT name, properties->'certificate'->>'not_after', properties->'certificate'->>'subject_cn'
		FROM assets WHERE id = $1 AND tenant_id = $2`, aCerts[0], a.tenant.String()).Scan(&name, &notAfter, &subject); err != nil {
		t.Fatal(err)
	}
	if name != certFP || notAfter == "" || subject != "example.com" {
		t.Errorf("certificate asset name %q not_after %q subject %q", name, notAfter, subject)
	}
	if e := edges(a); len(e) != 1 || e[0][1] != aCerts[0] || e[0][0] != "service" {
		t.Fatalf("tenant A edges = %v, want one service -> %s", e, aCerts[0])
	}
	var hostedBy string
	if err := r.db.QueryRowContext(ctx, `SELECT properties->>'hosted_by' FROM assets WHERE tenant_id = $1 AND asset_type = 'service'`,
		a.tenant.String()).Scan(&hostedBy); err != nil || hostedBy != "cloudflare" {
		t.Errorf("service hosted_by = %q (%v)", hostedBy, err)
	}

	// A re-scan: no duplicate certificate, no duplicate edge.
	ingestAs(a, certProbeReport(testLeafCert()))
	if n := len(certs(a)); n != 1 {
		t.Errorf("after a re-scan: %d certificate assets, want 1", n)
	}
	if n := len(edges(a)); n != 1 {
		t.Errorf("after a re-scan: %d edges, want 1", n)
	}

	// Another tenant seeing the same certificate gets its own asset and edge;
	// tenant A's are untouched.
	b := r.newTenant("httpx")
	ingestAs(b, certProbeReport(testLeafCert()))
	bCerts := certs(b)
	if len(bCerts) != 1 || bCerts[0] == aCerts[0] {
		t.Fatalf("tenant B certificates %v (tenant A %v): want B's own", bCerts, aCerts)
	}
	if e := edges(b); len(e) != 1 || e[0][1] != bCerts[0] {
		t.Errorf("tenant B edges = %v, want one to %s", e, bCerts[0])
	}
	if n := len(certs(a)); n != 1 || len(edges(a)) != 1 {
		t.Errorf("tenant A changed by tenant B's ingest: %d certificates, %d edges", n, len(edges(a)))
	}

	// Hostile values from the scanned server are bounded and cleaned.
	c := r.newTenant("httpx")
	leaf := testLeafCert()
	leaf.SubjectCN = strings.Repeat("x", 100_000) + "\x1b[31m"
	leaf.IssuerCN = "evil\nINFO forged"
	leaf.SANs = make([]string, 10_000)
	for i := range leaf.SANs {
		leaf.SANs[i] = fmt.Sprintf("h%d.example.com", i)
	}
	ingestAs(c, certProbeReport(leaf))
	var cnLen, sanCount int
	var issuer string
	if err := r.db.QueryRowContext(ctx, `SELECT char_length(properties->'certificate'->>'subject_cn'),
			jsonb_array_length(properties->'certificate'->'sans'), properties->'certificate'->>'issuer_cn'
		FROM assets WHERE tenant_id = $1 AND asset_type = 'certificate'`, c.tenant.String()).Scan(&cnLen, &sanCount, &issuer); err != nil {
		t.Fatal(err)
	}
	if cnLen > ingest.MaxCertNameLen || sanCount > ingest.MaxCertSANs || strings.ContainsAny(issuer, "\n\x1b") {
		t.Errorf("hostile certificate stored unbounded: cn %d runes, %d SANs, issuer %q", cnLen, sanCount, issuer)
	}
}
