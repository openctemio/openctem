package ingest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeCertPromoter struct {
	calls  int
	tenant shared.ID
	tool   string
	certs  []CertificateNames
	err    error
}

func (f *fakeCertPromoter) PromoteCertificateNames(_ context.Context, tenantID shared.ID, tool string, certs []CertificateNames) (int, error) {
	f.calls++
	f.tenant, f.tool, f.certs = tenantID, tool, certs
	return len(certs), f.err
}

// Only the certificates this ingest persisted are handed over, with names
// from the technical block and the flat properties, deduplicated and capped.
func TestReportCertificateNames(t *testing.T) {
	na := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	many := make([]string, 0, 150)
	for i := range 150 {
		many = append(many, fmt.Sprintf("h%d.example.com", i))
	}
	report := &ctis.Report{Assets: []ctis.Asset{
		{ID: "c1", Type: ctis.AssetTypeCertificate, Value: "fp1", Technical: &ctis.AssetTechnical{Certificate: &ctis.CertificateTechnical{
			SubjectCN: "www.example.com", SANs: []string{"www.example.com", "api.example.com"}, IssuerOrg: "CA", NotAfter: &na,
		}}},
		{ID: "c2", Type: ctis.AssetTypeCertificate, Value: "fp2", Properties: ctis.Properties{
			"subject_cn": "mail.example.com", "sans": []any{"mail.example.com", "smtp.example.com", 7},
			"issuer_cn": "Other CA", "not_after": na.Format(time.RFC3339),
		}},
		{ID: "c3", Type: ctis.AssetTypeCertificate, Value: "fp3", Properties: ctis.Properties{"sans": many}},
		{ID: "refused", Type: ctis.AssetTypeCertificate, Value: "fp4", Properties: ctis.Properties{"sans": []string{"x.example.com"}}},
		{ID: "sub", Type: ctis.AssetTypeSubdomain, Value: "y.example.com"},
		{ID: "empty", Type: ctis.AssetTypeCertificate, Value: "fp5"},
	}}
	ids := map[string]shared.ID{"c1": shared.NewID(), "c2": shared.NewID(), "c3": shared.NewID(), "sub": shared.NewID(), "empty": shared.NewID()}
	got := reportCertificateNames(report, ids)
	if len(got) != 3 {
		t.Fatalf("got %d certificates, want 3: %+v", len(got), got)
	}
	if got[0].AssetID != ids["c1"] || len(got[0].Names) != 2 || got[0].Issuer != "CA" || got[0].NotAfter == nil {
		t.Errorf("c1 = %+v", got[0])
	}
	if len(got[1].Names) != 2 || got[1].Issuer != "Other CA" || got[1].NotAfter == nil || !got[1].NotAfter.Equal(na) {
		t.Errorf("c2 = %+v", got[1])
	}
	if len(got[2].Names) != maxNamesPerCertificate {
		t.Errorf("c3 names = %d, want the cap %d", len(got[2].Names), maxNamesPerCertificate)
	}
}

// The hook passes the ingest's tenant and tool, skips CI-run reports, and a
// promoter failure never fails the ingest.
func TestPromoteCertificateNamesHook(t *testing.T) {
	tenant := shared.NewID()
	report := &ctis.Report{Tool: &ctis.Tool{Name: "httpx"}, Assets: []ctis.Asset{
		{ID: "c1", Type: ctis.AssetTypeCertificate, Value: "fp1", Properties: ctis.Properties{"sans": []string{"www.example.com"}}},
	}}
	ids := map[string]shared.ID{"c1": shared.NewID()}

	p := &fakeCertPromoter{}
	s := &Service{logger: logger.NewNop(), certNames: p}
	s.promoteCertificateNames(context.Background(), tenant, Binding{Kind: BindingCommand}, report, ids)
	if p.calls != 1 || p.tenant != tenant || p.tool != "httpx" || len(p.certs) != 1 {
		t.Fatalf("promoter call = %+v", p)
	}
	s.promoteCertificateNames(context.Background(), tenant, Binding{Kind: BindingCIRun}, report, ids)
	if p.calls != 1 {
		t.Error("a CI-run report was promoted")
	}
	p.err = errors.New("db down")
	s.promoteCertificateNames(context.Background(), tenant, Binding{Kind: BindingUnsolicited}, report, ids) // logged only
	(&Service{logger: logger.NewNop()}).promoteCertificateNames(context.Background(), tenant, Binding{}, report, ids)
}
