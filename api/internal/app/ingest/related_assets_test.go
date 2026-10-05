package ingest

import (
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func certReport(related ...string) *ctis.Report {
	return &ctis.Report{Assets: []ctis.Asset{
		{ID: "svc", Type: ctis.AssetTypeHTTPService, Value: "https://example.com", RelatedAssets: related},
		{ID: "cert", Type: ctis.AssetTypeCertificate, Value: strings.Repeat("a", 64)},
		{ID: "dom", Type: ctis.AssetTypeDomain, Value: "example.com"},
	}}
}

func TestRelatedAssetRelationships(t *testing.T) {
	tenant := shared.NewID()
	ids := map[string]shared.ID{"svc": shared.NewID(), "cert": shared.NewID(), "dom": shared.NewID()}
	all := map[string]bool{"svc": true, "cert": true, "dom": true}

	t.Run("service to its certificate", func(t *testing.T) {
		rels := relatedAssetRelationships(tenant, certReport("cert", "cert"), ids, all)
		if len(rels) != 1 {
			t.Fatalf("relationships = %d, want 1 (deduplicated)", len(rels))
		}
		r := rels[0]
		if r.Type() != asset.RelTypeServesCertificate || r.SourceAssetID() != ids["svc"] || r.TargetAssetID() != ids["cert"] || r.TenantID() != tenant {
			t.Errorf("relationship = %s %s -> %s (tenant %s)", r.Type(), r.SourceAssetID(), r.TargetAssetID(), r.TenantID())
		}
	})

	t.Run("links ingest has no meaning for are ignored", func(t *testing.T) {
		if rels := relatedAssetRelationships(tenant, certReport("dom", "missing", "svc"), ids, all); len(rels) != 0 {
			t.Errorf("relationships = %d, want 0", len(rels))
		}
		rep := certReport()
		rep.Assets[2].RelatedAssets = []string{"cert"} // a domain is not a service
		if rels := relatedAssetRelationships(tenant, rep, ids, all); len(rels) != 0 {
			t.Errorf("domain -> certificate: %d relationships, want 0", len(rels))
		}
	})

	t.Run("a source the report may not change gets no edge", func(t *testing.T) {
		if rels := relatedAssetRelationships(tenant, certReport("cert"), ids, map[string]bool{"cert": true}); len(rels) != 0 {
			t.Errorf("relationships = %d, want 0", len(rels))
		}
	})

	t.Run("an end that was not stored gets no edge", func(t *testing.T) {
		if rels := relatedAssetRelationships(tenant, certReport("cert"), map[string]shared.ID{"svc": ids["svc"]}, all); len(rels) != 0 {
			t.Errorf("relationships = %d, want 0", len(rels))
		}
	})

	t.Run("fan-out is bounded", func(t *testing.T) {
		rep := &ctis.Report{}
		svc := ctis.Asset{ID: "svc", Type: ctis.AssetTypeHTTPService, Value: "https://example.com"}
		m := map[string]shared.ID{"svc": shared.NewID()}
		refs := map[string]bool{"svc": true}
		var certs []ctis.Asset
		for i := 0; i < 5000; i++ {
			id := fmt.Sprintf("c%d", i)
			svc.RelatedAssets = append(svc.RelatedAssets, id)
			certs = append(certs, ctis.Asset{ID: id, Type: ctis.AssetTypeCertificate, Value: fmt.Sprintf("%064d", i)})
			m[id] = shared.NewID()
		}
		rep.Assets = append([]ctis.Asset{svc}, certs...)
		if rels := relatedAssetRelationships(tenant, rep, m, refs); len(rels) != maxRelatedPerAsset {
			t.Errorf("relationships = %d, want capped at %d", len(rels), maxRelatedPerAsset)
		}
	})
}

// A certificate's text is chosen by the scanned server: capped and cleaned
// on every ingest path, whatever produced the report.
func TestCapReportText_Certificate(t *testing.T) {
	sans := make([]string, 10_000)
	for i := range sans {
		sans[i] = fmt.Sprintf("h%d.example.com", i)
	}
	sans[0] = "evil\n.example.com\x1b[2J"
	ct := &ctis.CertificateTechnical{
		SubjectCN: strings.Repeat("x", 100_000), IssuerCN: "R11\nINFO forged\x00",
		SerialNumber: strings.Repeat("9", 5000), SANs: sans,
	}
	rep := &ctis.Report{Assets: []ctis.Asset{{Type: ctis.AssetTypeCertificate, Value: "x", Technical: &ctis.AssetTechnical{Certificate: ct}}}}
	if capReportText(rep) == 0 {
		t.Fatal("nothing capped")
	}
	if n := len([]rune(ct.SubjectCN)); n > MaxCertNameLen {
		t.Errorf("subject CN %d runes", n)
	}
	if len([]rune(ct.SerialNumber)) > MaxCertSerialLen {
		t.Errorf("serial not capped")
	}
	if ct.IssuerCN != "R11INFO forged" {
		t.Errorf("issuer CN = %q", ct.IssuerCN)
	}
	if len(ct.SANs) != MaxCertSANs || ct.SANs[0] != "evil.example.com[2J" {
		t.Errorf("SANs = %d, first %q", len(ct.SANs), ct.SANs[0])
	}
}
