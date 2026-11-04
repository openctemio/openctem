package integration

// Identity version 4: a compliance framework is keyed as its CTIS registry
// token. A finding stored from a free-text spelling ("PCI-DSS"), by a 1.x
// release (version-1 key, no tuple) or by the version-3 ingest (a tuple
// with the spelling), is re-keyed by the start-up runner onto the key a
// CTIS 2.0 report ("pci_dss") gives, keeping its id and triage. The re-key
// never reaches another tenant.

import (
	"context"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/refingerprint"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func complianceFinding(framework string) ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeCompliance, Kind: "fail", Title: "Firewall rule review", Severity: ctis.SeverityMedium,
		RuleID: "pci-1.2.1", Location: &ctis.FindingLocation{Path: "infra/fw.tf"},
		Compliance: &ctis.ComplianceDetails{Framework: ctis.ComplianceFramework(framework), ControlID: "1.2.1"}}
}

func TestIdentityV4_FreeTextFrameworkMeetsTheRegistryToken(t *testing.T) {
	g := newGoldenRig(t)
	svc := rekeyService(&mergeFixture{t: t, db: g.r.db})
	ctx := context.Background()
	file := goldenFile{Tool: "checkov"}
	file.Asset.Type, file.Asset.Value = ctis.AssetTypeHost, "pci.example.com"

	for _, stored := range []string{"version 1", "version 3"} {
		t.Run(stored, func(t *testing.T) {
			a, b := g.r.newTenant("checkov"), g.r.newTenant("checkov")
			// CTIS 2.0 refuses a free-text framework: a "PCI-DSS" row is one a
			// 1.x release stored. The row is created, then written as it was.
			g.ingest(t, a, file, "checkov", complianceFinding("pci_dss"))
			rows := v3Rows(t, g, a)
			if len(rows) != 1 {
				t.Fatalf("%d findings, want 1", len(rows))
			}
			var id, asset string
			for k := range rows {
				id = k
			}
			if err := g.r.db.QueryRowContext(context.Background(), `SELECT asset_id FROM findings WHERE id = $1`, id).Scan(&asset); err != nil {
				t.Fatal(err)
			}
			execOK(t, g, `UPDATE findings SET compliance_framework = 'PCI-DSS' WHERE id = $1`, id)
			f := complianceFinding("PCI-DSS")
			switch stored {
			case "version 1":
				v1 := ingest.VersionOneFingerprint(shared.MustIDFromString(asset), &f, &ctis.Tool{Name: "checkov"})
				execOK(t, g, `UPDATE findings SET fingerprint = $2, fingerprint_version = 1, identity_key = NULL,
					identity_algo = NULL, identity_fields = NULL WHERE id = $1`, id, v1)
				execOK(t, g, `DELETE FROM finding_fingerprints WHERE finding_id = $1 AND fingerprint <> $2`, id, v1)
			case "version 3":
				k3 := vulnerability.IdentityKey{Version: 3, Kind: vulnerability.IdentityKindCompliance, Fields: []vulnerability.IdentityField{
					{Name: vulnerability.IdentityFieldAsset, Value: asset}, {Name: "framework", Value: "PCI-DSS"},
					{Name: "control", Value: "1.2.1"}, {Name: "resource", Value: "infra/fw.tf"}}}
				raw, err := vulnerability.MarshalIdentityKey(k3)
				if err != nil {
					t.Fatal(err)
				}
				execOK(t, g, `UPDATE findings SET fingerprint = $2, fingerprint_version = 3, identity_key = $3::jsonb WHERE id = $1`,
					id, k3.Fingerprint(), string(raw))
				execOK(t, g, `DELETE FROM finding_fingerprints WHERE finding_id = $1 AND fingerprint <> $2`, id, k3.Fingerprint())
			}
			execOK(t, g, `UPDATE findings SET status = 'false_positive', resolution = 'false_positive' WHERE id = $1`, id)

			// Tenant B has the same control under the free-text spelling, as
			// a 1.x release stored it.
			g.ingest(t, b, file, "checkov", complianceFinding("pci_dss"))
			for bid := range v3Rows(t, g, b) {
				var bAsset string
				if err := g.r.db.QueryRowContext(context.Background(), `SELECT asset_id FROM findings WHERE id = $1`, bid).Scan(&bAsset); err != nil {
					t.Fatal(err)
				}
				v1 := ingest.VersionOneFingerprint(shared.MustIDFromString(bAsset), &f, &ctis.Tool{Name: "checkov"})
				execOK(t, g, `UPDATE findings SET compliance_framework = 'PCI-DSS', fingerprint = $2, fingerprint_version = 1,
					identity_key = NULL, identity_algo = NULL, identity_fields = NULL WHERE id = $1`, bid, v1)
			}
			bBefore := v3Rows(t, g, b)

			if _, err := svc.Run(ctx, a.tenant, refingerprint.Options{Apply: true}); err != nil {
				t.Fatal(err)
			}
			after := v3Rows(t, g, a)
			if r, ok := after[id]; !ok || r.version != vulnerability.IdentityVersion {
				t.Fatalf("after the re-key %+v, want %s at version %d", after, id, vulnerability.IdentityVersion)
			}

			// A CTIS 2.0 report of the same control, with the registry token.
			g.ingest(t, a, file, "checkov", complianceFinding("pci_dss"))
			live := v3Rows(t, g, a)
			if len(live) != 1 {
				t.Fatalf("%d findings after the 2.0 report, want 1 (%v)", len(live), live)
			}
			if r, ok := live[id]; !ok || r.status != "false_positive" {
				t.Fatalf("the 2.0 report landed on %v, want finding %s with its triage", live, id)
			}

			// Cross-tenant: tenant B's finding is untouched by A's re-key.
			bAfter := v3Rows(t, g, b)
			if len(bAfter) != len(bBefore) {
				t.Fatalf("tenant B findings %d -> %d", len(bBefore), len(bAfter))
			}
			for bid, r := range bBefore {
				if bAfter[bid] != r {
					t.Fatalf("tenant B finding %s changed: %+v -> %+v", bid, r, bAfter[bid])
				}
				if bid == id {
					t.Fatal("tenant B holds tenant A's finding")
				}
			}
		})
	}
}

func execOK(t *testing.T, g *goldenRig, q string, args ...any) {
	t.Helper()
	if _, err := g.r.db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatal(err)
	}
}
