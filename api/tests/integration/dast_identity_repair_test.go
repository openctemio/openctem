package integration

// One-time DAST repair: findings forked when a producer stopped sending the
// HTTP method, and a fixed-path template's two paths on one origin, become
// one finding each. The oldest keeps its triage; the others become audited
// tombstones; a second run changes nothing; another tenant is untouched.

import (
	"context"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestDASTRepair_FoldsForkedFindings(t *testing.T) {
	g := newGoldenRig(t)
	ctx := context.Background()
	file := goldenFile{Tool: "nuclei"}
	file.Asset.Type, file.Asset.Value = ctis.AssetTypeDomain, "shop.example.com"
	dast := func(rule, u, method string) ctis.Finding {
		f := ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: rule, Severity: "medium", RuleID: rule,
			Location: &ctis.FindingLocation{Path: u}}
		if method != "" {
			f.Properties = ctis.Properties{"method": method}
		}
		return f
	}
	seed := func(tn v2Tenant) {
		g.ingest(t, tn, file, "nuclei", dast("exposed-env", "https://shop.example.com/.env", "GET"))
		g.ingest(t, tn, file, "nuclei", dast("exposed-env", "https://shop.example.com/.env", "POST"))
		g.ingest(t, tn, file, "nuclei", dast("wp-user-enum", "https://shop.example.com/wp-json/wp/v2/users", ""))
		g.ingest(t, tn, file, "nuclei", dast("wp-user-enum", "https://shop.example.com/?rest_route=/wp/v2/users", ""))
		// Turn the POST row into what the newer sensor wrote: method "",
		// created later.
		var id string
		var raw []byte
		if err := g.r.db.QueryRowContext(ctx, `SELECT id, identity_key FROM findings WHERE tenant_id = $1 AND rule_id = 'exposed-env'
			AND identity_key::text LIKE '%POST%'`, tn.tenant.String()).Scan(&id, &raw); err != nil {
			t.Fatal(err)
		}
		k, err := vulnerability.ParseIdentityKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		for i := range k.Fields {
			if k.Fields[i].Name == "method" {
				k.Fields[i].Value = ""
			}
		}
		kraw, _ := vulnerability.MarshalIdentityKey(k)
		if _, err := g.r.db.ExecContext(ctx, `UPDATE findings SET identity_key = $1::jsonb, fingerprint = $2, created_at = NOW() + interval '1 hour'
			WHERE id = $3`, string(kraw), k.Fingerprint(), id); err != nil {
			t.Fatal(err)
		}
	}
	tn, other := g.r.newTenant(), g.r.newTenant()
	seed(tn)
	seed(other)
	// The oldest exposed-env finding was triaged.
	if _, err := g.r.db.ExecContext(ctx, `UPDATE findings SET status = 'false_positive' WHERE tenant_id = $1 AND rule_id = 'exposed-env'
		AND identity_key::text LIKE '%GET%'`, tn.tenant.String()); err != nil {
		t.Fatal(err)
	}

	repo := postgres.NewFindingRekeyRepository(&postgres.DB{DB: g.r.db})
	fold := vulnerability.ParseFoldRules("wp-user-enum")
	dry, err := repo.RepairDAST(ctx, tn.tenant, fold, false)
	if err != nil || len(dry.Merges) != 2 {
		t.Fatalf("dry run: %+v %v, want 2 merges", dry, err)
	}
	live := func(tenant string) int {
		var n int
		_ = g.r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND status <> 'duplicate'`, tenant).Scan(&n)
		return n
	}
	if live(tn.tenant.String()) != 4 {
		t.Fatal("a dry run changed findings")
	}
	rep, err := repo.RepairDAST(ctx, tn.tenant, fold, true)
	if err != nil || len(rep.Merges) != 2 {
		t.Fatalf("apply: %+v %v", rep, err)
	}
	if live(tn.tenant.String()) != 2 || live(other.tenant.String()) != 4 {
		t.Fatalf("live findings: tenant %d (want 2), other tenant %d (want 4, untouched)", live(tn.tenant.String()), live(other.tenant.String()))
	}
	var status string
	if err := g.r.db.QueryRowContext(ctx, `SELECT status FROM findings WHERE tenant_id = $1 AND rule_id = 'exposed-env' AND status <> 'duplicate'`,
		tn.tenant.String()).Scan(&status); err != nil || status != "false_positive" {
		t.Fatalf("survivor status %q %v, want the oldest finding's triage", status, err)
	}
	var tombs, audits int
	_ = g.r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND status = 'duplicate' AND duplicate_of IS NOT NULL`, tn.tenant.String()).Scan(&tombs)
	_ = g.r.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.duplicate_marked'
		AND metadata->>'reason' = 'dast_identity_repair'`, tn.tenant.String()).Scan(&audits)
	if tombs != 2 || audits != 2 {
		t.Fatalf("tombstones %d audits %d, want 2 and 2", tombs, audits)
	}
	again, err := repo.RepairDAST(ctx, tn.tenant, fold, true)
	if err != nil || len(again.Merges) != 0 || again.Rekeyed != 0 {
		t.Fatalf("second run: %+v %v, want nothing", again, err)
	}
	// The next sighting from the newer sensor (no method) lands on the
	// survivor.
	g.ingest(t, tn, file, "nuclei", dast("exposed-env", "https://shop.example.com/.env", ""))
	if live(tn.tenant.String()) != 2 {
		t.Fatal("a sighting without a method forked the finding again")
	}
}
