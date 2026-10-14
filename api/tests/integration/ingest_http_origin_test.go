package integration

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// An HTTP probe report, exactly as the recon converter writes it, creates one
// http_service origin per URL. The converter names the origin by its bare
// host; without the fix that name equals the subdomain's (or the address's)
// and the origin was folded into that row: the inventory then had no web
// origins at all and every web capability had nothing to target.
func TestIngest_HTTPProbeCreatesOrigins(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	ctx := context.Background()

	ingestAs := func(tn v2Tenant, tool string, targets []string, rep *ctis.Report) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		rep.Tool = &ctis.Tool{Name: tool}
		bind := ingest.Binding{Kind: ingest.BindingCommand, Targets: targets}
		out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest %s: %v %v", tool, err, out.Errors)
		}
	}
	convert := func(in *ctis.ReconToCTISInput) *ctis.Report {
		t.Helper()
		rep, err := ctis.ConvertReconToCTIS(in, nil)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	typesByName := func(tn v2Tenant) map[string]string {
		t.Helper()
		rows, err := r.db.QueryContext(ctx, `SELECT name, asset_type || '/' || COALESCE(sub_type, '')
			FROM assets WHERE tenant_id = $1`, tn.tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var n, ty string
			if err := rows.Scan(&n, &ty); err != nil {
				t.Fatal(err)
			}
			out[n] = ty
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	now := time.Now().Unix()
	a := r.newTenant("subfinder", "httpx")
	// The name and the address are in the inventory first (discovery, DNS).
	ingestAs(a, "subfinder", []string{"example.com"}, convert(&ctis.ReconToCTISInput{
		ScannerName: "subfinder", Target: "example.com", StartedAt: now, FinishedAt: now,
		Subdomains: []ctis.SubdomainInput{{Host: "app.example.com", Domain: "example.com", IPs: []string{"203.0.113.7"}}},
	}))
	before := typesByName(a)
	if before["app.example.com"] != "subdomain/" {
		t.Fatalf("setup: inventory = %v", before)
	}

	probe := convert(&ctis.ReconToCTISInput{
		ScannerName: "httpx", Target: "app.example.com", StartedAt: now, FinishedAt: now,
		LiveHosts: []ctis.LiveHostInput{
			{URL: "https://app.example.com", Host: "app.example.com", IP: "203.0.113.7", Port: 443, Scheme: "https", StatusCode: 200, Title: "App", WebServer: "nginx"},
			{URL: "http://203.0.113.7:8080", Host: "203.0.113.7", IP: "203.0.113.7", Port: 8080, Scheme: "http", StatusCode: 401, Title: "Admin"},
		},
	})
	ingestAs(a, "httpx", []string{"app.example.com", "203.0.113.7:8080"}, probe)
	// A second identical probe is idempotent.
	ingestAs(a, "httpx", []string{"app.example.com", "203.0.113.7:8080"}, probe)

	got := typesByName(a)
	var origins []string
	for n, ty := range got {
		if ty == "service/http" {
			origins = append(origins, n)
		}
	}
	sort.Strings(origins)
	want := []string{"http://203.0.113.7:8080", "https://app.example.com"}
	if len(origins) != len(want) || origins[0] != want[0] || origins[1] != want[1] {
		t.Fatalf("http_service origins = %v, want %v (inventory %v)", origins, want, got)
	}
	if got["app.example.com"] != "subdomain/" {
		t.Errorf("the subdomain changed type: %q", got["app.example.com"])
	}
	var title *string
	if err := r.db.QueryRowContext(ctx, `SELECT properties->>'title' FROM assets WHERE tenant_id = $1 AND name = 'https://app.example.com'`,
		a.tenant.String()).Scan(&title); err != nil || title == nil || *title != "App" {
		t.Errorf("origin title = %v (%v)", title, err)
	}
	var folded *string
	if err := r.db.QueryRowContext(ctx, `SELECT properties->>'title' FROM assets WHERE tenant_id = $1 AND name = 'app.example.com'`,
		a.tenant.String()).Scan(&folded); err != nil || folded != nil {
		t.Errorf("probe output folded into the subdomain row: title = %v (%v)", folded, err)
	}

	// Tenant isolation: another tenant's probe of the same URL is its own
	// origin, and tenant A still has exactly its two.
	b := r.newTenant("httpx")
	ingestAs(b, "httpx", []string{"app.example.com"}, convert(&ctis.ReconToCTISInput{
		ScannerName: "httpx", Target: "app.example.com", StartedAt: now, FinishedAt: now,
		LiveHosts: []ctis.LiveHostInput{{URL: "https://app.example.com", Host: "app.example.com", Port: 443, Scheme: "https", StatusCode: 200}},
	}))
	if typesByName(b)["https://app.example.com"] != "service/http" {
		t.Errorf("tenant B origin missing: %v", typesByName(b))
	}
	n := 0
	for _, ty := range typesByName(a) {
		if ty == "service/http" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("tenant A origins after tenant B's probe = %d, want 2", n)
	}
}
