package integration

// The edge protection vendor of a pair's last outcome (RFC-093) on a migrated
// database: an edge answer settles the pair as failed with the sensor's
// vendor token, from per-target outcomes and from the coverage gaps of an
// older sensor's result; any later settlement clears it; and another
// organization never reads it.

import (
	"context"
	"testing"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
)

// finishWith finishes the capability's last run with the task's result set
// to raw (a JSON document).
func (g *cycleRig) finishWith(capability, raw string) {
	g.t.Helper()
	run := g.f.runs[capability].String()
	g.exec(`UPDATE commands SET status = 'completed', result = $2::jsonb WHERE payload->>'scan_run_id' = $1`, run, raw)
	g.exec(`UPDATE scan_runs SET status = 'completed' WHERE id = $1`, run)
}

func TestAssetCoverage_EdgeVendorSettledAndCleared(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	b := g.r.newTenant()
	g.scope(a)
	name := g.asset(a, "edge.tside.test", "subdomain", "", "")
	g.pass(a)

	cases := []struct {
		name, result, outcome, vendor string
	}{
		{"older sensor, blocked gap", `{"metadata": {"coverage_gaps": [{"host": "EDGE.tside.test", "reason": "blocked", "edge": "blocked", "vendor": "Datadome"}], "coverage_gaps_total": 1}}`, "edge_blocked", "datadome"},
		{"older sensor, challenged gap", `{"metadata": {"coverage_gaps": [{"host": "edge.tside.test", "reason": "blocked", "edge": "challenged", "vendor": "cloudflare"}], "coverage_gaps_total": 1}}`, "edge_challenged", "cloudflare"},
		{"outcome with a vendor", `{"target_outcomes": [{"target": "edge.tside.test", "state": "failed", "class": "edge_blocked", "vendor": "akamai"}]}`, "edge_blocked", "akamai"},
		{"done outcome, gap wins", `{"target_outcomes": [{"target": "edge.tside.test", "state": "done"}], "metadata": {"coverage_gaps": [{"host": "edge.tside.test", "reason": "blocked", "vendor": "imperva"}], "coverage_gaps_total": 1}}`, "edge_blocked", "imperva"},
		{"rate floor has no vendor", `{"metadata": {"coverage_gaps": [{"host": "edge.tside.test", "reason": "rate_floor", "vendor": "x"}], "coverage_gaps_total": 1}}`, "rate_limited", ""},
	}
	for _, c := range cases {
		g.dueIn(a, name, "resolve.dns", -1)
		g.pass(a)
		g.finishWith("resolve.dns", c.result)
		g.pass(a)
		r := g.row(a, name, "resolve.dns")
		if r.State != covdom.StateFailed || r.LastOutcome != c.outcome || r.LastEdgeVendor != c.vendor {
			t.Fatalf("%s: %s outcome %q vendor %q, want failed %q %q", c.name, r.State, r.LastOutcome, r.LastEdgeVendor, c.outcome, c.vendor)
		}
		if e := g.entry(a, name, "resolve.dns"); e.LastEdgeVendor != c.vendor {
			t.Fatalf("%s: entry vendor %q", c.name, e.LastEdgeVendor)
		}
	}

	// Another organization never reads the pair, with or without its vendor.
	rows, err := g.repo.ListForAsset(context.Background(), b.tenant, name)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("another tenant read %d coverage rows of the asset", len(rows))
	}

	// A later success clears the vendor.
	g.dueIn(a, name, "resolve.dns", -1)
	g.pass(a)
	g.finishWith("resolve.dns", `{"target_outcomes": [{"target": "edge.tside.test", "state": "failed", "class": "edge_blocked", "vendor": "akamai"}]}`)
	g.pass(a)
	if r := g.row(a, name, "resolve.dns"); r.LastEdgeVendor != "akamai" {
		t.Fatalf("vendor not set: %q", r.LastEdgeVendor)
	}
	g.dueIn(a, name, "resolve.dns", -1)
	g.pass(a)
	g.complete("resolve.dns")
	g.pass(a)
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StateCovered || r.LastEdgeVendor != "" {
		t.Fatalf("after a success = %s vendor %q", r.State, r.LastEdgeVendor)
	}
}
