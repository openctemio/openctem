package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A scan command given only addresses and ranges can only observe them: a
// report asset naming only other addresses is dropped with its findings;
// in-chunk addresses and address-less names are kept.
func TestIngest_DropsAddressesOutsideTheChunk(t *testing.T) {
	report := func() *ctis.Report {
		return &ctis.Report{
			Assets: []ctis.Asset{
				{ID: "in", Type: ctis.AssetTypeIPAddress, Value: "198.51.100.7"},
				{ID: "edge", Type: ctis.AssetTypeIPAddress, Value: "198.51.100.200"},
				{ID: "out", Type: ctis.AssetTypeIPAddress, Value: "203.0.113.9"},
				{ID: "svc", Type: ctis.AssetTypeHost, Value: "203.0.113.10", Properties: ctis.Properties{"ip_addresses": []any{"203.0.113.10"}}},
				{ID: "name", Type: ctis.AssetTypeSubdomain, Value: "www.example.com"},
			},
			Findings: []ctis.Finding{{ID: "f1", AssetRef: "out", Title: "planted", Severity: ctis.SeverityHigh, Type: ctis.FindingTypeVulnerability}},
		}
	}
	run := func(b Binding) (map[string]bool, *Output) {
		repo := newMemAssetRepo()
		p, _ := newDiscoveryProcessor(repo)
		tenant := shared.NewID()
		out := &Output{}
		if _, err := p.processBatch(context.Background(), tenant, report(), out, nil, false, newAlterScope(b)); err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for name := range repo.rows[tenant] {
			got[name] = true
		}
		return got, out
	}

	scanCmd := func(targets ...string) Binding {
		id := shared.NewID()
		return Binding{Kind: BindingCommand, CommandID: &id, CommandType: command.CommandTypeScan, Targets: targets}
	}

	got, out := run(scanCmd("198.51.100.0/25", "198.51.100.200"))
	for _, want := range []string{"198.51.100.7", "198.51.100.200", "www.example.com"} {
		if !got[want] {
			t.Errorf("%s was dropped; it is inside the chunk or names no address", want)
		}
	}
	for _, bad := range []string{"203.0.113.9", "203.0.113.10"} {
		if got[bad] {
			t.Errorf("%s is outside the chunk and was created", bad)
		}
	}
	if out.AssetsOutsideChunk != 2 || !out.OutOfScopeAssetRefs["out"] {
		t.Errorf("outside chunk = %d, refs %v", out.AssetsOutsideChunk, out.OutOfScopeAssetRefs)
	}

	// A command that names a host name is not an address chunk: this rule
	// drops nothing. The job-target rule (job_bound.go) keeps the range's
	// addresses and drops an address no in-bound asset vouches for.
	got, out = run(scanCmd("198.51.100.0/25", "app.example.com"))
	if out.AssetsOutsideChunk != 0 {
		t.Errorf("a chunk with a name dropped %d assets as outside the chunk", out.AssetsOutsideChunk)
	}
	if !got["198.51.100.7"] || got["203.0.113.9"] || !out.OutsideJobAssetRefs["out"] {
		t.Errorf("job-target rule: stored %v, outside job %v", got, out.OutsideJobAssetRefs)
	}

	// Not a scan command (a retest names its own items): not this rule.
	b := scanCmd("198.51.100.0/25")
	b.CommandType = command.CommandTypeRetest
	if _, out = run(b); out.AssetsOutsideChunk != 0 {
		t.Errorf("a retest dropped %d assets", out.AssetsOutsideChunk)
	}
	// A trusted upload is never bound to a chunk.
	if got, out = func() (map[string]bool, *Output) { return run(TrustedBinding()) }(); !got["203.0.113.9"] || out.AssetsOutsideChunk != 0 {
		t.Errorf("a trusted upload dropped %d assets", out.AssetsOutsideChunk)
	}
}

func TestAddressChunk(t *testing.T) {
	for _, c := range []struct {
		targets []string
		want    bool
	}{
		{[]string{"198.51.100.0/24"}, true},
		{[]string{"198.51.100.7", "2001:db8::/120", "198.51.100.8:8443"}, true},
		{[]string{"198.51.100.7", "example.com"}, false},
		{[]string{"https://198.51.100.7/admin"}, false},
		{nil, false},
	} {
		if got := addressChunk(newCoverTargets(c.targets)); got != c.want {
			t.Errorf("addressChunk(%v) = %v, want %v", c.targets, got, c.want)
		}
	}
}
