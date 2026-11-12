package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A scan command given only addresses and ranges reports on them; a report
// asset naming only other addresses is recorded as a discovery outside the
// chunk (research 436), never dropped, and its ref is marked so its findings
// run no automations. It is never reported as outside the uploader's scope.
func TestIngest_RecordsAddressesOutsideTheChunk(t *testing.T) {
	report := func() *ctis.Report {
		return &ctis.Report{
			Assets: []ctis.Asset{
				{ID: "in", Type: ctis.AssetTypeIPAddress, Value: "198.51.100.7"},
				{ID: "edge", Type: ctis.AssetTypeIPAddress, Value: "198.51.100.200"},
				{ID: "out", Type: ctis.AssetTypeIPAddress, Value: "203.0.113.9"},
				{ID: "svc", Type: ctis.AssetTypeHost, Value: "203.0.113.10", Properties: ctis.Properties{"ip_addresses": []any{"203.0.113.10"}}},
				{ID: "name", Type: ctis.AssetTypeDomainName, Value: "www.example.com"},
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
	for _, outside := range []string{"203.0.113.9", "203.0.113.10"} {
		if !got[outside] {
			t.Errorf("%s is outside the chunk and was dropped; it must be recorded", outside)
		}
	}
	if out.AssetsOutsideChunk != 2 || !out.OutsideJobAssetRefs["out"] || !out.OutsideJobAssetRefs["svc"] ||
		out.OutOfScopeAssetRefs["out"] || out.OutsideJobAssetRefs["in"] {
		t.Errorf("outside chunk = %d, outside refs %v, out of scope %v", out.AssetsOutsideChunk, out.OutsideJobAssetRefs, out.OutOfScopeAssetRefs)
	}

	// A command that names a host name is not an address chunk. The
	// job-target rule (job_bound.go) records an address no in-bound asset
	// vouches for as outside the targets.
	got, out = run(scanCmd("198.51.100.0/25", "app.example.com"))
	if out.AssetsOutsideChunk != 0 {
		t.Errorf("a chunk with a name counted %d assets as outside the chunk", out.AssetsOutsideChunk)
	}
	if !got["198.51.100.7"] || !got["203.0.113.9"] || !out.OutsideJobAssetRefs["out"] || out.OutsideJobAssetRefs["in"] {
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
