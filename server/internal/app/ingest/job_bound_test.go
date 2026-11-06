package ingest

import (
	"context"
	"fmt"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/branch"
	"github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func jobCmd(tool string, ct command.CommandType, targets ...string) Binding {
	id := shared.NewID()
	return Binding{Kind: BindingCommand, CommandID: &id, CommandType: ct, Tool: tool, Targets: targets}
}

// runJobBound processes a report's assets for one tenant and returns the
// names stored for it and the output.
func runJobBound(t *testing.T, repo *memAssetRepo, tenant shared.ID, b Binding, report *ctis.Report) (map[string]bool, *Output) {
	t.Helper()
	p, _ := newDiscoveryProcessor(repo)
	out := &Output{}
	// Service.Ingest strips the producer's properties and derives the stored
	// keys from typed members before the processors read the report.
	adoptCTIS2Members(report, false)
	if _, err := p.processBatch(context.Background(), tenant, report, out, nil, false, newAlterScope(b)); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for name := range repo.rows[tenant] {
		got[name] = true
	}
	return got, out
}

func wantKept(t *testing.T, got map[string]bool, names ...string) {
	t.Helper()
	for _, n := range names {
		if !got[n] {
			t.Errorf("%s was dropped; it is inside the job's targets (stored: %v)", n, got)
		}
	}
}

// wantOutside checks that each name lies outside the job's targets and was
// recorded anyway (research 436), and that its report ref is marked.
func wantOutside(t *testing.T, got map[string]bool, out *Output, refs []string, names ...string) {
	t.Helper()
	for _, n := range names {
		if !got[n] {
			t.Errorf("%s lies outside the job's targets and was dropped; it must be recorded (stored: %v)", n, got)
		}
	}
	for _, r := range refs {
		if !out.OutsideJobAssetRefs[r] {
			t.Errorf("ref %s is not marked outside the targets (%v)", r, out.OutsideJobAssetRefs)
		}
	}
}

// Subdomain discovery under the target root is inside the job; a name
// outside it is recorded and marked outside the targets.
func TestJobBound_SubdomainDiscoveryStaysUnderTheRoot(t *testing.T) {
	report := &ctis.Report{
		Tool: &ctis.Tool{Name: "subfinder"},
		Assets: []ctis.Asset{
			{ID: "root", Type: ctis.AssetTypeDomainName, Value: "example.com"},
			{ID: "sub", Type: ctis.AssetTypeDomainName, Value: "api.example.com"},
			{ID: "deep", Type: ctis.AssetTypeDomainName, Value: "a.b.example.com"},
			{ID: "evil", Type: ctis.AssetTypeDomainName, Value: "evil-example.net"},
			{ID: "suffix", Type: ctis.AssetTypeDomainName, Value: "notexample.com"},
		},
	}
	got, out := runJobBound(t, newMemAssetRepo(), shared.NewID(), jobCmd("subfinder", command.CommandTypeScan, "example.com"), report)
	wantKept(t, got, "example.com", "api.example.com", "a.b.example.com")
	wantOutside(t, got, out, []string{"evil", "suffix"}, "evil-example.net", "notexample.com")
	if out.AssetsOutsideJob != 2 || out.OutsideJobAssetRefs["sub"] || out.AssetsOverCap != 0 {
		t.Fatalf("outside job = %d, over cap %d, refs %v", out.AssetsOutsideJob, out.AssetsOverCap, out.OutsideJobAssetRefs)
	}
}

// A port scan of a target name keeps the address the name resolves to and
// the services on it inside the job; an address no in-bound asset vouches
// for, its port, and a host name outside the targets are recorded outside.
func TestJobBound_PortScanKeepsServicesOnTargetHosts(t *testing.T) {
	report := &ctis.Report{
		Tool: &ctis.Tool{Name: "naabu"},
		Assets: []ctis.Asset{
			{ID: "ip", Type: ctis.AssetTypeIPAddress, Value: "198.51.100.10", Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{
				Hostname: "app.example.com",
			}}},
			{ID: "svc", Type: ctis.AssetTypeService, Value: "198.51.100.10:443/tcp"},
			{ID: "host", Type: ctis.AssetTypeHost, Value: "app.example.com"},
			{ID: "stray", Type: ctis.AssetTypeIPAddress, Value: "203.0.113.77"},
			{ID: "straysvc", Type: ctis.AssetTypeService, Value: "203.0.113.77:22/tcp"},
			{ID: "other", Type: ctis.AssetTypeHost, Value: "victim.example.org"},
		},
		Relationships: []ctis.Relationship{
			{Type: ctis.RelExposes, FromRef: "ip", ToRef: "svc"},
			{Type: ctis.RelExposes, FromRef: "stray", ToRef: "straysvc"},
		},
	}
	got, out := runJobBound(t, newMemAssetRepo(), shared.NewID(), jobCmd("naabu", command.CommandTypeScan, "app.example.com"), report)
	wantKept(t, got, "198.51.100.10", "app.example.com")
	wantOutside(t, got, out, []string{"stray", "straysvc", "other"}, "203.0.113.77", "victim.example.org")
	for _, ref := range []string{"ip", "svc", "host"} {
		if out.OutsideJobAssetRefs[ref] {
			t.Errorf("%s is inside the job and was marked outside", ref)
		}
	}
}

// DNS resolution vouches only for the addresses a target name states; an
// address the report lists on its own, and a name outside the targets that
// claims a vouched address, are recorded outside the targets.
func TestJobBound_ResolutionVouchesOnlyStatedAddresses(t *testing.T) {
	report := &ctis.Report{
		Tool: &ctis.Tool{Name: "dnsx"},
		Assets: []ctis.Asset{
			{ID: "name", Type: ctis.AssetTypeDomainName, Value: "www.example.com", Technical: &ctis.AssetTechnical{Domain: &ctis.DomainTechnical{
				DNSRecords: []ctis.DNSRecord{{Type: "A", Name: "www.example.com", Value: "192.0.2.10"}},
			}}},
			{ID: "a", Type: ctis.AssetTypeIPAddress, Value: "192.0.2.10", Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Hostname: "attacker.example.net"}}},
			{ID: "b", Type: ctis.AssetTypeIPAddress, Value: "192.0.2.99"},
			{ID: "chain", Type: ctis.AssetTypeDomainName, Value: "attacker.example.net", Technical: &ctis.AssetTechnical{Domain: &ctis.DomainTechnical{
				DNSRecords: []ctis.DNSRecord{{Type: "A", Name: "attacker.example.net", Value: "192.0.2.10"}},
			}}},
			// Properties carry no meaning: a planted address list vouches for nothing.
			{ID: "planted", Type: ctis.AssetTypeDomainName, Value: "www.example.com", Properties: ctis.Properties{"ip_addresses": []any{"192.0.2.99"}}},
		},
	}
	got, out := runJobBound(t, newMemAssetRepo(), shared.NewID(), jobCmd("dnsx", command.CommandTypeScan, "www.example.com"), report)
	wantKept(t, got, "www.example.com", "192.0.2.10")
	wantOutside(t, got, out, []string{"b", "chain"}, "192.0.2.99", "attacker.example.net")
	if out.OutsideJobAssetRefs["a"] || out.OutsideJobAssetRefs["name"] {
		t.Fatalf("a vouched asset was marked outside: %v", out.OutsideJobAssetRefs)
	}
}

// An HTTP probe keeps services on the target and assets that name no host
// (a certificate) inside the job; a service on another host is recorded
// outside the targets.
func TestJobBound_ProbeKeepsOnlyTargetServices(t *testing.T) {
	report := &ctis.Report{
		Tool: &ctis.Tool{Name: "httpx"},
		Assets: []ctis.Asset{
			{ID: "svc", Type: ctis.AssetTypeWebOrigin, Name: "app.example.com", Value: "https://app.example.com"},
			{ID: "evil", Type: ctis.AssetTypeWebOrigin, Name: "evil.example.net", Value: "https://evil.example.net"},
			{ID: "cert", Type: ctis.AssetTypeCertificate, Value: "sha256:0123456789abcdef"},
		},
	}
	got, out := runJobBound(t, newMemAssetRepo(), shared.NewID(), jobCmd("httpx", command.CommandTypeScan, "https://app.example.com"), report)
	wantOutside(t, got, out, []string{"evil"}, "https://evil.example.net")
	if out.AssetsOutsideJob != 1 || out.OutsideJobAssetRefs["cert"] || out.OutsideJobAssetRefs["svc"] {
		t.Fatalf("outside job = %d, refs %v", out.AssetsOutsideJob, out.OutsideJobAssetRefs)
	}
}

// Retests are bound too; address chunks keep their own rule; trusted,
// unsolicited and CI-run reports are not job-bound.
func TestJobBound_WhichBindingsAreBound(t *testing.T) {
	report := func() *ctis.Report {
		return &ctis.Report{Assets: []ctis.Asset{{ID: "x", Type: ctis.AssetTypeDomainName, Value: "elsewhere.example.org"}}}
	}
	_, out := runJobBound(t, newMemAssetRepo(), shared.NewID(), jobCmd("nuclei", command.CommandTypeRetest, "app.example.com"), report())
	if out.AssetsOutsideJob != 1 {
		t.Errorf("retest outside job = %d, want 1", out.AssetsOutsideJob)
	}
	for name, b := range map[string]Binding{
		"trusted":      TrustedBinding(),
		"unsolicited":  {},
		"address only": jobCmd("naabu", command.CommandTypeScan, "198.51.100.0/24"),
		"collect":      jobCmd("x", command.CommandTypeCollect, "app.example.com"),
	} {
		got, out := runJobBound(t, newMemAssetRepo(), shared.NewID(), b, report())
		if out.AssetsOutsideJob != 0 || !got["elsewhere.example.org"] {
			t.Errorf("%s: outside job = %d, stored %v", name, out.AssetsOutsideJob, got)
		}
	}
}

// Tenant isolation: a report bound to tenant A's job records the
// out-of-bounds name in A only; tenant B's asset of the same name is never
// read, merged or changed.
func TestJobBound_CrossTenant(t *testing.T) {
	repo := newMemAssetRepo()
	tenantA, tenantB := shared.NewID(), shared.NewID()
	if got, _ := runJobBound(t, repo, tenantB, TrustedBinding(), &ctis.Report{Assets: []ctis.Asset{
		{ID: "b", Type: ctis.AssetTypeDomainName, Value: "victim.example.org"},
	}}); !got["victim.example.org"] {
		t.Fatal("seed asset of tenant B missing")
	}
	seed := repo.rows[tenantB]["victim.example.org"]
	before := seed.LastSeen()
	_, out := runJobBound(t, repo, tenantA, jobCmd("subfinder", command.CommandTypeScan, "example.com"), &ctis.Report{Assets: []ctis.Asset{
		{ID: "v", Type: ctis.AssetTypeDomainName, Value: "victim.example.org"},
	}})
	mine := repo.rows[tenantA]["victim.example.org"]
	if mine == nil || out.AssetsOutsideJob != 1 {
		t.Fatalf("tenant A: recorded %v, outside job %d", mine, out.AssetsOutsideJob)
	}
	if mine.ID() == seed.ID() || !mine.TenantID().Equals(tenantA) {
		t.Fatal("tenant A's report resolved to tenant B's asset")
	}
	if len(repo.rows[tenantB]) != 1 || !repo.rows[tenantB]["victim.example.org"].LastSeen().Equal(before) {
		t.Fatal("tenant B's asset was changed by tenant A's report")
	}
}

// A report records at most maxOutsideTargetAssets assets outside its
// targets; the rest are refused, counted and marked, and the assets inside
// the targets are unaffected.
func TestJobBound_OutsideTargetsCap(t *testing.T) {
	report := &ctis.Report{Tool: &ctis.Tool{Name: "subfinder"}, Assets: []ctis.Asset{
		{ID: "in", Type: ctis.AssetTypeDomainName, Value: "api.example.com"},
	}}
	extra := 5
	for i := 0; i < maxOutsideTargetAssets+extra; i++ {
		report.Assets = append(report.Assets, ctis.Asset{ID: fmt.Sprintf("o%d", i), Type: ctis.AssetTypeDomainName,
			Value: fmt.Sprintf("h%d.example.net", i)})
	}
	got, out := runJobBound(t, newMemAssetRepo(), shared.NewID(), jobCmd("subfinder", command.CommandTypeScan, "example.com"), report)
	if out.AssetsOutsideJob != maxOutsideTargetAssets || out.AssetsOverCap != extra || len(out.OverCapAssetRefs) != extra {
		t.Fatalf("recorded %d, refused %d (%d refs)", out.AssetsOutsideJob, out.AssetsOverCap, len(out.OverCapAssetRefs))
	}
	if !got["api.example.com"] || len(got) != maxOutsideTargetAssets+1 {
		t.Fatalf("stored %d names, want %d", len(got), maxOutsideTargetAssets+1)
	}
	last := fmt.Sprintf("o%d", maxOutsideTargetAssets+extra-1)
	if !out.OverCapAssetRefs[last] || out.OutsideJobAssetRefs[last] || got[fmt.Sprintf("h%d.example.net", maxOutsideTargetAssets+extra-1)] {
		t.Fatal("an asset over the cap was recorded")
	}
}

// Findings on an asset recorded outside the targets are kept and counted;
// findings on an asset refused over the cap are refused with a receipt item
// that names the binding and the cap.
func TestJobBound_FindingsOutsideTargets(t *testing.T) {
	tenantID := shared.NewID()
	repo := &interopRepo{}
	p := NewFindingProcessor(repo, nil, nil, logger.NewNop())
	outside, kept := shared.NewID(), shared.NewID()
	out := &Output{OutsideJobAssetRefs: map[string]bool{"redirect": true}, AssetsOutsideJob: 1,
		OverCapAssetRefs: map[string]bool{"flood": true}, AssetsOverCap: 1}
	report := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "nuclei"}, Findings: []ctis.Finding{
		{Type: ctis.FindingTypeVulnerability, Title: "seen after a redirect", Severity: ctis.SeverityHigh, AssetRef: "redirect", RuleID: "r1"},
		{Type: ctis.FindingTypeVulnerability, Title: "flood", Severity: ctis.SeverityHigh, AssetRef: "flood", RuleID: "r2"},
		{Type: ctis.FindingTypeVulnerability, Title: "on target", Severity: ctis.SeverityHigh, AssetRef: "kept", RuleID: "r3"},
	}}
	scope := newAlterScope(jobCmd("nuclei", command.CommandTypeScan, "app.example.com"))
	err := p.processBatch(context.Background(), newTestSensor(t, tenantID), tenantID, report,
		map[string]shared.ID{"kept": kept, "redirect": outside}, branch.BranchTypeRules{}, out, map[string]shared.ID{}, false, scope)
	if err != nil {
		t.Fatal(err)
	}
	if out.FindingsOutsideJob != 1 || out.FindingsOverCap != 1 || out.FindingsSkipped != 1 || out.FindingsCreated != 2 {
		t.Fatalf("outside %d, over cap %d, skipped %d, created %d", out.FindingsOutsideJob, out.FindingsOverCap, out.FindingsSkipped, out.FindingsCreated)
	}
	if !out.OutsideTargetAssetIDs[outside] || out.OutsideTargetAssetIDs[kept] {
		t.Fatalf("outside asset ids %v", out.OutsideTargetAssetIDs)
	}
	found := false
	for _, it := range out.Items {
		if it.ReasonCode == ingestreceipt.ReasonOverCap && it.Policy == ingestreceipt.PolicyBinding &&
			it.Disposition == ingestreceipt.DispositionRejected {
			found = true
		}
		if it.ReasonCode == ingestreceipt.ReasonOutsideJob {
			t.Fatal("a recorded finding has a refusal item")
		}
	}
	if !found {
		t.Fatal("no receipt item names the cap")
	}
}

// New findings on assets recorded outside the targets run no automations.
func TestWithoutOutsideTargets(t *testing.T) {
	tenantID := shared.NewID()
	outside, kept := shared.NewID(), shared.NewID()
	mk := func(assetID shared.ID) *vulnerability.Finding {
		f, err := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceDAST, "nuclei", vulnerability.SeverityHigh, "t")
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	all := []*vulnerability.Finding{mk(outside), mk(kept)}
	got := withoutOutsideTargets(all, &Output{OutsideTargetAssetIDs: map[shared.ID]bool{outside: true}})
	if len(got) != 1 || got[0].AssetID() != kept {
		t.Fatalf("kept %d findings", len(got))
	}
	if len(withoutOutsideTargets(all, &Output{})) != 2 {
		t.Fatal("nothing outside: every finding runs its automations")
	}
}

// The channel of a sensor's findings is the platform's: whatever the
// report's metadata.source_type says.
func TestPrincipalSourceType(t *testing.T) {
	tenant := shared.NewID()
	worker, err := sensor.NewSensor(tenant, "w", sensor.SensorTypeWorker, "", nil, sensor.ExecutionModeDaemon)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := sensor.NewSensor(tenant, "c", sensor.SensorTypeCollector, "", nil, sensor.ExecutionModeDaemon)
	if err != nil {
		t.Fatal(err)
	}
	scanner, coll := string(vulnerability.IngestChannelScanner), string(vulnerability.IngestChannelCollector)
	cmd := jobCmd("nuclei", command.CommandTypeScan, "app.example.com")
	for _, c := range []struct {
		name    string
		agt     *sensor.Sensor
		b       Binding
		claimed string
		want    string
	}{
		{"sensor claims manual", worker, cmd, "manual", scanner},
		{"sensor claims integration", worker, cmd, "integration", scanner},
		{"sensor claims collector", worker, Binding{}, "collector", scanner},
		{"sensor claims an unknown value", worker, cmd, "Manual\r\n", scanner},
		{"collector claims manual", collector, Binding{}, "manual", coll},
		{"accepted quarantine keeps the sensor's channel", worker, TrustedBinding(), "manual", scanner},
		{"server-side import", &sensor.Sensor{TenantID: &tenant}, TrustedBinding(), "integration", "integration"},
		{"no sensor", nil, TrustedBinding(), "manual", "manual"},
		{"CI run", &sensor.Sensor{TenantID: &tenant}, CIRunBinding(shared.NewID(), "github.com/acme/app"), "scanner", "scanner"},
	} {
		if got := principalSourceType(c.agt, c.b, c.claimed); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
