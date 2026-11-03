package ingest

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/branch"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
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

func wantDropped(t *testing.T, got map[string]bool, names ...string) {
	t.Helper()
	for _, n := range names {
		if got[n] {
			t.Errorf("%s lies outside the job's targets and was created", n)
		}
	}
}

// Subdomain discovery may add names under the target root, never a name
// outside it; a finding on a dropped asset goes with it.
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
	wantDropped(t, got, "evil-example.net", "notexample.com")
	if out.AssetsOutsideJob != 2 || !out.OutsideJobAssetRefs["evil"] || !out.OutsideJobAssetRefs["suffix"] {
		t.Fatalf("outside job = %d, refs %v", out.AssetsOutsideJob, out.OutsideJobAssetRefs)
	}
}

// A port scan of a target name keeps the address the name resolves to and
// the services on it; an address no in-bound asset vouches for, and a host
// name outside the targets, are dropped.
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
	wantDropped(t, got, "203.0.113.77", "victim.example.org")
	for name := range got {
		if strings.HasPrefix(name, "203.0.113.77:22") {
			t.Errorf("a port on an unvouched address was created: %s", name)
		}
	}
	if out.AssetsOutsideJob < 2 {
		t.Fatalf("outside job = %d, want at least 2", out.AssetsOutsideJob)
	}
}

// DNS resolution keeps the address a target name states in its records; an
// address the report lists on its own is dropped, and a vouched address
// cannot vouch for a name outside the targets.
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
	got, _ := runJobBound(t, newMemAssetRepo(), shared.NewID(), jobCmd("dnsx", command.CommandTypeScan, "www.example.com"), report)
	wantKept(t, got, "www.example.com", "192.0.2.10")
	wantDropped(t, got, "192.0.2.99", "attacker.example.net")
}

// An HTTP probe keeps services on the target and assets that name no host
// (a certificate); a service on another host is dropped.
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
	wantDropped(t, got, "https://evil.example.net")
	if out.AssetsOutsideJob != 1 || !out.OutsideJobAssetRefs["evil"] || out.OutsideJobAssetRefs["cert"] || out.OutsideJobAssetRefs["svc"] {
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

// Tenant isolation: a report bound to tenant A's job never touches tenant
// B's asset of the same out-of-bounds name, and creates nothing in A.
func TestJobBound_CrossTenant(t *testing.T) {
	repo := newMemAssetRepo()
	tenantA, tenantB := shared.NewID(), shared.NewID()
	if got, _ := runJobBound(t, repo, tenantB, TrustedBinding(), &ctis.Report{Assets: []ctis.Asset{
		{ID: "b", Type: ctis.AssetTypeDomainName, Value: "victim.example.org"},
	}}); !got["victim.example.org"] {
		t.Fatal("seed asset of tenant B missing")
	}
	before := repo.rows[tenantB]["victim.example.org"].LastSeen()
	got, out := runJobBound(t, repo, tenantA, jobCmd("subfinder", command.CommandTypeScan, "example.com"), &ctis.Report{Assets: []ctis.Asset{
		{ID: "v", Type: ctis.AssetTypeDomainName, Value: "victim.example.org"},
	}})
	if len(got) != 0 || out.AssetsOutsideJob != 1 {
		t.Fatalf("tenant A stored %v, outside job %d", got, out.AssetsOutsideJob)
	}
	if len(repo.rows[tenantB]) != 1 || !repo.rows[tenantB]["victim.example.org"].LastSeen().Equal(before) {
		t.Fatal("tenant B's asset was changed by tenant A's report")
	}
}

// Findings on a dropped asset are dropped with a receipt that names the
// binding, and nothing lands on the one asset that was kept.
func TestJobBound_FindingsOnDroppedAssetsAreSkipped(t *testing.T) {
	tenantID := shared.NewID()
	repo := &interopRepo{}
	p := NewFindingProcessor(repo, nil, nil, logger.NewNop())
	out := &Output{OutsideJobAssetRefs: map[string]bool{"evil": true}, AssetsOutsideJob: 1}
	report := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "nuclei"}, Findings: []ctis.Finding{
		{Type: ctis.FindingTypeVulnerability, Title: "planted", Severity: ctis.SeverityHigh, AssetRef: "evil", RuleID: "r1"},
		{Type: ctis.FindingTypeVulnerability, Title: "no ref", Severity: ctis.SeverityHigh, RuleID: "r2"},
	}}
	scope := newAlterScope(jobCmd("nuclei", command.CommandTypeScan, "app.example.com"))
	err := p.processBatch(context.Background(), newTestSensor(t, tenantID), tenantID, report,
		map[string]shared.ID{"kept": shared.NewID()}, branch.BranchTypeRules{}, out, map[string]shared.ID{}, false, scope)
	if err != nil {
		t.Fatal(err)
	}
	if out.FindingsOutsideJob != 1 || out.FindingsCreated != 0 || out.FindingsSkipped != 2 {
		t.Fatalf("outside job %d, created %d, skipped %d", out.FindingsOutsideJob, out.FindingsCreated, out.FindingsSkipped)
	}
	found := false
	for _, it := range out.Items {
		if it.ReasonCode == ingestreceipt.ReasonOutsideJob && it.Policy == ingestreceipt.PolicyBinding {
			found = true
		}
	}
	if !found {
		t.Fatal("no receipt item names the job binding")
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
