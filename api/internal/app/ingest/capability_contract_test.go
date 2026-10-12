package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func implementsManifest(tool string, implements []string, produces ...string) sensor.Manifest {
	m := contractManifest(tool, produces...)
	m.Tools[0].Contract.Implements = implements
	return m
}

func openPortReport(tool, claimed string) *ctis.Report {
	return &ctis.Report{
		Metadata: ctis.ReportMetadata{ID: "r-ports", Capability: claimed},
		Tool:     &ctis.Tool{Name: tool},
		Assets: []ctis.Asset{{Type: ctis.AssetTypeIPAddress, Value: "192.0.2.10",
			Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Ports: []ctis.PortInfo{{Port: 443, Protocol: "tcp"}}}}}},
	}
}

// The capability of a command-bound report comes from the command's tool,
// never from the sensor alone.
func TestBoundCapability(t *testing.T) {
	agt := tenantSensor()
	src := &fakeContracts{byKey: map[manifestKey]sensor.Manifest{
		{tenantKey(agt.TenantID), agt.ID}: implementsManifest("acme-ports", []string{"scan.ports@1"}, "asset:ip_address", "asset:open_port"),
	}}
	s := &Service{logger: logger.NewNop(), results: &policyResults{mode: sensorresult.ModeWarn}, contracts: src}
	ctx := context.Background()

	cases := []struct {
		name, tool, claim, want string
	}{
		// A third-party tool: its declared implements decide.
		{"declared", "acme-ports", "", "scan.ports@1"},
		// SECURITY: a claim outside the tool's capabilities is replaced.
		{"claim outside", "acme-ports", "secrets.code@1", "scan.ports@1"},
		// A built-in: the catalog decides.
		{"catalog", "naabu", "", "scan.ports@1"},
		// trivy has several stages: only a matching claim picks one.
		{"several, no claim", "trivy", "", ""},
		{"several, matching claim", "trivy", "container.image@1", "container.image@1"},
		{"several, foreign claim", "trivy", "scan.ports@1", ""},
		// A tool nobody knows: no capability, whatever it claims.
		{"unknown tool", "mystery", "scan.ports@1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := openPortReport(tc.tool, tc.claim)
			got := s.bindOutputTypes(ctx, agt, *agt.TenantID, boundCommand(tc.tool), r, Options{})
			if got.Metadata.Capability != tc.want {
				t.Fatalf("capability %q, want %q", got.Metadata.Capability, tc.want)
			}
		})
	}
}

// Another tenant's manifest never names the capability of a report.
func TestBoundCapabilityIsTenantScoped(t *testing.T) {
	owner, other := tenantSensor(), tenantSensor()
	src := &fakeContracts{byKey: map[manifestKey]sensor.Manifest{
		{tenantKey(owner.TenantID), owner.ID}: implementsManifest("acme-ports", []string{"scan.ports@1"}, "asset:ip_address"),
	}}
	s := &Service{logger: logger.NewNop(), results: &policyResults{mode: sensorresult.ModeWarn}, contracts: src}
	other.ID = owner.ID // same sensor id, another tenant
	got := s.bindOutputTypes(context.Background(), other, *other.TenantID, boundCommand("acme-ports"), openPortReport("acme-ports", "scan.ports@1"), Options{})
	if got.Metadata.Capability != "" {
		t.Fatalf("a foreign tenant's declaration bound the capability: %q", got.Metadata.Capability)
	}
}

// Port closure is keyed by capability: a third-party port scanner bound to
// scan.ports gets it, without being in a name list.
func TestPortScanReportByCapability(t *testing.T) {
	r := openPortReport("acme-ports", "scan.ports@1")
	if !isPortScanReport(r) {
		t.Fatal("a scan.ports report is a port scan")
	}
	r.Metadata.Capability = "probe.http@1"
	if isPortScanReport(r) {
		t.Fatal("a probe.http report is not a port scan")
	}
	r.Metadata.Capability = ""
	r.Tool.Name = "naabu"
	if !isPortScanReport(r) {
		t.Fatal("an unbound report of a known port scanner keeps the name rule")
	}
	if isPortScanReport(nil) || isPortScanReport(&ctis.Report{}) {
		t.Fatal("nil or toolless")
	}
}

// A report that misses its capability's required output is applied (warn).
func TestCapabilityContractWarnsAndApplies(t *testing.T) {
	agt := tenantSensor()
	s := &Service{logger: logger.NewNop(), results: &policyResults{mode: sensorresult.ModeQuarantine}}
	r := &ctis.Report{Metadata: ctis.ReportMetadata{ID: "r1"}, Tool: &ctis.Tool{Name: "naabu"},
		Assets: []ctis.Asset{{Type: ctis.AssetTypeIPAddress, Value: "192.0.2.10"}}} // no ports
	got := s.bindOutputTypes(context.Background(), agt, *agt.TenantID, boundCommand("naabu"), r, Options{})
	if len(got.Assets) != 1 || got.Metadata.Capability != "scan.ports@1" {
		t.Fatalf("applied %+v capability %q", got.Assets, got.Metadata.Capability)
	}
}

func TestSanitizeToolContractImplements(t *testing.T) {
	base := func() *sensor.ToolContract {
		return &sensor.ToolContract{APIVersion: sensor.ToolContractAPIVersion, Digest: "sha256:" + string(make64('b')),
			Version: "2.0.0", Class: "target-scan", Tier: "T1", Produces: []string{"asset:open_port"}}
	}
	c := base()
	c.Implements = []string{"scan.ports@1", "scan.ports@1"}
	c.Origin, c.Batch = sensor.ToolOriginBuiltin, true
	got, why := sensor.SanitizeToolContract(c)
	if got == nil || len(got.Implements) != 1 || !got.ImplementsCapability("scan.ports@1") || got.Origin != "builtin" || !got.Batch {
		t.Fatalf("sanitized %+v (%s)", got, why)
	}
	for name, mut := range map[string]func(*sensor.ToolContract){
		"no major":   func(c *sensor.ToolContract) { c.Implements = []string{"scan.ports"} },
		"look-alike": func(c *sensor.ToolContract) { c.Implements = []string{"Scan.Ports@1"} },
		"unknown":    func(c *sensor.ToolContract) { c.Implements = []string{"scan.everything@1"} },
		"origin":     func(c *sensor.ToolContract) { c.Origin = "certified" },
		"too many": func(c *sensor.ToolContract) {
			for i := 0; i < 17; i++ {
				c.Implements = append(c.Implements, "scan.ports@1")
			}
		},
	} {
		c := base()
		mut(c)
		if got, _ := sensor.SanitizeToolContract(c); got != nil {
			t.Errorf("%s: accepted %+v", name, got)
		}
	}
	if (*sensor.ToolContract)(nil).ImplementsCapability("scan.ports@1") {
		t.Fatal("nil contract")
	}
}
