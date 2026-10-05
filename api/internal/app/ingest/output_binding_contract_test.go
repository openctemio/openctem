package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// manifestKey scopes a stored manifest the way the repository does: by the
// sensor's tenant (nil for a platform sensor) and the sensor.
type manifestKey struct {
	tenant string
	sensor shared.ID
}

// fakeContracts is a tenant-scoped manifest store.
type fakeContracts struct {
	byKey map[manifestKey]sensor.Manifest
	err   error
	calls int
}

func tenantKey(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func (f *fakeContracts) CurrentManifest(_ context.Context, tenantID *shared.ID, sensorID shared.ID) (*sensor.ManifestVersion, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	m, ok := f.byKey[manifestKey{tenantKey(tenantID), sensorID}]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return &sensor.ManifestVersion{SensorID: sensorID, TenantID: tenantID, Manifest: m}, nil
}

func contractManifest(tool string, produces ...string) sensor.Manifest {
	return sensor.Manifest{Schema: 1, Tools: []sensor.ManifestTool{{Name: tool, Installed: true,
		Contract: &sensor.ToolContract{APIVersion: sensor.ToolContractAPIVersion, Digest: "sha256:" + string(make64('a')),
			Version: "1.0.0", Class: "target-scan", Tier: "T1", Network: "targets", Produces: produces}}}}
}

func make64(c byte) []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return b
}

func probeReport(tool string) *ctis.Report {
	return &ctis.Report{
		Metadata: ctis.ReportMetadata{ID: "r-probe"},
		Tool:     &ctis.Tool{Name: tool},
		Assets: []ctis.Asset{
			{ID: "a1", Type: ctis.AssetTypeDomain, Value: "acme.test"},
			{ID: "a2", Type: ctis.AssetTypeRepository, Value: "github.com/evil/planted"},
		},
		Findings: []ctis.Finding{
			{Type: ctis.FindingTypeMisconfiguration, Title: "on the domain", AssetRef: "a1"},
			{Type: ctis.FindingTypeSecret, Title: "a secret it never declared", AssetRef: "a1"},
		},
		Dependencies: []ctis.Dependency{{Name: "left-pad", Version: "1.0.0"}},
	}
}

func tenantSensor() *sensor.Sensor {
	tid := shared.NewID()
	return &sensor.Sensor{ID: shared.NewID(), TenantID: &tid}
}

// A tool the catalog does not know, with a declared contract: the declared
// produces decide. Undeclared assets (and their findings), undeclared finding
// types and undeclared dependencies are held; without the contract the whole
// report would be applied (TestBindOutputTypes_NoContract).
func TestBindOutputTypes_DeclaredProducesQuarantine(t *testing.T) {
	agt := tenantSensor()
	src := &fakeContracts{byKey: map[manifestKey]sensor.Manifest{
		{tenantKey(agt.TenantID), agt.ID}: contractManifest("acme-probe", "asset:domain", "finding:misconfiguration"),
	}}
	res := &policyResults{mode: sensorresult.ModeQuarantine}
	s := &Service{logger: logger.NewNop(), results: res}
	s.SetToolContractSource(src)

	got := s.bindOutputTypes(context.Background(), agt, *agt.TenantID, boundCommand("acme-probe"), probeReport("acme-probe"), Options{Route: "ctis"})
	if len(got.Assets) != 1 || got.Assets[0].ID != "a1" || len(got.Findings) != 1 ||
		got.Findings[0].Type != ctis.FindingTypeMisconfiguration || len(got.Dependencies) != 0 {
		t.Fatalf("applied %+v / %+v / %+v", got.Assets, got.Findings, got.Dependencies)
	}
	if len(res.items) != 1 {
		t.Fatalf("quarantined %d items", len(res.items))
	}
	it := res.items[0]
	if it.Reason != sensorresult.ReasonOutOfContract || it.AssetsCount != 1 || it.FindingsCount != 1 || it.ToolName != "acme-probe" {
		t.Fatalf("item = %+v", it)
	}
	var held ctis.Report
	if err := json.Unmarshal(it.Payload, &held); err != nil || len(held.Assets) != 1 || held.Assets[0].ID != "a2" ||
		len(held.Findings) != 1 || held.Findings[0].Type != ctis.FindingTypeSecret || len(held.Dependencies) != 1 {
		t.Fatalf("held = %+v (%v)", held, err)
	}

	// Without a contract source the same report is applied whole: the
	// declaration is what holds it.
	plain := &Service{logger: logger.NewNop(), results: &policyResults{mode: sensorresult.ModeQuarantine}}
	if all := plain.bindOutputTypes(context.Background(), agt, *agt.TenantID, boundCommand("acme-probe"), probeReport("acme-probe"), Options{}); len(all.Assets) != 2 || len(all.Findings) != 2 {
		t.Fatalf("no contract: applied %d assets / %d findings", len(all.Assets), len(all.Findings))
	}
}

// A declaration only narrows: a dnsx contract that claims repositories does
// not let a repository through the catalog contract.
func TestBindOutputTypes_DeclarationNeverWidens(t *testing.T) {
	agt := tenantSensor()
	src := &fakeContracts{byKey: map[manifestKey]sensor.Manifest{
		{tenantKey(agt.TenantID), agt.ID}: contractManifest("dnsx", "asset:domain", "asset:ip_address", "asset:repository"),
	}}
	res := &policyResults{mode: sensorresult.ModeQuarantine}
	s := &Service{logger: logger.NewNop(), results: res, contracts: src}
	got := s.bindOutputTypes(context.Background(), agt, *agt.TenantID, boundCommand("dnsx"), dnsxReport(), Options{})
	for _, a := range got.Assets {
		if a.Type == ctis.AssetTypeRepository {
			t.Fatal("a declaration widened the catalog contract")
		}
	}
	if len(res.items) != 1 || res.items[0].AssetsCount != 1 {
		t.Fatalf("quarantined = %+v", res.items)
	}
}

// The declaration comes only from the submitting sensor's own manifest, read
// under that sensor's tenant. A contract another tenant's sensor (with the
// same tool and even a known sensor id) declared is never used.
func TestBindOutputTypes_DeclarationIsTenantScoped(t *testing.T) {
	victim := tenantSensor()
	other := tenantSensor()
	// Tenant B's sensor declares a wide contract; tenant A's declares none.
	src := &fakeContracts{byKey: map[manifestKey]sensor.Manifest{
		{tenantKey(other.TenantID), other.ID}:   contractManifest("acme-probe", "asset:domain", "asset:repository", "finding:secret", "finding:misconfiguration", "dependency"),
		{tenantKey(other.TenantID), victim.ID}:  contractManifest("acme-probe", "asset:repository"),
		{tenantKey(victim.TenantID), victim.ID}: contractManifest("acme-probe", "asset:domain"),
	}}
	res := &policyResults{mode: sensorresult.ModeQuarantine}
	s := &Service{logger: logger.NewNop(), results: res, contracts: src}
	got := s.bindOutputTypes(context.Background(), victim, *victim.TenantID, boundCommand("acme-probe"), probeReport("acme-probe"), Options{})
	if len(got.Assets) != 1 || got.Assets[0].Type != ctis.AssetTypeDomain || len(got.Findings) != 0 {
		t.Fatalf("tenant A applied %+v / %+v: another tenant's contract was used", got.Assets, got.Findings)
	}
}

// Old sensors: no manifest, a manifest without contracts, or a store error
// leave the catalog contract as the only rule (behavior before contracts).
func TestBindOutputTypes_NoDeclarationUnchanged(t *testing.T) {
	agt := tenantSensor()
	for name, src := range map[string]*fakeContracts{
		"no manifest":     {byKey: map[manifestKey]sensor.Manifest{}},
		"no contract":     {byKey: map[manifestKey]sensor.Manifest{{tenantKey(agt.TenantID), agt.ID}: {Schema: 1, Tools: []sensor.ManifestTool{{Name: "dnsx"}}}}},
		"store error":     {err: errors.New("db down")},
		"other tool only": {byKey: map[manifestKey]sensor.Manifest{{tenantKey(agt.TenantID), agt.ID}: contractManifest("httpx", "asset:http_service")}},
	} {
		res := &policyResults{mode: sensorresult.ModeQuarantine}
		s := &Service{logger: logger.NewNop(), results: res, contracts: src}
		got := s.bindOutputTypes(context.Background(), agt, *agt.TenantID, boundCommand("dnsx"), dnsxReport(), Options{})
		// The catalog alone: domain and IP kept, the repository and its finding held.
		if len(got.Assets) != 2 || len(got.Findings) != 1 || len(res.items) != 1 {
			t.Errorf("%s: applied %d assets / %d findings, %d quarantined", name, len(got.Assets), len(got.Findings), len(res.items))
		}
	}
	// A server-side (synthetic) sensor never reads a manifest.
	src := &fakeContracts{}
	s := &Service{logger: logger.NewNop(), contracts: src}
	_ = s.bindOutputTypes(context.Background(), &sensor.Sensor{}, shared.NewID(), boundCommand("acme-probe"), probeReport("acme-probe"), Options{})
	if src.calls != 0 {
		t.Fatal("a synthetic sensor read a manifest")
	}
}

// A findings-only report is checked too (the asset-only early return is
// gone for declared contracts), and warn mode applies the report whole.
func TestBindOutputTypes_FindingsOnlyAndWarn(t *testing.T) {
	agt := tenantSensor()
	src := &fakeContracts{byKey: map[manifestKey]sensor.Manifest{
		{tenantKey(agt.TenantID), agt.ID}: contractManifest("acme-sast", "finding:vulnerability"),
	}}
	rep := func() *ctis.Report {
		return &ctis.Report{Tool: &ctis.Tool{Name: "acme-sast"}, Findings: []ctis.Finding{
			{Type: ctis.FindingTypeVulnerability, Title: "ok"}, {Type: ctis.FindingTypeSecret, Title: "undeclared"}, {Title: "no type"},
		}}
	}
	res := &policyResults{mode: sensorresult.ModeQuarantine}
	s := &Service{logger: logger.NewNop(), results: res, contracts: src}
	got := s.bindOutputTypes(context.Background(), agt, *agt.TenantID, boundCommand("acme-sast"), rep(), Options{})
	if len(got.Findings) != 1 || got.Findings[0].Title != "ok" || len(res.items) != 1 || res.items[0].FindingsCount != 2 {
		t.Fatalf("applied %+v, quarantined %+v", got.Findings, res.items)
	}
	warn := &Service{logger: logger.NewNop(), results: &policyResults{mode: sensorresult.ModeWarn}, contracts: src}
	if all := warn.bindOutputTypes(context.Background(), agt, *agt.TenantID, boundCommand("acme-sast"), rep(), Options{}); len(all.Findings) != 3 {
		t.Fatalf("warn mode applied %d findings", len(all.Findings))
	}
}

func TestSanitizeContractLabel(t *testing.T) {
	if got := sanitizeContractLabel(" Repo\n\x1b[31m" + string(make64('x'))); len(got) > 64 || got[0] != 'r' {
		t.Fatalf("label = %q", got)
	}
	for _, c := range sanitizeContractLabel("a\nb\x7f") {
		if c < 0x20 || c == 0x7f {
			t.Fatal("control character in a label")
		}
	}
	if sanitizeContractLabel("  ") != "(none)" {
		t.Fatal("empty label")
	}
}
