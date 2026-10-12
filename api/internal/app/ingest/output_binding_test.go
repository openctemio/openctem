package ingest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// policyResults is a result store with a fixed policy that records what is
// quarantined.
type policyResults struct {
	sensorresult.Repository
	mode  sensorresult.Mode
	items []*sensorresult.Item
}

func (p *policyResults) GetPolicy(_ context.Context, tenantID shared.ID) (sensorresult.Policy, error) {
	return sensorresult.Policy{TenantID: tenantID, Mode: p.mode}, nil
}

func (p *policyResults) Create(_ context.Context, item *sensorresult.Item, _ sensorresult.Limits) error {
	item.ID = shared.NewID()
	p.items = append(p.items, item)
	return nil
}

func dnsxReport() *ctis.Report {
	return &ctis.Report{
		Metadata: ctis.ReportMetadata{ID: "r1"},
		Tool:     &ctis.Tool{Name: "dnsx"},
		Assets: []ctis.Asset{
			{ID: "a1", Type: ctis.AssetTypeDomain, Value: "acme.test"},
			{ID: "a2", Type: ctis.AssetTypeIPAddress, Value: "203.0.113.4"},
			{ID: "a3", Type: ctis.AssetTypeRepository, Value: "github.com/evil/planted"},
		},
		Findings: []ctis.Finding{
			{Title: "on the domain", AssetRef: "a1"},
			{Title: "on the planted repo", AssetRef: "a3"},
		},
	}
}

func boundCommand(tool string) Binding {
	id := shared.NewID()
	return Binding{Kind: BindingCommand, CommandID: &id, Tool: tool}
}

// G12, quarantine mode: a dnsx report carrying a repository has that asset
// and its finding held for review, never applied; in-contract assets apply.
func TestBindOutputTypes_QuarantinesOutOfContract(t *testing.T) {
	res := &policyResults{mode: sensorresult.ModeQuarantine}
	s := &Service{logger: logger.NewNop(), results: res}
	agt := &sensor.Sensor{ID: shared.NewID()}
	in := dnsxReport()

	got := s.bindOutputTypes(context.Background(), agt, shared.NewID(), boundCommand("dnsx"), in, Options{Route: "ctis"})
	if len(got.Assets) != 2 || len(got.Findings) != 1 || got.Findings[0].AssetRef != "a1" {
		t.Fatalf("applied %d assets / %d findings", len(got.Assets), len(got.Findings))
	}
	for _, a := range got.Assets {
		if a.Type == ctis.AssetTypeRepository {
			t.Fatal("an out-of-contract asset is applied")
		}
	}
	if len(res.items) != 1 || res.items[0].Reason != sensorresult.ReasonOutOfContract ||
		res.items[0].AssetsCount != 1 || res.items[0].FindingsCount != 1 || res.items[0].ToolName != "dnsx" {
		t.Fatalf("quarantined = %+v", res.items)
	}
	var held ctis.Report
	if err := json.Unmarshal(res.items[0].Payload, &held); err != nil || len(held.Assets) != 1 || held.Assets[0].ID != "a3" {
		t.Fatalf("held payload = %+v, %v", held, err)
	}
	if len(in.Assets) != 3 {
		t.Fatal("the input report was changed")
	}
}

// Warn mode (existing tenants): applied whole, nothing quarantined.
func TestBindOutputTypes_WarnModeApplies(t *testing.T) {
	res := &policyResults{mode: sensorresult.ModeWarn}
	s := &Service{logger: logger.NewNop(), results: res}
	got := s.bindOutputTypes(context.Background(), &sensor.Sensor{ID: shared.NewID()}, shared.NewID(), boundCommand("dnsx"), dnsxReport(), Options{})
	if len(got.Assets) != 3 || len(res.items) != 0 {
		t.Fatalf("warn mode: %d assets applied, %d quarantined", len(got.Assets), len(res.items))
	}
}

// No contract: an unsolicited report, a tool the catalog does not know (a
// tenant's custom tool), a findings-only report.
func TestBindOutputTypes_NoContract(t *testing.T) {
	res := &policyResults{mode: sensorresult.ModeQuarantine}
	s := &Service{logger: logger.NewNop(), results: res}
	agt := &sensor.Sensor{ID: shared.NewID()}
	if got := s.bindOutputTypes(context.Background(), agt, shared.NewID(), Binding{}, dnsxReport(), Options{}); len(got.Assets) != 3 {
		t.Error("an unsolicited report was bound (it has its own gate)")
	}
	if got := s.bindOutputTypes(context.Background(), agt, shared.NewID(), boundCommand("acme-custom"), dnsxReport(), Options{}); len(got.Assets) != 3 {
		t.Error("a tool without a contract was bound")
	}
	if len(res.items) != 0 {
		t.Fatal("quarantined without a contract")
	}
}

// A report of a tool with a contract keeps the inputs it re-observes, and
// an unclassified asset is out of every contract.
func TestBindOutputTypes_ReobservedInputsAndUnclassified(t *testing.T) {
	s := &Service{logger: logger.NewNop(), results: &policyResults{mode: sensorresult.ModeQuarantine}}
	r := &ctis.Report{Tool: &ctis.Tool{Name: "httpx"}, Assets: []ctis.Asset{
		{ID: "s", Type: ctis.AssetTypeHTTPService, Value: "https://acme.test"},
		{ID: "d", Type: ctis.AssetTypeDomain, Value: "acme.test"},
		{ID: "u", Type: "made_up_type", Value: "x"},
	}}
	got := s.bindOutputTypes(context.Background(), &sensor.Sensor{ID: shared.NewID()}, shared.NewID(), boundCommand("httpx"), r, Options{})
	ids := map[string]bool{}
	for _, a := range got.Assets {
		ids[a.ID] = true
	}
	if !ids["s"] || !ids["d"] || ids["u"] {
		t.Fatalf("applied %v", ids)
	}
}
