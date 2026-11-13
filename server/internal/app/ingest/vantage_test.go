package ingest

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type recordedAnswers struct {
	calls   int
	tenant  shared.ID
	sensor  shared.ID
	zone    *shared.ID
	answers map[string][]netip.Addr
}

func (r *recordedAnswers) RecordAnswers(_ context.Context, tenantID, sensorID shared.ID, zoneID *shared.ID, answers map[string][]netip.Addr, _ time.Time) error {
	r.calls++
	r.tenant, r.sensor, r.zone, r.answers = tenantID, sensorID, zoneID, answers
	return nil
}

func dnsReport() *ctis.Report {
	return &ctis.Report{Assets: []ctis.Asset{
		{ID: "a", Type: ctis.AssetTypeDomainName, Value: "Intranet.Example.com", Name: "Intranet.Example.com",
			Properties: ctis.Properties{"ip_addresses": []any{"10.20.0.5", "bogus"}}},
		{ID: "b", Type: ctis.AssetTypeHost, Value: "10.1.2.3", Name: "10.1.2.3",
			Properties: ctis.Properties{"ip_addresses": []any{"10.1.2.3"}}},
	}}
}

// The observer is the authenticated sensor and the zone the command's, never
// a value of the report.
func TestRecordVantage_FromBoundCommandOfOwnSensor(t *testing.T) {
	tenant, zone, cmd := shared.NewID(), shared.NewID(), shared.NewID()
	agt := &sensor.Sensor{ID: shared.NewID(), TenantID: &tenant, Scope: sensor.ScopeOrganization}
	rec := &recordedAnswers{}
	s := &Service{logger: logger.NewNop(), vantage: rec}
	s.recordVantage(context.Background(), agt, tenant, Binding{Kind: BindingCommand, CommandID: &cmd, ScanZoneID: &zone}, dnsReport(), time.Now())
	if rec.calls != 1 || rec.sensor != agt.ID || rec.tenant != tenant || rec.zone == nil || *rec.zone != zone {
		t.Fatalf("recorded %+v", rec)
	}
	got := rec.answers["intranet.example.com"]
	if len(got) != 1 || got[0] != netip.MustParseAddr("10.20.0.5") || len(rec.answers) != 1 {
		t.Fatalf("answers = %v, want intranet.example.com -> 10.20.0.5 only", rec.answers)
	}
}

func TestRecordVantage_NothingFromSharedUnboundOrOtherTenant(t *testing.T) {
	tenant, other, cmd := shared.NewID(), shared.NewID(), shared.NewID()
	bound := Binding{Kind: BindingCommand, CommandID: &cmd}
	cases := map[string]struct {
		agt *sensor.Sensor
		b   Binding
	}{
		"shared sensor":        {&sensor.Sensor{ID: shared.NewID(), TenantID: &tenant, Scope: sensor.ScopeInstance}, bound},
		"unsolicited report":   {&sensor.Sensor{ID: shared.NewID(), TenantID: &tenant}, Binding{Kind: BindingUnsolicited}},
		"trusted ingest":       {&sensor.Sensor{TenantID: &tenant}, TrustedBinding()},
		"sensor of a tenant B": {&sensor.Sensor{ID: shared.NewID(), TenantID: &other}, bound},
	}
	for name, c := range cases {
		rec := &recordedAnswers{}
		(&Service{logger: logger.NewNop(), vantage: rec}).recordVantage(context.Background(), c.agt, tenant, c.b, dnsReport(), time.Now())
		if rec.calls != 0 {
			t.Errorf("%s: recorded %v", name, rec.answers)
		}
	}
}
