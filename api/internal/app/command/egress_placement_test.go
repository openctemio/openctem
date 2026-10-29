package command

import (
	"context"
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/proxypool"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeSensors map[shared.ID]*sensordom.Sensor

func (f fakeSensors) GetByTenantAndID(_ context.Context, _, id shared.ID) (*sensordom.Sensor, error) {
	if s, ok := f[id]; ok {
		return s, nil
	}
	return nil, shared.ErrNotFound
}

type fakeEgress struct {
	tenant shared.ID
	pool   string
	name   string
}

func (f fakeEgress) JobEgress(context.Context, shared.ID, shared.ID) (*proxypool.JobEgress, error) {
	return &proxypool.JobEgress{Mode: proxypool.ModePool, PoolID: f.pool}, nil
}

// PoolName never names another tenant's pool.
func (f fakeEgress) PoolName(_ context.Context, tenantID shared.ID, poolID string) string {
	if tenantID != f.tenant || poolID != f.pool {
		return ""
	}
	return f.name
}

func TestEgressHoldsExplainThemselves(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	withCaps := func(caps ...string) *sensordom.Sensor {
		return &sensordom.Sensor{Name: "edge-1", Reported: sensordom.CapabilityReport{Capabilities: caps}}
	}
	old, valid, full := shared.NewID(), shared.NewID(), shared.NewID()
	svc := &Service{
		sensors: fakeSensors{
			old:   withCaps(),
			valid: withCaps(sensordom.CapabilityEgressUpstream, sensordom.CapabilityNetConfined),
			full: withCaps(sensordom.CapabilityEgressUpstream, sensordom.CapabilityNetConfined,
				sensordom.CapabilityEgressValidate),
		},
		egress: fakeEgress{tenant: tenant, pool: "pool-1", name: "EU exit"},
	}
	scan := &commanddom.Command{Type: commanddom.CommandTypeScan}
	validate := &commanddom.Command{Type: commanddom.CommandTypeValidate}
	cases := []struct {
		name   string
		sensor shared.ID
		cmd    *commanddom.Command
		want   string
	}{
		{"no proxy support holds scans", old, scan, commanddom.PlacementEgressUnsupported},
		{"no proxy support holds validate", old, validate, commanddom.PlacementEgressValidateUnsupported},
		{"proxy-capable sensor, no validate support", valid, validate, commanddom.PlacementEgressValidateUnsupported},
		{"proxy-capable sensor runs scans", valid, scan, ""},
		{"full support runs validate", full, validate, ""},
	}
	for _, c := range cases {
		d, err := svc.egressFor(context.Background(), tenant, c.sensor.String(), []*commanddom.Command{c.cmd})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := d.holdReason(c.cmd.Type); got != c.want {
			t.Errorf("%s: reason = %q, want %q", c.name, got, c.want)
		}
		if c.want != "" {
			w := svc.egressWait(context.Background(), tenant, d)
			if w == nil || w.PoolID != "pool-1" || w.PoolName != "EU exit" {
				t.Errorf("%s: pool = %+v", c.name, w)
			}
			// The name is read tenant-scoped: another tenant gets none.
			if w := svc.egressWait(context.Background(), other, d); w == nil || w.PoolName != "" {
				t.Errorf("%s: another tenant's read named the pool: %+v", c.name, w)
			}
		}
	}
	// A command that never reaches targets is not held.
	if d := (egressDecision{blocked: true, validateBlocked: true}); d.holdReason(commanddom.CommandTypeCollect) != "" {
		t.Errorf("a non-job command has a hold reason")
	}
}

// A host direct-only sensor that needs a pool is held for its own reason,
// scans and validate alike: upgrading the sensor does not help.
func TestEgressDecision_HostDirectHoldReason(t *testing.T) {
	d := egressDecision{blocked: true, validateBlocked: true, hostDirect: true}
	for _, typ := range []commanddom.CommandType{commanddom.CommandTypeScan, commanddom.CommandTypeValidate} {
		if got := d.holdReason(typ); got != commanddom.PlacementEgressHostDirect {
			t.Errorf("%s: reason = %q, want %q", typ, got, commanddom.PlacementEgressHostDirect)
		}
	}
	if got := d.holdReason(commanddom.CommandTypeCollect); got != "" {
		t.Errorf("a non-job command has a hold reason: %q", got)
	}
}
