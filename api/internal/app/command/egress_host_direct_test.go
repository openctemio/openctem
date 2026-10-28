package command

import (
	"context"
	"errors"
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/proxypool"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeEgressSource struct{ eg *proxypool.JobEgress }

func (f fakeEgressSource) JobEgress(context.Context, shared.ID, shared.ID) (*proxypool.JobEgress, error) {
	return f.eg, nil
}

type fakeSensorLookup struct{ sn *sensordom.Sensor }

func (f fakeSensorLookup) GetByTenantAndID(context.Context, shared.ID, shared.ID) (*sensordom.Sensor, error) {
	return f.sn, nil
}

type fakeRequirement struct {
	on  bool
	err error
}

func (f fakeRequirement) ProxyRequired(context.Context, shared.ID) (bool, error) { return f.on, f.err }

func egressService(sn *sensordom.Sensor, appliesTo string, req ProxyRequirement) *Service {
	eg := &proxypool.JobEgress{Mode: proxypool.ModePool, PoolID: shared.NewID().String(), AppliesTo: appliesTo,
		Endpoints: []proxypool.JobEndpoint{{ID: "e1", Scheme: "http", Host: "10.0.0.5", Port: 3128, Weight: 1}}}
	return &Service{egress: fakeEgressSource{eg: eg}, sensors: fakeSensorLookup{sn: sn}, proxyRequired: req}
}

func egressSensor(caps ...string) *sensordom.Sensor {
	tenant := shared.NewID()
	sn := &sensordom.Sensor{ID: shared.NewID(), TenantID: &tenant}
	sn.Reported.Capabilities = caps
	return sn
}

func egressScanCmds() []*commanddom.Command {
	c, _ := commanddom.NewCommand(shared.NewID(), commanddom.CommandTypeScan, commanddom.CommandPriorityNormal, []byte(`{"scanner":"x"}`))
	v, _ := commanddom.NewCommand(shared.NewID(), commanddom.CommandTypeValidate, commanddom.CommandPriorityNormal, []byte(`{}`))
	return []*commanddom.Command{c, v}
}

// A host direct-only sensor that inherits the organization's default pool
// runs direct: its jobs are delivered with no egress member (the pool is not
// stamped), not held for an upgrade it would never get.
func TestHostDirectSensorInheritingTheDefaultPoolRunsDirect(t *testing.T) {
	sn := egressSensor(sensordom.CapabilityNetConfined, sensordom.CapabilityEgressHostDirect)
	svc := egressService(sn, proxypool.AppliesPublic, nil)
	d, err := svc.egressFor(context.Background(), shared.NewID(), sn.ID.String(), egressScanCmds())
	if err != nil {
		t.Fatal(err)
	}
	if d.egress != nil || d.blocked || d.validateBlocked {
		t.Fatalf("decision %+v", d)
	}
	cmds, err := d.stamp(egressScanCmds())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cmds {
		if egressOf(c.Payload) {
			t.Fatalf("a direct job carries an egress member: %s", c.Payload)
		}
	}
}

func egressOf(payload []byte) bool {
	return len(payload) > 0 && containsKey(payload, `"egress"`)
}

func containsKey(b []byte, k string) bool {
	for i := 0; i+len(k) <= len(b); i++ {
		if string(b[i:i+len(k)]) == k {
			return true
		}
	}
	return false
}

// Without the marker the same sensor is still held (an old sensor that cannot
// honor a pool must not run direct); one that reports both is not host
// direct (it takes pools).
func TestWithoutTheMarkerAnOldSensorIsStillHeld(t *testing.T) {
	for name, sn := range map[string]*sensordom.Sensor{
		"no marker":           egressSensor(sensordom.CapabilityNetConfined),
		"marker and upstream": egressSensor(sensordom.CapabilityNetConfined, sensordom.CapabilityEgressUpstream, sensordom.CapabilityEgressHostDirect),
	} {
		svc := egressService(sn, proxypool.AppliesPublic, nil)
		d, err := svc.egressFor(context.Background(), shared.NewID(), sn.ID.String(), egressScanCmds())
		if err != nil {
			t.Fatal(err)
		}
		if name == "no marker" && (!d.blocked || d.hostDirect) {
			t.Errorf("%s: decision %+v", name, d)
		}
		if name == "marker and upstream" && (d.blocked || d.egress == nil || d.hostDirect) {
			t.Errorf("%s: decision %+v", name, d)
		}
	}
}

// A pool named for this sensor, or the organization requiring a proxy, is a
// conflict with the host's veto: the jobs wait (all types), never direct.
func TestHostDirectSensorIsHeldWhenAPoolIsNamedOrAProxyIsRequired(t *testing.T) {
	sn := egressSensor(sensordom.CapabilityNetConfined, sensordom.CapabilityEgressHostDirect)
	for name, svc := range map[string]*Service{
		"pool assigned to the sensor": egressService(sn, proxypool.AppliesAll, nil),
		"proxy required":              egressService(sn, proxypool.AppliesPublic, fakeRequirement{on: true}),
	} {
		d, err := svc.egressFor(context.Background(), shared.NewID(), sn.ID.String(), egressScanCmds())
		if err != nil {
			t.Fatal(err)
		}
		if !d.blocked || !d.validateBlocked || !d.hostDirect {
			t.Errorf("%s: decision %+v", name, d)
		}
		kept := d.withoutEgressJobs(egressScanCmds())
		if len(kept) != 0 {
			t.Errorf("%s: %d job(s) delivered", name, len(kept))
		}
	}
	// Proxy required switched off again: direct.
	d, err := egressService(sn, proxypool.AppliesPublic, fakeRequirement{on: false}).egressFor(context.Background(), shared.NewID(), sn.ID.String(), egressScanCmds())
	if err != nil || d.blocked || d.egress != nil {
		t.Fatalf("not required: %+v %v", d, err)
	}
}

// A requirement that cannot be read fails the delivery: a job never leaves
// on a guess.
func TestProxyRequirementErrorFailsDelivery(t *testing.T) {
	sn := egressSensor(sensordom.CapabilityEgressHostDirect)
	svc := egressService(sn, proxypool.AppliesPublic, fakeRequirement{err: errors.New("db down")})
	if _, err := svc.egressFor(context.Background(), shared.NewID(), sn.ID.String(), egressScanCmds()); err == nil {
		t.Fatal("expected an error")
	}
}
