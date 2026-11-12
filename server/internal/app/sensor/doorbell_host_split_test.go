package sensor

import (
	"context"
	"errors"
	"testing"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeSplits struct {
	n       int
	err     error
	calls   int
	tenant  shared.ID
	sensor  shared.ID
	ctxLive bool
}

func (f *fakeSplits) HostSplitReady(ctx context.Context, tenantID, sensorID shared.ID, _ []string) (int, error) {
	f.calls++
	f.tenant, f.sensor = tenantID, sensorID
	f.ctxLive = ctx.Err() == nil
	return f.n, f.err
}

// Live 2026-11-04: every pending task of the organization waited for a host
// another run's task held on a few of its targets. The claim splits such a
// task and starts its free targets, but the doorbell counted only tasks
// whose hosts were all free: it said pending_jobs=0, and the idle sensor
// took the work only on its 5-minute safety poll. It now rings for them.
func TestDoorbell_RingsForWorkTheClaimWouldSplit(t *testing.T) {
	splits := &fakeSplits{n: 1}
	d := newTestDoorbell(&fakeWork{})
	d.SetHostSplits(splits)
	a := testSensor()
	h := d.Ring(context.Background(), DoorbellRequest{Identity: SensorIdentity{Sensor: a}})
	if h.PendingJobs != 1 || h.NextHeartbeatSeconds != 5 {
		t.Fatalf("got pending=%d next=%d, want 1 and the 5s busy interval", h.PendingJobs, h.NextHeartbeatSeconds)
	}
	// Asked for the authenticated sensor's own organization only.
	if splits.tenant != *a.TenantID || splits.sensor != a.ID || !splits.ctxLive {
		t.Fatalf("split count asked for tenant %s sensor %s (ctx live %v)", splits.tenant, splits.sensor, splits.ctxLive)
	}
}

func TestDoorbell_HostSplitCountOnlyWhenItMatters(t *testing.T) {
	a := testSensor()
	for name, tc := range map[string]struct {
		work sensordom.PendingWork
		req  DoorbellRequest
	}{
		// Work whose hosts are free already rings; no second read.
		"work already waiting": {work: sensordom.PendingWork{Count: 2}, req: DoorbellRequest{Identity: SensorIdentity{Sensor: a}}},
		// A full sensor would not claim, so nothing would be split.
		"no free slot": {req: DoorbellRequest{Identity: SensorIdentity{Sensor: a}, NoFreeSlots: true}},
		// A paused sensor claims nothing.
		"paused": {req: DoorbellRequest{Identity: SensorIdentity{Sensor: a, Paused: true}}},
	} {
		t.Run(name, func(t *testing.T) {
			splits := &fakeSplits{n: 3}
			d := newTestDoorbell(&fakeWork{work: tc.work})
			d.SetHostSplits(splits)
			h := d.Ring(context.Background(), tc.req)
			if splits.calls != 0 {
				t.Fatalf("split count read %d times", splits.calls)
			}
			if h.PendingJobs != tc.work.Count {
				t.Fatalf("pending %d, want %d", h.PendingJobs, tc.work.Count)
			}
		})
	}

	// A shared (platform) sensor has no organization: never asked.
	p := testSensor()
	p.TenantID = nil
	p.Scope = sensordom.ScopeInstance
	splits := &fakeSplits{n: 3}
	d := newTestDoorbell(&fakeWork{})
	d.SetHostSplits(splits)
	if h := d.Ring(context.Background(), DoorbellRequest{Identity: SensorIdentity{Sensor: p}}); splits.calls != 0 || h.PendingJobs != 0 {
		t.Fatalf("platform sensor: %d split reads, pending %d", splits.calls, h.PendingJobs)
	}
}

// A failing split count never fails the heartbeat nor drops its other hints.
func TestDoorbell_HostSplitFailureIsQuiet(t *testing.T) {
	d := newTestDoorbell(&fakeWork{work: sensordom.PendingWork{ZoneFingerprint: "z@1"}})
	d.SetHostSplits(&fakeSplits{n: 4, err: errors.New("boom")})
	h := d.Ring(context.Background(), DoorbellRequest{Identity: SensorIdentity{Sensor: testSensor()}, Aware: true})
	if h.PendingJobs != 0 || h.ConfigVersion == "" || h.NextHeartbeatSeconds == 0 {
		t.Fatalf("hints after a failed split count: %+v", h)
	}
}
