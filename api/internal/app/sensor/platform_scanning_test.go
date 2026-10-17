package sensor

import (
	"context"
	"errors"
	"reflect"
	"testing"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakePlatformStore struct {
	sum   *sensordom.PlatformScanningSummary
	err   error
	calls int
}

func (f *fakePlatformStore) PlatformScanningSummary(context.Context, shared.ID) (*sensordom.PlatformScanningSummary, error) {
	f.calls++
	return f.sum, f.err
}

func allow(ok bool) PlatformScanningPolicy {
	return func(context.Context, shared.ID) (bool, string) { return ok, "" }
}

func TestPlatformScanning_NotOfferedSaysNothingElse(t *testing.T) {
	store := &fakePlatformStore{sum: &sensordom.PlatformScanningSummary{
		Regions: []sensordom.PlatformRegionState{{Region: "eu", Online: true, FreeSlot: true}}, Tools: []string{"nuclei"}, Queued: 2}}
	for name, svc := range map[string]*PlatformScanningService{
		"no policy":        NewPlatformScanningService(store, nil),
		"policy refuses":   NewPlatformScanningService(store, allow(false)),
		"no sensor at all": NewPlatformScanningService(&fakePlatformStore{sum: &sensordom.PlatformScanningSummary{}}, allow(true)),
	} {
		got, err := svc.Get(context.Background(), shared.NewID())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.Offered || got.Status != "" || len(got.Regions) != 0 || len(got.Tools) != 0 || got.YourJobs.Queued != 0 ||
			got.Regions == nil || got.Tools == nil {
			t.Errorf("%s: %+v", name, got)
		}
	}
	if store.calls != 0 {
		t.Errorf("read the platform sensors for a tenant that may not use them (%d calls)", store.calls)
	}
}

func TestPlatformScanning_StatusIsTheBestRegion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		regions []sensordom.PlatformRegionState
		want    string
	}{
		{"one free", []sensordom.PlatformRegionState{{Region: "us"}, {Region: "eu", Online: true, FreeSlot: true}}, PlatformScanningAvailable},
		{"all full", []sensordom.PlatformRegionState{{Region: "eu", Online: true}, {Region: "us"}}, PlatformScanningBusy},
		{"none online", []sensordom.PlatformRegionState{{Region: "eu"}}, PlatformScanningUnavailable},
	} {
		svc := NewPlatformScanningService(&fakePlatformStore{sum: &sensordom.PlatformScanningSummary{Regions: tc.regions, Running: 1}}, allow(true))
		got, err := svc.Get(context.Background(), shared.NewID())
		if err != nil {
			t.Fatal(err)
		}
		if !got.Offered || got.Status != tc.want || len(got.Regions) != len(tc.regions) || got.YourJobs.Running != 1 ||
			got.QueueLimitMinutes != PlatformQueueLimitMinutes || got.Tools == nil {
			t.Errorf("%s: %+v", tc.name, got)
		}
	}
}

func TestPlatformScanning_StoreError(t *testing.T) {
	svc := NewPlatformScanningService(&fakePlatformStore{err: errors.New("db down")}, allow(true))
	if _, err := svc.Get(context.Background(), shared.NewID()); err == nil {
		t.Fatal("a store error was swallowed")
	}
}

// The published egress addresses are shown only to an organization that may
// use shared sensors, global list first, then regions in label order; an
// organization that may not use them learns nothing, not even the list.
func TestPlatformScanning_Egress(t *testing.T) {
	store := &fakePlatformStore{sum: &sensordom.PlatformScanningSummary{
		Regions: []sensordom.PlatformRegionState{{Region: "eu", Online: true, FreeSlot: true}}}}
	reads := 0
	src := func(context.Context) ([]PlatformEgress, error) {
		reads++
		return EgressFromLists([]string{"203.0.113.0/24"}, map[string][]string{"us": {"198.51.100.2"}, "eu": {"198.51.100.1"}, "none": {}}), nil
	}
	got, err := NewPlatformScanningService(store, allow(true)).WithEgress(src).Get(context.Background(), shared.NewID())
	if err != nil {
		t.Fatal(err)
	}
	want := []PlatformEgress{{Addresses: []string{"203.0.113.0/24"}}, {Region: "eu", Addresses: []string{"198.51.100.1"}}, {Region: "us", Addresses: []string{"198.51.100.2"}}}
	if !reflect.DeepEqual(got.Egress, want) {
		t.Fatalf("egress: %+v", got.Egress)
	}
	reads = 0
	off, err := NewPlatformScanningService(store, allow(false)).WithEgress(src).Get(context.Background(), shared.NewID())
	if err != nil || off.Egress == nil || len(off.Egress) != 0 || reads != 0 {
		t.Fatalf("not offered: %+v %v reads=%d", off, err, reads)
	}
	// None published: an empty list, never null.
	empty, _ := NewPlatformScanningService(store, allow(true)).WithEgress(func(context.Context) ([]PlatformEgress, error) { return nil, nil }).
		Get(context.Background(), shared.NewID())
	if empty.Egress == nil || len(empty.Egress) != 0 {
		t.Fatalf("none published: %+v", empty.Egress)
	}
	if _, err := NewPlatformScanningService(store, allow(true)).WithEgress(func(context.Context) ([]PlatformEgress, error) {
		return nil, errors.New("db down")
	}).Get(context.Background(), shared.NewID()); err == nil {
		t.Fatal("an egress read error was swallowed")
	}
}
