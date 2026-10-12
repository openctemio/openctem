package sensor

import (
	"context"
	"errors"
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
