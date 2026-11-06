package proxypool

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	pooldom "github.com/openctemio/openctem/api/pkg/domain/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeExitStore struct {
	pooldom.ExitStore
	exits   []pooldom.ExitRow
	sensors []pooldom.SensorEgressRow
	tenant  shared.ID
}

func (f *fakeExitStore) ListEndpointExits(_ context.Context, tid shared.ID, _ time.Time) ([]pooldom.ExitRow, error) {
	if tid != f.tenant {
		return nil, nil
	}
	return f.exits, nil
}

func (f *fakeExitStore) ListSensorEgress(_ context.Context, tid shared.ID, _ time.Time) ([]pooldom.SensorEgressRow, error) {
	if tid != f.tenant {
		return nil, nil
	}
	return f.sensors, nil
}

func TestScannerAddressesMergesSortsAndDedupes(t *testing.T) {
	tid := shared.NewID()
	store := &fakeExitStore{tenant: tid,
		exits: []pooldom.ExitRow{{PoolName: "p", Address: netip.MustParseAddr("2001:db8::5")},
			{PoolName: "p", Address: netip.MustParseAddr("203.0.113.9")}},
		sensors: []pooldom.SensorEgressRow{{SensorName: "s", Address: netip.MustParseAddr("203.0.113.9")},
			{SensorName: "s", Address: netip.MustParseAddr("10.1.2.3")}}}
	s := NewService(nil, nil, nil, logger.NewNop())
	s.EnableScannerAddresses(store, func(context.Context, shared.ID) ([]PlatformEgress, error) {
		return []PlatformEgress{{Region: "eu", Addresses: []string{"198.51.100.0/25", "198.51.100.77/25", "junk", " 192.0.2.4 "}}}, nil
	})
	got, err := s.ScannerAddresses(context.Background(), tid.String())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.1.2.3/32", "192.0.2.4/32", "198.51.100.0/25", "203.0.113.9/32", "2001:db8::5/128"}
	if !slices.Equal(got.CIDRs, want) {
		t.Fatalf("cidrs = %v, want %v", got.CIDRs, want)
	}
	priv := map[string]bool{}
	for _, it := range got.Items {
		priv[it.Address] = it.Private
	}
	if !priv["10.1.2.3"] || priv["203.0.113.9"] {
		t.Fatalf("private flags %v", priv)
	}
	if len(got.Items) != 7 {
		t.Fatalf("items = %d %+v", len(got.Items), got.Items)
	}
	// Another tenant reads none of it (the store is tenant-scoped; the
	// platform source decides per tenant).
	s.EnableScannerAddresses(store, nil)
	other, err := s.ScannerAddresses(context.Background(), shared.NewID().String())
	if err != nil || len(other.Items) != 0 || len(other.CIDRs) != 0 {
		t.Fatalf("another tenant = %+v %v", other, err)
	}
	if _, err := s.ScannerAddresses(context.Background(), "nope"); err == nil {
		t.Fatal("a malformed tenant was accepted")
	}
}
