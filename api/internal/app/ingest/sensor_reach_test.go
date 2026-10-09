package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeReachGrants struct {
	g   *sensor.Grant
	err error
}

func (f fakeReachGrants) Get(context.Context, shared.ID, shared.ID) (*sensor.Grant, error) {
	return f.g, f.err
}

type fakeReachSource struct{ in ReachInputs }

func (f fakeReachSource) SensorReachInputs(context.Context, shared.ID, shared.ID, time.Time) (ReachInputs, error) {
	return f.in, nil
}

func (fakeReachSource) FingerprintAssetIDs(context.Context, shared.ID, []string) (map[string][]shared.ID, error) {
	return nil, nil
}

func (fakeReachSource) AssetLocators(context.Context, shared.ID, []shared.ID) ([]AssetLocator, error) {
	return nil, nil
}

func TestSensorReach_Roles(t *testing.T) {
	tid := shared.NewID()
	worker := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Type: sensor.SensorTypeWorker}
	for _, c := range []struct {
		name   string
		agt    *sensor.Sensor
		grants GrantReader
		all    bool
	}{
		{"collector type", &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Type: sensor.SensorTypeCollector}, nil, true},
		{"worker, no grants wired", worker, nil, false},
		{"ci-runner grant", worker, fakeReachGrants{g: &sensor.Grant{Profile: sensor.ProfileCIRunner}}, true},
		{"named collector grant", worker, fakeReachGrants{g: &sensor.Grant{Profile: sensor.ProfileCollector + ":aws"}}, true},
		{"internal scanner grant", worker, fakeReachGrants{g: &sensor.Grant{Profile: sensor.ProfileInternalScanner}}, false},
		{"legacy-broad grant", worker, fakeReachGrants{g: &sensor.Grant{Profile: sensor.ProfileLegacyBroad}}, false},
		{"no grant row", worker, fakeReachGrants{err: shared.ErrNotFound}, false},
	} {
		s := &Service{grants: c.grants}
		r, err := s.reachOf(context.Background(), c.agt, tid)
		if err != nil || r.all != c.all {
			t.Errorf("%s: all=%v err=%v, want all=%v", c.name, r.all, err, c.all)
		}
	}
	s := &Service{grants: fakeReachGrants{err: errors.New("db down")}}
	if _, err := s.reachOf(context.Background(), worker, tid); err == nil {
		t.Error("a grant read error must fail the lookup (fail closed)")
	}
}

func TestSensorReach_CommandsAndZones(t *testing.T) {
	tid := shared.NewID()
	agt := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Type: sensor.SensorTypeWorker}

	// Unwired: reaches nothing.
	r, err := (&Service{}).reachOf(context.Background(), agt, tid)
	if err != nil || r.all || r.covers("10.1.0.5", nil) {
		t.Fatalf("unwired reach covers something: %+v %v", r, err)
	}

	src := fakeReachSource{in: ReachInputs{
		CommandPayloads: []json.RawMessage{[]byte(`{"targets":["app.example.com"]}`), []byte(`{"target":"https://github.com/acme/api.git"}`)},
		ZoneRanges:      []string{"10.1.0.0/16"},
	}}
	r, err = (&Service{reach: src}).reachOf(context.Background(), agt, tid)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"10.1.0.5":               true,  // zone range
		"10.2.0.5":               false, // another zone
		"api.app.example.com":    true,  // under a command target
		"other.example.com":      false,
		"github.com/acme/api":    true, // the command's repository
		"github.com/acme/secret": false,
	} {
		if got := r.covers(name, nil); got != want {
			t.Errorf("covers(%q) = %v, want %v", name, got, want)
		}
	}
	// An asset reached through one of its IP addresses.
	if !r.covers("db.internal", map[string]any{asset.PropKeyIPAddresses: []any{"10.1.3.4"}}) {
		t.Error("asset with an address in the zone range not covered")
	}
}
