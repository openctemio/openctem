package signer

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

const (
	tZoneA       = "11111111-1111-4111-8111-111111111111"
	tZoneB       = "22222222-2222-4222-8222-222222222222"
	tOtherTenant = "33333333-3333-4333-8333-333333333333"
	tOtherSensor = "44444444-4444-4444-8444-444444444444"
)

func putZone(t *testing.T, s *Service, z jobsign.LedgerZone) {
	t.Helper()
	if _, ref := s.ledger.ApplyZone(jobsign.ZoneChange{Requester: "admin", Put: &z}, tNow); ref != nil {
		t.Fatalf("zone put refused: %+v", ref)
	}
}

func zoneJob(zoneID string, ranges []string, targets ...string) []byte {
	return statement(func(m map[string]any) {
		m["sensor_scope"] = jobsign.SensorScopeInstance
		m["targets"] = targets
		if zoneID != "" {
			m["zone"] = map[string]any{"id": zoneID, "ranges": ranges}
		}
	})
}

// A shared sensor reaches internal space only inside an instance scan zone
// in the signer's own zone ledger, assigned to the job's organization,
// served by the claiming sensor, with exactly that zone's ranges; and only
// targets inside the signed ranges. Overlapping ranges of two organizations
// are told apart by the zone.
func TestSign_InstanceZoneRules(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), nil)
	ranges := []string{"10.20.0.0/16"}
	// Organization A's zone and organization B's zone cover the same range.
	putZone(t, s, jobsign.LedgerZone{ID: tZoneA, Ranges: ranges, Tenants: []string{tTenant}, Sensors: []string{tSensor}})
	putZone(t, s, jobsign.LedgerZone{ID: tZoneB, Ranges: ranges, Tenants: []string{tOtherTenant}, Sensors: []string{tSensor}})

	// Within its own zone: signed, and the zone is in the signed payload.
	env, ref := s.Sign(zoneJob(tZoneA, ranges, "10.20.1.5", "10.20.2.0/24", "https://10.20.3.4:8443/", "203.0.113.10"))
	if ref != nil {
		t.Fatalf("a job inside its zone was refused: %+v", ref)
	}
	if _, st := decodeEnvelope(t, env); st.Zone == nil || st.Zone.ID != tZoneA || len(st.Zone.Ranges) != 1 {
		t.Fatalf("signed statement zone = %+v", st.Zone)
	}

	refused := []struct {
		name   string
		raw    []byte
		reason string
	}{
		// No zone: internal stays refused.
		{"internal without zone", zoneJob("", nil, "10.20.1.5"), ReasonSharedInternal},
		// The signed ranges bound the targets.
		{"internal outside the zone", zoneJob(tZoneA, ranges, "10.21.0.1"), ReasonSharedInternal},
		{"range wider than the zone", zoneJob(tZoneA, ranges, "10.0.0.0/8"), ReasonSharedInternal},
		{"loopback inside a zone job", zoneJob(tZoneA, ranges, "127.0.0.1"), ReasonSharedInternal},
		{"metadata inside a zone job", zoneJob(tZoneA, ranges, "169.254.169.254"), ReasonSharedInternal},
		{"internal name inside a zone job", zoneJob(tZoneA, ranges, "db.internal"), ReasonSharedInternal},
		// Organization A cannot use organization B's zone, even for the
		// same range.
		{"another organization's zone", zoneJob(tZoneB, ranges, "10.20.1.5"), ReasonZoneNotAssigned},
		// A zone the signer never recorded.
		{"zone not in the ledger", zoneJob("55555555-5555-4555-8555-555555555555", ranges, "10.20.1.5"), ReasonZoneNotInLedger},
		// The API cannot widen the ranges it names.
		{"ranges not the zone's", zoneJob(tZoneA, []string{"10.0.0.0/8"}, "10.30.0.1"), ReasonZoneRanges},
		{"public range as zone", zoneJob(tZoneA, []string{"8.8.8.0/24"}, "8.8.8.8"), ReasonBadZone},
		{"unsorted ranges", zoneJob(tZoneA, []string{"10.20.0.0/16", "10.10.0.0/16"}, "10.20.0.1"), ReasonBadZone},
		// A zone on an organization's own statement.
		{"zone without shared scope", statement(func(m map[string]any) {
			m["zone"] = map[string]any{"id": tZoneA, "ranges": ranges}
		}), ReasonBadZone},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			env, ref := s.Sign(tc.raw)
			if ref == nil {
				t.Fatalf("signed: %s", env)
			}
			if ref.reason != tc.reason {
				t.Fatalf("refused with %s (%s), want %s", ref.reason, ref.detail, tc.reason)
			}
		})
	}

	// A sensor that does not serve the zone.
	other := statement(func(m map[string]any) {
		m["sensor_scope"] = jobsign.SensorScopeInstance
		m["sensor_id"] = tOtherSensor
		m["targets"] = []string{"10.20.1.5"}
		m["zone"] = map[string]any{"id": tZoneA, "ranges": ranges}
	})
	if _, ref := s.Sign(other); ref == nil || ref.reason != ReasonZoneSensor {
		t.Fatalf("a sensor outside the zone: %+v", ref)
	}

	// Unassigning the organization (a put without it) stops signing.
	putZone(t, s, jobsign.LedgerZone{ID: tZoneA, Ranges: ranges, Tenants: []string{}, Sensors: []string{tSensor}})
	if _, ref := s.Sign(zoneJob(tZoneA, ranges, "10.20.1.5")); ref == nil || ref.reason != ReasonZoneNotAssigned {
		t.Fatalf("zone no longer assigned: %+v", ref)
	}
	// Deleting it too.
	if _, ref := s.ledger.ApplyZone(jobsign.ZoneChange{Requester: "admin", DeleteID: tZoneA}, tNow); ref != nil {
		t.Fatal(ref)
	}
	if _, ref := s.Sign(zoneJob(tZoneA, ranges, "10.20.1.5")); ref == nil || ref.reason != ReasonZoneNotInLedger {
		t.Fatalf("deleted zone: %+v", ref)
	}
}

// The zone ledger survives a restart (it is replayed from ledger.log) and
// refuses malformed changes.
func TestZoneLedger_ReplayAndValidation(t *testing.T) {
	dir := t.TempDir()
	key := newKey(t)
	s := newService(t, dir, key, nil)
	ranges := []string{"192.168.10.0/24"}
	putZone(t, s, jobsign.LedgerZone{ID: tZoneA, Ranges: ranges, Tenants: []string{tTenant}, Sensors: []string{tSensor}})
	for name, ch := range map[string]jobsign.ZoneChange{
		"both":           {Put: &jobsign.LedgerZone{ID: tZoneB, Ranges: ranges}, DeleteID: tZoneA},
		"neither":        {},
		"bad id":         {Put: &jobsign.LedgerZone{ID: "zone-1", Ranges: ranges}},
		"public range":   {Put: &jobsign.LedgerZone{ID: tZoneB, Ranges: []string{"203.0.113.0/24"}}},
		"no range":       {Put: &jobsign.LedgerZone{ID: tZoneB, Ranges: []string{}}},
		"bad tenant":     {Put: &jobsign.LedgerZone{ID: tZoneB, Ranges: ranges, Tenants: []string{"x"}}},
		"bad delete id":  {DeleteID: "nope"},
		"loopback range": {Put: &jobsign.LedgerZone{ID: tZoneB, Ranges: []string{"127.0.0.0/8"}}},
	} {
		if _, ref := s.ledger.ApplyZone(ch, tNow); ref == nil || ref.reason != ReasonZoneMalformed {
			t.Fatalf("%s: %+v", name, ref)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := newService(t, dir, key, nil)
	if s2.ledger.ZoneCount() != 1 {
		t.Fatalf("zones after restart = %d, want 1", s2.ledger.ZoneCount())
	}
	if _, ref := s2.Sign(zoneJob(tZoneA, ranges, "192.168.10.7")); ref != nil {
		t.Fatalf("replayed zone does not sign: %+v", ref)
	}
}
