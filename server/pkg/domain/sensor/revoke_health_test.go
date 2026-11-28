package sensor

import "testing"

// A sensor that can no longer authenticate is not reachable: revoking or
// disabling it ends its "online" health at once, whatever its last heartbeat.
func TestRevokeAndDisableEndOnlineHealth(t *testing.T) {
	for name, end := range map[string]func(*Sensor){
		"revoke":  func(s *Sensor) { s.Revoke("retired") },
		"disable": func(s *Sensor) { s.Disable("paused") },
	} {
		s := &Sensor{Status: SensorStatusActive}
		s.UpdateLastSeen()
		if s.Health != SensorHealthOnline {
			t.Fatalf("%s: setup health %q", name, s.Health)
		}
		end(s)
		if s.Health != SensorHealthOffline {
			t.Errorf("%s: health %q, want offline", name, s.Health)
		}
	}
}
