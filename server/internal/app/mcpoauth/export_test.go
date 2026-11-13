package mcpoauth

import "time"

// SetClock replaces the service clock in tests.
func SetClock(s *Service, now func() time.Time) { s.now = now }
