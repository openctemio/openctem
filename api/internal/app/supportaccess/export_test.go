package supportaccess

import "time"

// SetClock replaces the service clock (tests).
func SetClock(s *Service, now func() time.Time) { s.now = now }
