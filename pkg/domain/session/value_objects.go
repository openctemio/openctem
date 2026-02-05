package session

// Status represents the status of a session.
type Status string

const (
	// StatusActive indicates an active session.
	StatusActive Status = "active"
	// StatusExpired indicates an expired session.
	StatusExpired Status = "expired"
	// StatusRevoked indicates a revoked session.
	StatusRevoked Status = "revoked"
)

// IsValid checks if the status is valid.
func (s Status) IsValid() bool {
	switch s {
	case StatusActive, StatusExpired, StatusRevoked:
		return true
	default:
		return false
	}
}

// String returns the string representation of the status.
func (s Status) String() string {
	return string(s)
}

// IsActive returns true if the session is active.
func (s Status) IsActive() bool {
	return s == StatusActive
}

// StatusFromString converts a string to Status.
func StatusFromString(s string) Status {
	switch s {
	case "active":
		return StatusActive
	case "expired":
		return StatusExpired
	case "revoked":
		return StatusRevoked
	default:
		return StatusActive
	}
}
