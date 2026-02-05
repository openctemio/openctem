package postgres

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Helper functions for null handling in PostgreSQL queries

// nullString converts a string to sql.NullString.
// Empty strings are treated as NULL.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// nullStringValue extracts a string from sql.NullString.
// Returns empty string if NULL.
func nullStringValue(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

// nullTime converts a *time.Time to sql.NullTime.
// nil is treated as NULL.
func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// nullTimeValue extracts a *time.Time from sql.NullTime.
// Returns nil if NULL.
func nullTimeValue(nt sql.NullTime) *time.Time {
	if nt.Valid {
		return &nt.Time
	}
	return nil
}

// nullBoolValue extracts a *bool from sql.NullBool.
// Returns nil if NULL.
func nullBoolValue(nb sql.NullBool) *bool {
	if nb.Valid {
		return &nb.Bool
	}
	return nil
}

// parseNullID parses a sql.NullString into *shared.ID.
// Returns nil if NULL or if parsing fails.
func parseNullID(ns sql.NullString) *shared.ID {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	id, err := shared.IDFromString(ns.String)
	if err != nil {
		return nil
	}
	return &id
}

// nullID helper for optional shared.ID pointers.
func nullID(id *shared.ID) sql.NullString {
	if id == nil || id.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: id.String(), Valid: true}
}

// nullIDValue converts a shared.ID to sql.NullString, returning null if the ID is zero.
func nullIDValue(id shared.ID) sql.NullString {
	if id.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: id.String(), Valid: true}
}

// nullIDPtr converts a *shared.ID to sql.NullString.
func nullIDPtr(id *shared.ID) sql.NullString {
	return nullID(id)
}

// isUniqueViolation checks if the error is a PostgreSQL unique constraint violation.
func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}

// parseIP parses an IP address string into net.IP.
func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

// nullBytes returns nil if the byte slice is empty, otherwise returns the slice.
// Used for optional JSONB columns where we want to insert NULL instead of empty bytes.
func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// toJSONB marshals a value to JSON bytes for JSONB columns.
// Returns nil if the value is nil.
func toJSONB(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
}

// fromJSONB unmarshals JSON bytes from a JSONB column into the target.
// Does nothing if data is nil or empty.
func fromJSONB(data []byte, target any) error {
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, target)
}
