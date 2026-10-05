package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
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

// isCheckViolation checks if the error is a PostgreSQL CHECK constraint violation
// (SQLSTATE 23514). Callers should map this to a 400 rather than a 500 — it means
// the supplied value (e.g. an enum) is outside the column's allowed set.
func isCheckViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23514"
	}
	return false
}

// isForeignKeyViolation checks if the error is a PostgreSQL foreign-key violation
// (SQLSTATE 23503) — e.g. referencing an asset/row that does not exist. Callers
// should map this to a 400/404 rather than a 500.
func isForeignKeyViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23503"
	}
	return false
}

// invalidInput reports a database rejection of caller-supplied values as
// shared.ErrValidation, so the handler above answers 400 instead of 500:
//
//	22001 string_data_right_truncation — a value longer than its column
//	23514 check_violation              — a value outside the column's allowed set
//	23503 foreign_key_violation        — a reference to a row that does not exist
//
// It returns nil for every other error, which the caller wraps as before.
func invalidInput(err error) error {
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return nil
	}
	switch pqErr.Code {
	case "22001":
		return fmt.Errorf("%w: a field is longer than its maximum length", shared.ErrValidation)
	case "23514":
		return fmt.Errorf("%w: a field has a value that is not allowed", shared.ErrValidation)
	case "23503":
		return fmt.Errorf("%w: a referenced record does not exist", shared.ErrValidation)
	}
	return nil
}

// deletedOne turns a tenant-scoped DELETE that matched no row into
// shared.ErrNotFound. Without it a DELETE of an unknown id — or of another
// tenant's id, which the tenant_id predicate filters out — reported success.
func deletedOne(res sql.Result, what string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete %s: rows affected: %w", what, err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s not found", shared.ErrNotFound, what)
	}
	return nil
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

// unmarshalJSONBMap decodes JSONB bytes into a map.

// nullIngestChannel maps an unset channel to SQL NULL.
//
// findings.ingest_channel is the source_type enum and ” is not one of its
// members, so writing an empty string fails the insert and loses the whole
// finding over a provenance label nobody asked for. NULL is also the honest
// value: it means "not recorded", which is true of every row written before
// migration 000197.
func nullIngestChannel(c vulnerability.IngestChannel) interface{} {
	if c == "" {
		return nil
	}
	return string(c)
}
