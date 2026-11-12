// Package dberr classifies database errors.
//
// IsTransient tells a failure that may pass when the same work runs again
// later (the connection dropped, the server is restarting, a lock or
// statement timed out, two writers collided, the pool had no connection
// before the deadline) from one that will fail the same way every time
// (a constraint, a bad value, a missing table). Callers that must never
// lose data use it to retry the first kind instead of recording a final
// failure.
package dberr

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"

	"github.com/lib/pq"
)

// transientCodes are the PostgreSQL SQLSTATEs that say "try again later".
var transientCodes = map[string]bool{
	"40001": true, // serialization_failure
	"40P01": true, // deadlock_detected
	"55P03": true, // lock_not_available (lock_timeout)
	"57014": true, // query_canceled (statement_timeout)
	"57P01": true, // admin_shutdown
	"57P02": true, // crash_shutdown
	"57P03": true, // cannot_connect_now
	"25P03": true, // idle_in_transaction_session_timeout
	"53000": true, // insufficient_resources
	"53100": true, // disk_full
	"53200": true, // out_of_memory
	"53300": true, // too_many_connections
}

// IsTransient reports whether err is a database or connection failure that
// may succeed when the same work is run again. A nil error is not.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	// A deadline (a statement timeout, or no pooled connection free before
	// the deadline) or a cancel (the worker is stopping) ends this attempt,
	// not the work.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	if errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EPIPE) {
		return true
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		// Class 08: connection exception.
		code := string(pqErr.Code)
		if strings.HasPrefix(code, "08") {
			return true
		}
		return transientCodes[code]
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}
