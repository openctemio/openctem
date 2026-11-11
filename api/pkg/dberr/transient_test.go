package dberr

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/lib/pq"
)

func TestIsTransient(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"deadline", context.DeadlineExceeded, true},
		{"canceled", context.Canceled, true},
		{"wrapped deadline", fmt.Errorf("upsert: %w", context.DeadlineExceeded), true},
		{"bad conn", driver.ErrBadConn, true},
		{"conn done", sql.ErrConnDone, true},
		{"reset", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, true},
		{"refused", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), true},
		{"serialization", &pq.Error{Code: "40001"}, true},
		{"deadlock", fmt.Errorf("batch: %w", &pq.Error{Code: "40P01"}), true},
		{"lock timeout", &pq.Error{Code: "55P03"}, true},
		{"statement timeout", &pq.Error{Code: "57014"}, true},
		{"admin shutdown", &pq.Error{Code: "57P01"}, true},
		{"cannot connect now", &pq.Error{Code: "57P03"}, true},
		{"connection failure", &pq.Error{Code: "08006"}, true},
		{"too many connections", &pq.Error{Code: "53300"}, true},
		{"unique violation", &pq.Error{Code: "23505"}, false},
		{"invalid utf8", &pq.Error{Code: "22021"}, false},
		{"check violation", &pq.Error{Code: "23514"}, false},
		{"undefined column", &pq.Error{Code: "42703"}, false},
		{"no rows", sql.ErrNoRows, false},
		{"plain", errors.New("validation failed"), false},
	}
	for _, c := range cases {
		if got := IsTransient(c.err); got != c.want {
			t.Errorf("%s: IsTransient = %v, want %v", c.name, got, c.want)
		}
	}
}
