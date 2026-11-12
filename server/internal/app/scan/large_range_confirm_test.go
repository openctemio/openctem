package scan

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// A range wider than a /16 is saved only when the request confirms it; the
// refusal carries the address and chunk counts. A /16 needs nothing.
func TestRequireLargeRangeConfirmed(t *testing.T) {
	err := requireLargeRangeConfirmed([]string{"192.0.2.10", "10.0.0.0/8", "172.16.0.0/12"}, false)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != CodeLargeRangeUnconfirmed {
		t.Fatalf("err = %v", err)
	}
	want := "10.0.0.0/8, 172.16.0.0/12: 17,825,792 addresses, dispatched as up to 272 /16 chunks and scanned live hosts first. Confirm the size with confirm_large_range: true."
	if de.Message != want {
		t.Fatalf("message = %q", de.Message)
	}
	if d, ok := de.Details.(LargeRangeDetails); !ok || d.Addresses != 17825792 || d.Chunks != 272 || len(d.Ranges) != 2 {
		t.Fatalf("details = %+v", de.Details)
	}
	if err := requireLargeRangeConfirmed([]string{"10.0.0.0/8"}, true); err != nil {
		t.Fatalf("confirmed: %v", err)
	}
	if err := requireLargeRangeConfirmed([]string{"10.0.0.0/16", "2001:db8::/112", "example.com"}, false); err != nil {
		t.Fatalf("a /16 needs no confirmation: %v", err)
	}
}
