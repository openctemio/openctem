package command

import (
	"net/netip"
	"slices"
	"testing"
)

func TestHostKeyConflicts(t *testing.T) {
	got := HostKeyConflicts([]string{"a.example.com", "203.0.113.7", "in:203.0.113.0/24", "net:198.51.100.0/24"})
	want := []string{"203.0.113.7", "a.example.com", "in:198.51.100.0/24", "net:198.51.100.0/24", "net:203.0.113.0/24"}
	if !slices.Equal(got, want) {
		t.Fatalf("conflicts = %v, want %v", got, want)
	}
}

func TestHostKeyLockAndBucket(t *testing.T) {
	if HostKeyLock("in:203.0.113.0/24") != HostKeyLock("net:203.0.113.0/24") {
		t.Fatal("an address marker and a range key of one bucket must share a lock")
	}
	if HostKeyLock("a.example.com") != "a.example.com" {
		t.Fatal("a plain key locks itself")
	}
	if b := AddrBucket(netip.MustParseAddr("::ffff:203.0.113.7")); b.String() != "203.0.113.0/24" {
		t.Fatalf("bucket = %s", b)
	}
	if b := AddrBucket(netip.MustParseAddr("2001:db8::1:5")); b.String() != "2001:db8::1:0/120" {
		t.Fatalf("v6 bucket = %s", b)
	}
}
