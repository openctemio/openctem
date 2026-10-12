package sensor

import (
	"testing"
	"time"
)

func TestKeyUseDebouncer(t *testing.T) {
	var d keyUseDebouncer
	t0 := time.Unix(1_700_000_000, 0)
	if !d.due("s1|10.0.0.1", t0) {
		t.Fatal("first use must be recorded")
	}
	if d.due("s1|10.0.0.1", t0.Add(time.Second)) {
		t.Fatal("a repeat within the interval must not be recorded")
	}
	if !d.due("s1|10.0.0.2", t0.Add(time.Second)) {
		t.Fatal("a new address must always be recorded (IP-change events)")
	}
	if !d.due("s1|10.0.0.1", t0.Add(keyUseInterval)) {
		t.Fatal("a use after the interval must be recorded")
	}
	// The table stays bounded.
	for i := range maxKeyUseEntries + 10 {
		d.due(time.Duration(i).String(), t0.Add(keyUseInterval))
	}
	if len(d.last) > maxKeyUseEntries {
		t.Fatalf("%d entries, want at most %d", len(d.last), maxKeyUseEntries)
	}
}
