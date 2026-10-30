package command

import (
	"slices"
	"testing"
)

func TestSharedFleetHostLimitFor(t *testing.T) {
	cases := []struct {
		g    DispatchGate
		want int
	}{
		{DispatchGate{}, SharedFleetHostLimit},
		{DispatchGate{Tier: 1, Intensity: "active"}, SharedFleetHostLimit},
		{DispatchGate{Intensity: "intrusive"}, SharedFleetIntrusiveHostLimit},
		{DispatchGate{Tier: 2}, SharedFleetIntrusiveHostLimit},
	}
	for _, c := range cases {
		if got := SharedFleetHostLimitFor(c.g); got != c.want {
			t.Errorf("SharedFleetHostLimitFor(%+v) = %d, want %d", c.g, got, c.want)
		}
	}
}

func TestSharedFleetHostsAllowed(t *testing.T) {
	// One job of another organization already holds example.com.
	held := map[string]int{"example.com": 1}
	got := SharedFleetHostsAllowed(held, []SharedFleetJob{
		{ID: "a", Keys: []string{"example.com"}, Limit: 2},        // second holder: kept
		{ID: "b", Keys: []string{"example.com"}, Limit: 2},        // third: dropped
		{ID: "c", Keys: []string{"www.example.com"}, Limit: 2},    // other host: kept
		{ID: "d", Keys: nil, Limit: 2},                            // no host: kept
		{ID: "e", Keys: []string{"www.example.com"}, Limit: 1},    // intrusive, host held by c: dropped
		{ID: "f", Keys: []string{"in:203.0.113.0/24"}, Limit: 2},  // address in a bucket: kept
		{ID: "g", Keys: []string{"net:203.0.113.0/24"}, Limit: 1}, // range of that bucket, intrusive: dropped
	})
	if want := []string{"a", "c", "d", "f"}; !slices.Equal(got, want) {
		t.Fatalf("kept %v, want %v", got, want)
	}
	if held["example.com"] != 2 || held["www.example.com"] != 1 {
		t.Fatalf("held %v after the batch", held)
	}
}
