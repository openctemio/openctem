package scope

import (
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestReplacementChange(t *testing.T) {
	cases := []struct {
		name             string
		typ              TargetType
		old, new         string
		widens, narrows  bool
		added, removed   []string
		addedN, removedN uint64
	}{
		{"moved range", TargetTypeCIDR, "192.0.2.0/24", "198.51.100.0/24", true, true,
			[]string{"198.51.100.0/24"}, []string{"192.0.2.0/24"}, 256, 256},
		{"narrowed range", TargetTypeCIDR, "192.0.2.0/24", "192.0.2.0/25", false, true,
			nil, []string{"192.0.2.128/25"}, 0, 128},
		{"widened range", TargetTypeIPRange, "192.0.2.10-192.0.2.20", "192.0.2.0/27", true, false,
			[]string{"192.0.2.0-192.0.2.9", "192.0.2.21-192.0.2.31"}, nil, 21, 0},
		{"single address", TargetTypeIPAddress, "192.0.2.1", "192.0.2.2", true, true,
			[]string{"192.0.2.2"}, []string{"192.0.2.1"}, 1, 1},
		{"name to its wildcard parent widens", TargetTypeDomain, "app.example.com", "*.example.com", true, false,
			[]string{"*.example.com"}, nil, 0, 0},
		{"wildcard to a name under it narrows", TargetTypeDomain, "*.example.com", "app.example.com", false, true,
			nil, []string{"*.example.com"}, 0, 0},
		{"wildcard does not cover its apex", TargetTypeDomain, "*.example.com", "example.com", true, true,
			[]string{"example.com"}, []string{"*.example.com"}, 0, 0},
		{"another name", TargetTypeDomain, "app.example.com", "api.example.com", true, true,
			[]string{"api.example.com"}, []string{"app.example.com"}, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ReplacementChange(c.typ, c.old, c.new)
			if got.Widens != c.widens || got.Narrows != c.narrows ||
				!slices.Equal(got.Added, c.added) || !slices.Equal(got.Removed, c.removed) ||
				got.AddedAddresses != c.addedN || got.RemovedAddresses != c.removedN {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestSupersede(t *testing.T) {
	now := time.Now()
	old, err := NewEntry(shared.NewID(), TargetTypeCIDR, "192.0.2.0/24", "", "", EntryOptions{Now: now})
	if err != nil || !old.InEffect(now) {
		t.Fatal(err)
	}
	next := shared.NewID()
	old.Supersede(next, now)
	if old.InEffect(now) || !old.IsSuperseded() || old.SupersededBy() == nil || *old.SupersededBy() != next || !old.Status().IsValid() {
		t.Fatalf("superseded entry: %s %v", old.Status(), old.SupersededBy())
	}
}
