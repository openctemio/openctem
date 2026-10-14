package command

import (
	"slices"
	"testing"

	"github.com/openctemio/ctis/politeness"
)

func TestPartitionHeld(t *testing.T) {
	targets := []string{"203.0.113.1", "203.0.113.2", "203.0.113.2:8443", "www.example.com", "https://www.example.com/x", "198.51.100.7"}
	keys := politeness.Keys(targets, "")
	cases := []struct {
		name    string
		held    []string
		blocked []string
	}{
		{"an address blocks its address:port forms", []string{"203.0.113.2"}, []string{"203.0.113.2", "203.0.113.2:8443"}},
		{"a name blocks its URLs", []string{"www.example.com"}, []string{"www.example.com", "https://www.example.com/x"}},
		{"a range holder blocks every address of its bucket", []string{"net:203.0.113.0/24"},
			[]string{"203.0.113.1", "203.0.113.2", "203.0.113.2:8443"}},
		{"a bucket marker alone blocks nothing", []string{"in:203.0.113.0/24"}, nil},
		{"nothing held", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, ok := PartitionHeld(targets, "", keys, c.held)
			if !ok {
				t.Fatal("not partitioned")
			}
			if !slices.Equal(p.Blocked, c.blocked) || len(p.Free)+len(p.Blocked) != len(targets) {
				t.Fatalf("blocked %q free %q", p.Blocked, p.Free)
			}
			// Each part holds exactly its targets' keys, within the command's.
			if !slices.Equal(p.FreeKeys, followUpHostKeys(keys, p.Free, "")) ||
				!slices.Equal(p.BlockedKeys, followUpHostKeys(keys, p.Blocked, "")) {
				t.Fatalf("keys %v / %v", p.FreeKeys, p.BlockedKeys)
			}
			for _, k := range p.FreeKeys {
				for _, h := range c.held {
					if slices.Contains(HostKeyConflicts([]string{k}), h) {
						t.Fatalf("the free part holds %s, which conflicts with held %s", k, h)
					}
				}
			}
		})
	}
}

// A range target held back by an address holder in its bucket.
func TestPartitionHeld_RangeTarget(t *testing.T) {
	targets := []string{"10.0.0.0/24", "10.0.1.0/24"}
	keys := politeness.Keys(targets, "")
	p, ok := PartitionHeld(targets, "", keys, []string{"in:10.0.1.0/24"})
	if !ok || !slices.Equal(p.Blocked, []string{"10.0.1.0/24"}) || !slices.Equal(p.FreeKeys, []string{"net:10.0.0.0/24"}) {
		t.Fatalf("%+v %v", p, ok)
	}
}

// Keys computed in the payload's network are attributed too.
func TestPartitionHeld_Network(t *testing.T) {
	targets := []string{"10.0.0.5", "intranet.local"}
	keys := politeness.Keys(targets, "site-a")
	p, ok := PartitionHeld(targets, "site-a", keys, []string{"10.0.0.5#site-a"})
	if !ok || !slices.Equal(p.Blocked, []string{"10.0.0.5"}) || !slices.Equal(p.FreeKeys, []string{"intranet.local#site-a"}) {
		t.Fatalf("%+v %v", p, ok)
	}
}

// A key no target produces cannot be attributed: never split.
func TestPartitionHeld_UnattributedKey(t *testing.T) {
	targets := []string{"a.example.com", "b.example.com"}
	if _, ok := PartitionHeld(targets, "", []string{"a.example.com", "b.example.com", "c.example.com"}, []string{"a.example.com"}); ok {
		t.Fatal("split a command with a key no target produces")
	}
}

func TestHostPartition_Splittable(t *testing.T) {
	cases := []struct {
		free, blocked int
		want          bool
	}{
		{21, 2, true}, {1, 1, true}, {2, 3, false}, {0, 4, false}, {4, 0, false},
	}
	for _, c := range cases {
		p := HostPartition{Free: make([]string, c.free), Blocked: make([]string, c.blocked)}
		if got := p.Splittable(); got != c.want {
			t.Fatalf("free %d blocked %d: %v", c.free, c.blocked, got)
		}
	}
}
