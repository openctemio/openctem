package scanrun

import (
	"fmt"
	"slices"
	"testing"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

func stepTool(t *testing.T, tool string) scanapp.StepTool {
	t.Helper()
	st, ok := testCat.ForStep(tool, nil)
	if !ok {
		t.Fatalf("no stage for %s", tool)
	}
	return scanapp.StepTool{Catalog: testCat, Name: tool, Stage: st, HasStage: true}
}

func slash24s(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("198.51.%d.0/24", i)
	}
	return out
}

func chunkSizes(chunks []*scanapp.StepTargets) []int {
	out := make([]int, len(chunks))
	for i, c := range chunks {
		out[i] = len(c.Targets)
	}
	return out
}

// A /16 cut into 256 /24 pieces used to be chunked by string count (50 per
// chunk, 12 800 addresses each). A port scan chunk now holds at most 1 024
// addresses: 64 chunks of 4 pieces that every eligible sensor shares.
func TestStepChunks_PortScanByAddressCount(t *testing.T) {
	chunks := stepChunks(stepTool(t, "naabu"), &scanapp.StepTargets{Targets: slash24s(256)})
	if len(chunks) != 64 {
		t.Fatalf("chunks = %d, want 64", len(chunks))
	}
	for i, c := range chunks {
		if len(c.Targets) != 4 {
			t.Fatalf("chunk %d has %d pieces, want 4", i, len(c.Targets))
		}
	}
	// Every piece is in exactly one chunk, in order.
	var all []string
	for _, c := range chunks {
		all = append(all, c.Targets...)
	}
	if !slices.Equal(all, slash24s(256)) {
		t.Fatal("chunks lost or reordered pieces")
	}
}

func TestStepChunks_MixedWeights(t *testing.T) {
	targets := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3",
		"198.51.0.0/24", "198.51.1.0/24", "198.51.2.0/24", "198.51.3.0/24", "app.example.com"}
	chunks := stepChunks(stepTool(t, "naabu"), &scanapp.StepTargets{Targets: targets, Refused: 2, Reason: "r"})
	// 3 + 768 = 771 addresses; the fourth /24 would make 1 027 > 1 024.
	if got := chunkSizes(chunks); !slices.Equal(got, []int{6, 2}) {
		t.Fatalf("chunk sizes = %v, want [6 2]", got)
	}
	if chunks[1].Refused != 2 || chunks[1].Reason != "r" {
		t.Fatalf("refusals not carried: %+v", chunks[1])
	}
	// A target heavier than the budget gets a chunk of its own.
	chunks = stepChunks(stepTool(t, "naabu"), &scanapp.StepTargets{Targets: []string{"203.0.113.1", "198.51.0.0/22", "203.0.113.2"}})
	if got := chunkSizes(chunks); !slices.Equal(got, []int{1, 1, 1}) {
		t.Fatalf("chunk sizes = %v, want [1 1 1]", got)
	}
	// Few small targets stay one chunk.
	if chunks := stepChunks(stepTool(t, "naabu"), &scanapp.StepTargets{Targets: []string{"198.51.0.0/24", "203.0.113.1"}}); len(chunks) != 1 {
		t.Fatalf("chunks = %d, want 1", len(chunks))
	}
}

// A passive stage sends no traffic to its targets: a range weighs 1 there,
// and stages without an address budget keep counting targets.
func TestStepChunks_NoBudgetCountsTargets(t *testing.T) {
	if got := chunkSizes(stepChunks(stepTool(t, "asn"), &scanapp.StepTargets{Targets: slash24s(256)})); len(got) != 1 {
		t.Fatalf("asn chunks = %v, want one chunk of 256", got)
	}
	targets := make([]string, 450)
	for i := range targets {
		targets[i] = fmt.Sprintf("h%d.example.com", i)
	}
	if got := chunkSizes(stepChunks(stepTool(t, "httpx"), &scanapp.StepTargets{Targets: targets})); !slices.Equal(got, []int{200, 200, 50}) {
		t.Fatalf("httpx chunk sizes = %v", got)
	}
}

// A range piece holds the range key of its bucket; an address holds itself
// and the marker of its bucket, so a range chunk and an address chunk inside
// it conflict while two addresses of one bucket do not.
func TestChunkHostKeys_RangesAndAddresses(t *testing.T) {
	ports, _ := stage.Lookup(stage.ScanPorts)
	rangeKeys := chunkHostKeys(ports, true, []string{"203.0.113.0/25"})
	if !slices.Equal(rangeKeys, []string{"net:203.0.113.0/24"}) {
		t.Fatalf("range keys = %v", rangeKeys)
	}
	addrKeys := chunkHostKeys(ports, true, []string{"203.0.113.7", "https://203.0.113.9:8443/x"})
	if !slices.Equal(addrKeys, []string{"203.0.113.7", "203.0.113.9", "in:203.0.113.0/24"}) {
		t.Fatalf("address keys = %v", addrKeys)
	}
	wide := chunkHostKeys(ports, true, []string{"198.51.0.0/22"})
	if !slices.Equal(wide, []string{"net:198.51.0.0/24", "net:198.51.1.0/24", "net:198.51.2.0/24", "net:198.51.3.0/24"}) {
		t.Fatalf("wide range keys = %v", wide)
	}
	v6 := chunkHostKeys(ports, true, []string{"2001:db8::/121", "2001:db8::1:5"})
	if !slices.Equal(v6, []string{"2001:db8::1:5", "in:2001:db8::1:0/120", "net:2001:db8::/120"}) {
		t.Fatalf("v6 keys = %v", v6)
	}

	conflict := func(a, b []string) bool {
		for _, k := range command.HostKeyConflicts(a) {
			if slices.Contains(b, k) {
				return true
			}
		}
		return false
	}
	other := chunkHostKeys(ports, true, []string{"203.0.113.200"})
	elsewhere := chunkHostKeys(ports, true, []string{"203.0.114.7"})
	for _, c := range []struct {
		name string
		a, b []string
		want bool
	}{
		{"range vs address inside", rangeKeys, addrKeys, true},
		{"address inside vs range", addrKeys, rangeKeys, true},
		{"two addresses of one bucket", addrKeys, other, false},
		{"range vs address elsewhere", rangeKeys, elsewhere, false},
		{"range vs same range", rangeKeys, rangeKeys, true},
		{"address vs same address", addrKeys, addrKeys, true},
	} {
		if got := conflict(c.a, c.b); got != c.want {
			t.Errorf("%s: conflict = %v, want %v", c.name, got, c.want)
		}
	}
}
