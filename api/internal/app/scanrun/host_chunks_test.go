package scanrun

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/openctemio/ctis/politeness"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// chunksConflict reports the first pair of chunks whose host keys conflict
// (what the claim's host-free predicate would hold one back for).
func chunksConflict(chunks []*scanapp.StepTargets) (int, int, string, bool) {
	for a := range chunks {
		ca := politeness.Conflicts(politeness.Keys(chunks[a].Targets, ""))
		for b := a + 1; b < len(chunks); b++ {
			for _, k := range politeness.Keys(chunks[b].Targets, "") {
				if slices.Contains(ca, k) {
					return a, b, k, true
				}
			}
		}
	}
	return 0, 0, "", false
}

func allTargets(chunks []*scanapp.StepTargets) []string {
	var out []string
	for _, c := range chunks {
		out = append(out, c.Targets...)
	}
	slices.Sort(out)
	return out
}

// The live shape (2026-10-14): a nuclei step whose targets name some hosts
// twice, bare and as address:port, far apart in the list. Cut by position
// the two forms landed in different chunks, and one chunk waited for its
// sibling. Cut by host, no two chunks of the step conflict, every target is
// in exactly one chunk, and the chunks stay balanced.
func TestStepChunks_NoIntraStepConflict(t *testing.T) {
	var targets []string
	for i := 1; i <= 80; i++ {
		targets = append(targets, fmt.Sprintf("203.0.113.%d", i))
	}
	for i := 1; i <= 80; i += 7 {
		targets = append(targets, fmt.Sprintf("203.0.113.%d:8443", i), fmt.Sprintf("http://203.0.113.%d:8080/", i))
	}
	for i := 0; i < 12; i++ {
		targets = append(targets, fmt.Sprintf("app%d.example.com", i), fmt.Sprintf("https://app%d.example.com/", i))
	}
	// Positional cut (as before) conflicts.
	var positional []*scanapp.StepTargets
	for i := 0; i < len(targets); i += 25 {
		positional = append(positional, &scanapp.StepTargets{Targets: targets[i:min(i+25, len(targets))]})
	}
	if _, _, _, ok := chunksConflict(positional); !ok {
		t.Fatal("the fixture should conflict when cut by position")
	}

	chunks := stepChunks(stepTool(t, "nuclei"), &scanapp.StepTargets{Targets: targets}, nil)
	if a, b, k, ok := chunksConflict(chunks); ok {
		t.Fatalf("chunks %d and %d of one step both hold %s", a, b, k)
	}
	want := slices.Clone(targets)
	slices.Sort(want)
	if !slices.Equal(allTargets(chunks), want) {
		t.Fatal("chunks lost or duplicated targets")
	}
	sizes := chunkSizes(chunks)
	// 128 targets: as many chunks as size 25 needs (6), evenly filled.
	if len(chunks) != 6 || slices.Max(sizes) > 25 || slices.Max(sizes)-slices.Min(sizes) > 3 {
		t.Fatalf("chunk sizes = %v, want 6 balanced chunks of at most 25", sizes)
	}
}

// A name and the address it resolves to are one host when the inventory
// says so: they go into one chunk.
func TestStepChunks_ResolutionKeepsANameWithItsAddress(t *testing.T) {
	var targets []string
	for i := 1; i <= 30; i++ {
		targets = append(targets, fmt.Sprintf("198.51.100.%d", i))
	}
	targets = append(targets, "www.example.com", "https://api.example.com/")
	aliases := map[string][]string{
		"www.example.com": {"198.51.100.2"},
		"api.example.com": {"198.51.100.29", "not-an-address"},
	}
	chunks := stepChunks(stepTool(t, "nuclei"), &scanapp.StepTargets{Targets: targets}, aliases)
	chunkOf := func(target string) int {
		for i, c := range chunks {
			if slices.Contains(c.Targets, target) {
				return i
			}
		}
		t.Fatalf("%s in no chunk", target)
		return -1
	}
	if len(chunks) < 2 {
		t.Fatalf("chunks = %d", len(chunks))
	}
	if chunkOf("www.example.com") != chunkOf("198.51.100.2") || chunkOf("https://api.example.com/") != chunkOf("198.51.100.29") {
		t.Fatalf("a name and its address were split: %v", chunks)
	}
}

// A host with more targets than a chunk holds is cut into chunks of its
// own (they hold the same host and run one after the other); the other
// hosts are not mixed into them.
func TestStepChunks_OversizeHost(t *testing.T) {
	var targets []string
	for i := 0; i < 30; i++ {
		targets = append(targets, fmt.Sprintf("https://big.example.com/p%d", i))
	}
	targets = append(targets, "small.example.com")
	chunks := stepChunks(stepTool(t, "nuclei"), &scanapp.StepTargets{Targets: targets}, nil)
	if got := chunkSizes(chunks); !slices.Equal(got, []int{25, 5, 1}) {
		t.Fatalf("chunk sizes = %v, want [25 5 1]", got)
	}
}

type fakeNameAddresses struct {
	got []string
	out map[string][]string
	err error
}

func (f *fakeNameAddresses) AddressesOf(_ context.Context, _ shared.ID, names []string) (map[string][]string, error) {
	f.got = names
	return f.out, f.err
}

// The resolution relations are read only for a step that is cut, for its
// names (never addresses or ranges), and a failed read falls back to keys.
func TestHostAliases(t *testing.T) {
	f := &fakeNameAddresses{out: map[string][]string{"a.example.com": {"203.0.113.1"}}}
	s := &Service{nameAddresses: f, logger: logger.NewNop()}
	tenant := shared.NewID()
	small := &scanapp.StepTargets{Targets: []string{"a.example.com", "203.0.113.1"}}
	if got := s.hostAliases(context.Background(), tenant, stepTool(t, "nuclei"), small); got != nil || f.got != nil {
		t.Fatalf("a step of one chunk read relations: %v", f.got)
	}
	var targets []string
	for i := 0; i < 30; i++ {
		targets = append(targets, fmt.Sprintf("203.0.113.%d", i))
	}
	targets = append(targets, "https://A.example.com:8443/x", "a.example.com", "198.51.100.0/24")
	got := s.hostAliases(context.Background(), tenant, stepTool(t, "nuclei"), &scanapp.StepTargets{Targets: targets})
	if !slices.Equal(f.got, []string{"a.example.com"}) || len(got) != 1 {
		t.Fatalf("looked up %v, got %v", f.got, got)
	}
	f.err = errors.New("db down")
	if got := s.hostAliases(context.Background(), tenant, stepTool(t, "nuclei"), &scanapp.StepTargets{Targets: targets}); got != nil {
		t.Fatalf("a failed read: %v", got)
	}
}
