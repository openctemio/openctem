package scanrun

// Host-affine chunks (research/130 follow-up, live 2026-10-14): when a step
// is cut into chunks, every target of one host goes into one chunk. Two
// chunks of a step therefore never hold the same host, and one never waits
// for its own sibling (live: a nuclei chunk of 23 targets waited behind a
// sibling holding one address its own "address:port" target shared, while a
// sensor slot sat free). One host is what github.com/openctemio/ctis/politeness
// says it is (politeness.GroupKeys): a name and its URLs and services; an
// address and its "address:port" forms; a range and the addresses of its
// buckets. A name also joins the addresses the inventory says it resolves
// to (resolves_to), when the step has them.

import (
	"context"
	"math"
	"net/netip"
	"slices"

	"github.com/openctemio/ctis/politeness"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// NameAddressReader maps names (lower-case) to the addresses the tenant's
// asset of that name resolves to (*postgres.AttributionRepository).
type NameAddressReader interface {
	AddressesOf(ctx context.Context, tenantID shared.ID, names []string) (map[string][]string, error)
}

// WithNameAddresses wires the resolution relations host-affine chunking
// reads. Without it a name and its address are two hosts for chunking (as
// they are for host keys).
func WithNameAddresses(r NameAddressReader) Option {
	return func(s *Service) {
		s.nameAddresses = r
	}
}

// maxAliasNames bounds the names one step looks up: beyond it the step is
// chunked without resolution relations (still host-affine on its keys).
const maxAliasNames = 5000

// hostAliases is, for each name target of a step that is cut into several
// chunks, the addresses the inventory says it resolves to. Nil when there
// is no reader, nothing to cut, or the read fails (logged: chunks are then
// host-affine on keys alone, which is still correct).
func (s *Service) hostAliases(ctx context.Context, tenantID shared.ID, resolved scanapp.StepTool, st *scanapp.StepTargets) map[string][]string {
	if s.nameAddresses == nil || st == nil || !resolved.HasStage {
		return nil
	}
	size := resolved.Stage.ChunkSizeFor(resolved.Name)
	if size <= 0 || len(st.Targets) <= size {
		return nil
	}
	seen := map[string]bool{}
	names := make([]string, 0, len(st.Targets))
	for _, t := range st.Targets {
		h := politeness.HostOf(t)
		if h == "" || seen[h] {
			continue
		}
		if _, err := netip.ParseAddr(h); err == nil {
			continue
		}
		if _, err := netip.ParsePrefix(h); err == nil {
			continue
		}
		seen[h] = true
		names = append(names, h)
	}
	if len(names) == 0 || len(names) > maxAliasNames {
		return nil
	}
	addrs, err := s.nameAddresses.AddressesOf(ctx, tenantID, names)
	if err != nil {
		s.logger.Warn("resolution relations could not be read; chunks follow host keys only",
			"tenant_id", tenantID.String(), "error", err)
		return nil
	}
	return addrs
}

// hostGroups is the step's targets grouped by host (politeness.GroupKeys):
// each target's own keys, plus for a name the address keys of what it
// resolves to (aliases, keyed by lower-case host).
func hostGroups(targets []string, aliases map[string][]string) [][]int {
	keys := make([][]string, len(targets))
	for i, t := range targets {
		keys[i] = politeness.TargetKeys(t, "")
		if len(aliases) == 0 {
			continue
		}
		for _, a := range aliases[politeness.HostOf(t)] {
			if addr, err := netip.ParseAddr(a); err == nil {
				keys[i] = append(keys[i], addr.Unmap().WithZone("").String())
			}
		}
	}
	return politeness.GroupKeys(keys)
}

// packChunks cuts a step's targets into chunks of whole hosts, in the
// order the hosts first appear. The number of chunks is what the chunk size
// and the address budget need, and each chunk is filled to an even share
// of the targets (and of the addresses, under a budget), so the chunks are
// balanced: 450 targets of size 200 are three chunks of 150. A host never
// spans two chunks, unless it alone is larger than a chunk (more targets
// than the size, or more addresses than the budget): it is then cut into
// chunks of its own, which hold the same host and run one after the other,
// as they would in one chunk. Targets keep their order inside a chunk.
func packChunks(st *scanapp.StepTargets, groups [][]int, weights []uint64, size, budget int) []*scanapp.StepTargets {
	groupWeight := func(g []int) uint64 {
		var w uint64
		for _, i := range g {
			w = addSat(w, weights[i])
		}
		return w
	}
	var count int
	var total uint64
	for _, g := range groups {
		count += len(g)
		total = addSat(total, groupWeight(g))
	}
	k := max(ceilDiv(u64(count), u64(size)), 1)
	if budget > 0 {
		k = max(k, ceilDiv(total, u64(budget)))
	}
	// The even share is recomputed over what is left after each chunk, so
	// a host that does not fit the share of one chunk does not leave the
	// step one chunk more than it needs.
	var parts [][]int
	var cur []int
	var curWeight uint64
	leftCount, leftWeight := u64(count), total
	share := func() (uint64, uint64) {
		n := max(k-min(u64(len(parts)), k), 1)
		return ceilDiv(leftCount, n), ceilDiv(leftWeight, n)
	}
	shareCount, shareWeight := share()
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, cur)
			leftCount -= u64(len(cur))
			leftWeight -= min(curWeight, leftWeight) // saturated sums
		}
		cur, curWeight = nil, 0
		shareCount, shareWeight = share()
	}
	for _, g := range groups {
		w := groupWeight(g)
		if len(g) > size || (budget > 0 && w > u64(budget)) {
			flush()
			for _, piece := range cutSequential(g, weights, size, budget) {
				cur = piece
				for _, i := range piece {
					curWeight = addSat(curWeight, weights[i])
				}
				flush()
			}
			continue
		}
		n := u64(len(cur) + len(g))
		over := n > shareCount || n > u64(size)
		if budget > 0 {
			over = over || addSat(curWeight, w) > shareWeight || addSat(curWeight, w) > u64(budget)
		}
		if len(cur) > 0 && over {
			flush()
		}
		cur = append(cur, g...)
		curWeight = addSat(curWeight, w)
	}
	flush()
	out := make([]*scanapp.StepTargets, len(parts))
	for p, idx := range parts {
		idx = slices.Clone(idx)
		slices.Sort(idx)
		ts := make([]string, len(idx))
		for j, i := range idx {
			ts[j] = st.Targets[i]
		}
		out[p] = &scanapp.StepTargets{Targets: ts, Refused: st.Refused, Reason: st.Reason}
	}
	return out
}

// cutSequential cuts the targets idx (in order) into pieces of at most size
// targets and budget addresses; a target heavier than the budget is a piece
// of its own.
func cutSequential(idx []int, weights []uint64, size, budget int) [][]int {
	var out [][]int
	start, sum := 0, uint64(0)
	for j, i := range idx {
		full := j-start >= size || (budget > 0 && j > start && addSat(sum, weights[i]) > u64(budget))
		if full {
			out = append(out, idx[start:j:j])
			start, sum = j, 0
		}
		sum = addSat(sum, weights[i])
	}
	return append(out, idx[start:len(idx):len(idx)])
}

func ceilDiv(a, b uint64) uint64 {
	if b == 0 {
		return math.MaxUint64
	}
	return a/b + min(a%b, 1)
}

// u64 is a non-negative int as uint64 (a negative one is 0).
func u64(n int) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}
