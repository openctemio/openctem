package vulnmatch

import (
	"context"
	"sort"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Locations of matcher findings (docs/architecture/vulnerability-matching.md,
// "Locations"; softwarematch/locations.go). One finding per host, product,
// version and CVE: the services of one host that run the same version are
// locations of one finding, on the oldest of them, when every user sees
// those services alike. A location keeps the finding it joined while its
// version changes; a service that runs another version gets its own finding.

// locIndex is the tenant's locations for one pass and the writes the pass
// makes to them.
type locIndex struct {
	store     softwarematch.LocationStore
	byKey     map[string]softwarematch.Location
	byFinding map[shared.ID][]softwarematch.Location
	// seen: findings a location was sighted on in this pass.
	seen   map[shared.ID]bool
	writes []softwarematch.LocationWrite
}

// loadLocations reads the tenant's locations. Without a location store the
// index is empty and the matcher keeps one finding per service.
func (s *Service) loadLocations(ctx context.Context, tenantID shared.ID) (*locIndex, error) {
	ix := &locIndex{byKey: map[string]softwarematch.Location{}, byFinding: map[shared.ID][]softwarematch.Location{},
		seen: map[shared.ID]bool{}}
	ls, ok := s.store.(softwarematch.LocationStore)
	if !ok {
		return ix, nil
	}
	ix.store = ls
	rows, err := ls.TenantLocations(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, l := range rows {
		ix.byKey[l.Key] = l
		ix.byFinding[l.FindingID] = append(ix.byFinding[l.FindingID], l)
	}
	return ix, nil
}

// enabled reports whether locations are kept for c.
func (ix *locIndex) enabled(c *candidate) bool {
	return ix.store != nil && softwarematch.Locatable(c.m)
}

// lookup returns the location stored under any form of key.
func (ix *locIndex) lookup(key vulnerability.IdentityKey) (softwarematch.Location, bool) {
	for _, form := range key.KeyForms() {
		if l, ok := ix.byKey[form]; ok {
			return l, true
		}
	}
	return softwarematch.Location{}, false
}

// sight records that c is observed on finding f.
func (ix *locIndex) sight(c *candidate, findingID shared.ID, quiet bool) {
	ix.seen[findingID] = true
	ix.writes = append(ix.writes, softwarematch.LocationWrite{
		FindingID: findingID, AssetID: c.m.AssetID, Key: c.key.Fingerprint(), Port: c.m.Port, Transport: c.m.Transport,
		ProductID: c.m.ProductID, VersionID: c.m.VersionID, Version: c.m.Version, LinkLocation: c.m.Location,
		Evidence: c.m.Evidence, Seen: true, Label: softwarematch.LocationLabel(c.m.AssetName, c.m.Port, c.m.Transport),
		Quiet: quiet,
	})
}

// move records a state move of a stored location.
func (ix *locIndex) move(l softwarematch.Location, to softwarematch.LocationState, reason string) {
	ix.writes = append(ix.writes, softwarematch.LocationWrite{
		FindingID: l.FindingID, AssetID: l.AssetID, Key: l.Key, Version: l.Version, State: to, From: l.State,
		Reason: reason, Label: softwarematch.LocationLabel(l.AssetName, l.Port, l.Transport),
	})
}

// flush stores the pending writes.
func (ix *locIndex) flush(ctx context.Context, tenantID shared.ID, st *Stats) error {
	if ix.store == nil || len(ix.writes) == 0 {
		return nil
	}
	n, err := ix.store.WriteLocations(ctx, tenantID, ix.writes)
	ix.writes = nil
	if err != nil {
		return err
	}
	st.Locations += n
	return nil
}

// matchedFinding reports whether any location of f matches in this pass.
func (ix *locIndex) matchedFinding(f softwarematch.MatcherFinding, matched map[string]bool) bool {
	if matched[f.Fingerprint] || ix.seen[f.ID] {
		return true
	}
	for _, l := range ix.byFinding[f.ID] {
		if matched[l.Key] {
			return true
		}
	}
	return false
}

// resolve finds the matcher finding a desired candidate belongs to: the one
// keyed on it, or the one holding it as a location. skip is true when a
// finding the matcher does not own (or a duplicate) holds the location:
// nothing is created or changed for it.
func (ix *locIndex) resolve(fp string, c *candidate, byFP map[string]softwarematch.MatcherFinding,
	byID map[shared.ID]softwarematch.MatcherFinding,
) (f softwarematch.MatcherFinding, found, skip bool) {
	if f, ok := byFP[fp]; ok {
		return f, true, false
	}
	if l, ok := ix.lookup(c.key); ok {
		if f, ok := byID[l.FindingID]; ok && f.Status != string(vulnerability.FindingStatusDuplicate) {
			return f, true, false
		}
		return softwarematch.MatcherFinding{}, false, true
	}
	return softwarematch.MatcherFinding{}, false, false
}

// hostTarget is an open matcher finding a new service of its host can join.
type hostTarget struct {
	finding softwarematch.MatcherFinding
	assetID shared.ID // the finding's own asset, for its scope signature
}

// hostTargets lists, per host key, the open matcher findings that hold a
// location of that host, product and version: from the locations stored and
// from this pass's candidates resolved to a finding.
func (ix *locIndex) hostTargets(byID map[shared.ID]softwarematch.MatcherFinding, resolved map[string]softwarematch.MatcherFinding,
	desired map[string]*candidate,
) map[string][]hostTarget {
	out := map[string][]hostTarget{}
	seen := map[string]bool{}
	add := func(hk string, f softwarematch.MatcherFinding) {
		if !isOpen(f.Status) || seen[hk+"|"+f.ID.String()] {
			return
		}
		seen[hk+"|"+f.ID.String()] = true
		out[hk] = append(out[hk], hostTarget{finding: f, assetID: f.AssetID})
	}
	for fid, locs := range ix.byFinding {
		f, ok := byID[fid]
		if !ok {
			continue
		}
		for _, l := range locs {
			if l.ProductID == nil || l.VersionID == nil {
				continue
			}
			host := softwarematch.ServiceHost(l.AssetName)
			if host == "" {
				continue
			}
			add(softwarematch.HostKey(softwarematch.Match{AssetName: l.AssetName, ProductID: *l.ProductID, VersionID: *l.VersionID,
				Result: softwarematch.VersionVuln{CVEID: f.CVEID}}), f)
		}
	}
	for fp, f := range resolved {
		if c, ok := desired[fp]; ok && softwarematch.Locatable(c.m) {
			add(softwarematch.HostKey(c.m), f)
		}
	}
	return out
}

// pickTarget is the oldest target whose asset has signature sig.
func pickTarget(targets []hostTarget, sigs map[shared.ID]string, sig string) (softwarematch.MatcherFinding, bool) {
	var best *hostTarget
	for i := range targets {
		t := &targets[i]
		s, ok := sigs[t.assetID]
		if !ok || s != sig {
			continue
		}
		if best == nil || t.finding.CreatedAt.Before(best.finding.CreatedAt) ||
			(t.finding.CreatedAt.Equal(best.finding.CreatedAt) && t.finding.ID.String() < best.finding.ID.String()) {
			best = t
		}
	}
	if best == nil {
		return softwarematch.MatcherFinding{}, false
	}
	return best.finding, true
}

// hostGroup is the new candidates of one host key and scope signature: one
// finding, on the oldest asset, with the others as its locations.
type hostGroup struct {
	key     string
	members []*candidate
}

// groupNew splits the candidates to create into those that join an open
// finding of their host (returned as joins, finding id per candidate), the
// groups that get one new finding each, and the rest (no locations: one
// finding each, as before). A candidate whose asset has no scope signature
// (it is gone) is never grouped.
func groupNew(cands []*candidate, ix *locIndex, sigs map[shared.ID]string, targets map[string][]hostTarget,
) (joins map[*candidate]shared.ID, groups []hostGroup, plain []*candidate) {
	joins = map[*candidate]shared.ID{}
	byKey := map[string]*hostGroup{}
	var order []string
	for _, c := range cands {
		sig, ok := sigs[c.m.AssetID]
		if !ix.enabled(c) || !ok {
			plain = append(plain, c)
			continue
		}
		hk := softwarematch.HostKey(c.m)
		if f, ok := pickTarget(targets[hk], sigs, sig); ok {
			joins[c] = f.ID
			continue
		}
		k := hk + "|" + sig
		g, ok := byKey[k]
		if !ok {
			g = &hostGroup{key: k}
			byKey[k] = g
			order = append(order, k)
		}
		g.members = append(g.members, c)
	}
	sort.Strings(order)
	for _, k := range order {
		g := byKey[k]
		sort.SliceStable(g.members, func(a, b int) bool {
			ma, mb := g.members[a].m, g.members[b].m
			if !ma.AssetCreatedAt.Equal(mb.AssetCreatedAt) {
				return ma.AssetCreatedAt.Before(mb.AssetCreatedAt)
			}
			return ma.AssetID.String() < mb.AssetID.String()
		})
		groups = append(groups, *g)
	}
	return joins, groups, plain
}
