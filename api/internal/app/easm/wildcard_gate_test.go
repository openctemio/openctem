package easm

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// wildcardMarks is one tenant's wildcard-only marks; any other tenant reads
// none.
type wildcardMarks struct {
	tenant shared.ID
	marked map[shared.ID]bool
	err    error
}

func (w *wildcardMarks) WildcardOnly(_ context.Context, t shared.ID, ids []shared.ID) (map[shared.ID]bool, error) {
	if w.err != nil {
		return nil, w.err
	}
	out := map[shared.ID]bool{}
	if !t.Equals(w.tenant) {
		return out, nil
	}
	for _, id := range ids {
		if w.marked[id] {
			out[id] = true
		}
	}
	return out, nil
}

func TestActiveGate_WildcardOnly(t *testing.T) {
	f := newGateFixture(t)
	g := NewActiveGate(f, f, f, f)
	marks := &wildcardMarks{tenant: f.tenant, marked: map[shared.ID]bool{}}
	g.SetWildcardDNS(marks)

	// Covered by *.scoped.com and confirmed by the scope join: before this
	// check such a name was probed.
	guess := f.add(t, "guess.scoped.com", asset.AssetTypeSubdomain)
	f.record(guess, attribution.StateConfirmed, false)
	marks.marked[guess.ID()] = true
	unrecorded := f.add(t, "other.scoped.com", asset.AssetTypeSubdomain)
	marks.marked[unrecorded.ID()] = true
	svc := f.add(t, "guess.scoped.com:443:tcp", asset.AssetTypeService)
	byPerson := f.add(t, "kept.scoped.com", asset.AssetTypeSubdomain)
	f.record(byPerson, attribution.StateConfirmed, true)
	marks.marked[byPerson.ID()] = true
	clean := f.add(t, "api.scoped.com", asset.AssetTypeSubdomain)

	ctx := context.Background()
	got, err := g.ActiveCheckBlocked(ctx, f.tenant, []string{
		guess.ID().String(), unrecorded.ID().String(), svc.ID().String(), byPerson.ID().String(), clean.ID().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string]*asset.Asset{"automatic confirmed": guess, "unrecorded": unrecorded, "service on the host": svc} {
		if got[a.ID().String()] != attribution.StateWildcardOnly {
			t.Errorf("%s: %q, want wildcard_only", name, got[a.ID().String()])
		}
	}
	if s, no := got[byPerson.ID().String()]; no {
		t.Errorf("confirmed by a person: refused %s", s)
	}
	if s, no := got[clean.ID().String()]; no {
		t.Errorf("resolving name: refused %s", s)
	}

	typed, err := g.BlockedTargets(ctx, f.tenant, []string{"guess.scoped.com", "https://guess.scoped.com/x"})
	if err != nil {
		t.Fatal(err)
	}
	if typed["guess.scoped.com"] != attribution.StateWildcardOnly || typed["https://guess.scoped.com/x"] != attribution.StateWildcardOnly {
		t.Errorf("typed targets: %v", typed)
	}

	// A mark held by another tenant never refuses this tenant's asset.
	other := &wildcardMarks{tenant: shared.NewID(), marked: map[shared.ID]bool{clean.ID(): true}}
	g.SetWildcardDNS(other)
	if got, err := g.ActiveCheckBlocked(ctx, f.tenant, []string{clean.ID().String()}); err != nil || len(got) != 0 {
		t.Errorf("another tenant's mark refused: %v %v", got, err)
	}

	// A failed read refuses everything (fail closed).
	g.SetWildcardDNS(&wildcardMarks{err: errors.New("db down")})
	if _, err := g.ActiveCheckBlocked(ctx, f.tenant, []string{clean.ID().String()}); err == nil {
		t.Error("a failed mark read must refuse")
	}
}

// A registrable domain never resolves through a wildcard of its own zone
// (RFC 4592): a mark on one (a filtered resolver left out an apex that shares
// its address with its wildcard) does not refuse it, nor a service on it.
func TestActiveGate_WildcardOnly_ApexMarkIgnored(t *testing.T) {
	f := newGateFixture(t)
	g := NewActiveGate(f, f, f, f)
	marks := &wildcardMarks{tenant: f.tenant, marked: map[shared.ID]bool{}}
	g.SetWildcardDNS(marks)

	apex := f.add(t, "scoped.com", asset.AssetTypeDomain)
	f.record(apex, attribution.StateConfirmed, false)
	marks.marked[apex.ID()] = true
	svc := f.add(t, "scoped.com:443:tcp", asset.AssetTypeService)
	sub := f.add(t, "mb2.scoped.com", asset.AssetTypeSubdomain)
	f.record(sub, attribution.StateConfirmed, false)
	marks.marked[sub.ID()] = true

	got, err := g.ActiveCheckBlocked(context.Background(), f.tenant, []string{apex.ID().String(), svc.ID().String(), sub.ID().String()})
	if err != nil {
		t.Fatal(err)
	}
	if s, no := got[apex.ID().String()]; no {
		t.Errorf("apex with a stale wildcard mark: refused %s", s)
	}
	if s, no := got[svc.ID().String()]; no {
		t.Errorf("service on the apex: refused %s", s)
	}
	if got[sub.ID().String()] != attribution.StateWildcardOnly {
		t.Errorf("marked subdomain: %q, want wildcard_only", got[sub.ID().String()])
	}
}
