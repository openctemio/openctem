package exploration

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/exploration"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func cand(typ asset.AssetType) exploration.Candidate {
	id := shared.NewID()
	return exploration.Candidate{AssetID: id, Type: typ, Evidence: []exploration.Link{{EndKind: exploration.EndAsset, EndID: &id}}}
}

func TestRules_OpenEachTypeWithItsCatalogAction(t *testing.T) {
	tenant := shared.NewID()
	repo, aud := newMemRepo(), &memAudit{}
	tr := &fakeTriggers{
		dangling: map[shared.ID][]exploration.Candidate{tenant: {cand(asset.AssetTypeSubdomain)}},
		versions: map[shared.ID][]exploration.Candidate{tenant: {cand(asset.AssetTypeHost)}},
		gone: map[shared.ID][]exploration.Candidate{tenant: {
			cand(asset.AssetTypeSubdomain), cand(asset.AssetTypeIPAddress), cand(asset.AssetTypeRepository),
		}},
	}
	r := NewRules(repo, tr, fixedSwitch{on: true}, aud, logger.NewNop())
	n, err := r.RunTenant(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	// The repository has no liveness step: four leads, not five.
	if n != 4 {
		t.Fatalf("opened %d, want 4", n)
	}
	got := map[string]string{}
	for _, l := range repo.leadsOf(tenant) {
		got[l.Type+"/"+l.Action.Capability] = string(l.State)
		if l.Origin != exploration.OriginRule || l.OriginRef != l.Type+"@1" {
			t.Errorf("origin %s %s", l.Origin, l.OriginRef)
		}
	}
	want := map[string]string{
		"dns.takeover_check/check.takeover":       "open",
		"version.confirm/probe.http":              "open",
		"asset.gone_with_findings/resolve.dns":    "open",
		"asset.gone_with_findings/discover.hosts": "open",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	// Every opened lead is audited with the rule as the actor.
	if len(aud.events) != 4 || aud.events[0].Action != audit.ActionExplorationLeadOpened || aud.ctxs[0].ActorEmail == "" {
		t.Fatalf("audit = %d events", len(aud.events))
	}
	// A second pass opens nothing new (live dedup key).
	if n, _ := r.RunTenant(context.Background(), tenant); n != 0 {
		t.Fatalf("second pass opened %d", n)
	}
}

// With automatic coverage off, or unreadable, an active (T1) lead waits for
// a person; a passive (T0) one still opens.
func TestRules_ActiveLeadsWaitWhenAutoCoverageIsOff(t *testing.T) {
	for name, sw := range map[string]fixedSwitch{"off": {on: false}, "unreadable": {on: true, err: errors.New("db down")}} {
		tenant := shared.NewID()
		repo := newMemRepo()
		tr := &fakeTriggers{
			dangling: map[shared.ID][]exploration.Candidate{tenant: {cand(asset.AssetTypeSubdomain)}},
			gone:     map[shared.ID][]exploration.Candidate{tenant: {cand(asset.AssetTypeDomain)}},
		}
		if _, err := NewRules(repo, tr, sw, nil, logger.NewNop()).RunTenant(context.Background(), tenant); err != nil {
			t.Fatal(err)
		}
		for _, l := range repo.leadsOf(tenant) {
			want := exploration.StateAwaitingApproval
			if l.Action.Capability == "resolve.dns" {
				want = exploration.StateOpen
			}
			if l.State != want {
				t.Errorf("%s: %s is %s, want %s", name, l.Action.Capability, l.State, want)
			}
		}
	}
}

// A tenant's candidates open leads only in that tenant.
func TestRules_TenantBound(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	repo := newMemRepo()
	tr := &fakeTriggers{dangling: map[shared.ID][]exploration.Candidate{a: {cand(asset.AssetTypeSubdomain)}}}
	r := NewRules(repo, tr, fixedSwitch{on: true}, nil, logger.NewNop())
	if n, _ := r.RunTenant(context.Background(), b); n != 0 {
		t.Fatalf("tenant b opened %d from tenant a's triggers", n)
	}
	if n, _ := r.RunTenant(context.Background(), a); n != 1 || len(repo.leadsOf(b)) != 0 {
		t.Fatal("leads leaked across tenants")
	}
}

// At most MaxLiveLeadsPerSubject live leads per asset, and the
// exploration's open-lead cap stops a pass.
func TestRules_Caps(t *testing.T) {
	tenant := shared.NewID()
	repo := newMemRepo()
	c := cand(asset.AssetTypeSubdomain)
	ex, _ := repo.EnsureContinuous(context.Background(), tenant)
	for i := 0; i < MaxLiveLeadsPerSubject; i++ {
		l, _ := exploration.NewLead(exploration.NewLeadInput{TenantID: tenant, ExplorationID: ex, Type: "version.confirm",
			Action: exploration.Action{Capability: "probe.http"}, SubjectAssetID: &c.AssetID,
			ReasonCode: "kev_on_unconfirmed_version", Origin: exploration.OriginUser, OriginRef: "user:x", AutoActive: true})
		l.DedupKey += string(rune('a' + i))
		_, _ = repo.OpenLead(context.Background(), l, nil)
	}
	tr := &fakeTriggers{dangling: map[shared.ID][]exploration.Candidate{tenant: {c}}}
	r := NewRules(repo, tr, fixedSwitch{on: true}, nil, logger.NewNop())
	if n, _ := r.RunTenant(context.Background(), tenant); n != 0 {
		t.Fatalf("a subject at its cap got %d more leads", n)
	}
}
