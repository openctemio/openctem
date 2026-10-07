package unit

// A seed authorizes active checks of every name under it, so adding one goes
// through the scope entry path (RFC-054 §6.1, research/53 S-1): approvers
// only, step-up, the organization's approval count, guardrails, an
// administrator notification. These tests use the real scope service, so a
// seed and a scope entry are refused or accepted by the same code.

import (
	"context"
	"errors"
	"testing"
	"time"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// legacySeeds is a seed store holding seeds made before seeds became scope
// entries; creating a seed row is a failure here (new seeds are entries).
type legacySeeds struct {
	byTenant map[shared.ID][]easmseed.Seed
}

func (l *legacySeeds) ListSeeds(_ context.Context, tid shared.ID) ([]easmseed.Seed, error) {
	return l.byTenant[tid], nil
}
func (l *legacySeeds) CountSeeds(_ context.Context, tid shared.ID) (int, error) {
	return len(l.byTenant[tid]), nil
}
func (l *legacySeeds) CreateSeed(context.Context, easmseed.Seed) error {
	return errors.New("a new seed must be a scope entry, not a seed row")
}
func (l *legacySeeds) UpdateSeed(_ context.Context, tid, id shared.ID, label string, d bool) (*easmseed.Seed, error) {
	for i := range l.byTenant[tid] {
		if l.byTenant[tid][i].ID == id {
			l.byTenant[tid][i].Label, l.byTenant[tid][i].DiscoveryEnabled = label, d
			s := l.byTenant[tid][i]
			return &s, nil
		}
	}
	return nil, shared.ErrNotFound
}
func (l *legacySeeds) DeleteSeed(context.Context, shared.ID, shared.ID) (*easmseed.Seed, error) {
	return nil, shared.ErrNotFound
}

func seedService(t *testing.T, admins int, st tenant.ScopeSettings) (*easmapp.SeedService, *scope.Service, *mockTargetRepo, *noticeLog, *legacySeeds) {
	t.Helper()
	svc, tr, notes := entryService(t, admins, st)
	store := &legacySeeds{byTenant: map[shared.ID][]easmseed.Seed{}}
	seeds := easmapp.NewSeedService(store, nil)
	seeds.SetEntries(svc)
	return seeds, svc, tr, notes, store
}

func addSeed(s *easmapp.SeedService, tenantID shared.ID, actor scope.Actor, value string) (*scopedom.Target, error) {
	return s.Create(context.Background(), tenantID, easmapp.CreateSeedInput{
		Kind: "root_domain", Value: value, Attested: true, Actor: actor,
	})
}

func TestSeedWidening_ApproverAloneIsAnActiveEntry(t *testing.T) {
	seeds, _, tr, notes, _ := seedService(t, 1, tenant.ScopeSettings{})
	tenantID := shared.NewID()
	got, err := addSeed(seeds, tenantID, approverA, "Acme.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if got.Pattern() != "*.acme.com" || got.TargetType() != scopedom.TargetTypeDomain ||
		!got.InEffect(time.Now()) || got.ExpiresAt() != nil || got.MaxTier() != scopedom.TierActive ||
		got.CreatedBy() != approverA.UserID || got.Reason() == "" {
		t.Fatalf("entry = %s %s %s exp=%v tier=%s by=%s reason=%q", got.Pattern(), got.TargetType(), got.Status(),
			got.ExpiresAt(), got.MaxTier(), got.CreatedBy(), got.Reason())
	}
	if active, _ := tr.ListActive(context.Background(), tenantID); len(active) != 1 {
		t.Fatalf("active entries = %d", len(active))
	}
	if len(notes.titles) == 0 {
		t.Fatal("a seed that took effect notified no administrator")
	}
}

// Two admins: the seed waits for the other one and authorizes nothing.
func TestSeedWidening_FollowsTheApprovalCount(t *testing.T) {
	seeds, svc, tr, notes, _ := seedService(t, 2, tenant.ScopeSettings{})
	tenantID := shared.NewID()
	got, err := addSeed(seeds, tenantID, approverA, "acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status() != scopedom.StatusPending || got.ApprovalsRequired() != 1 || got.InEffect(time.Now()) {
		t.Fatalf("status %s approvals %d", got.Status(), got.ApprovalsRequired())
	}
	if active, _ := tr.ListActive(context.Background(), tenantID); len(active) != 0 {
		t.Fatal("a pending seed authorizes probes")
	}
	if len(notes.titles) == 0 {
		t.Fatal("a pending seed notified nobody")
	}
	if _, _, err := svc.ApproveTarget(context.Background(), got.ID().String(), tenantID.String(), approverA); !errors.Is(err, scopedom.ErrEntrySelfApproval) {
		t.Fatalf("the requester approved their own seed: %v", err)
	}
	if _, eff, err := svc.ApproveTarget(context.Background(), got.ID().String(), tenantID.String(), approverB); err != nil || !eff {
		t.Fatalf("second admin: %v %v", eff, err)
	}

	// An explicit setting of 2 approvals applies to seeds as well.
	seeds2, _, _, _, _ := seedService(t, 3, tenant.ScopeSettings{WideningApprovals: intp(2)})
	got2, err := addSeed(seeds2, tenantID, approverA, "acme.com")
	if err != nil || got2.ApprovalsRequired() != 2 {
		t.Fatalf("approvals %v %v", got2, err)
	}
}

func intp(n int) *int { return &n }

func TestSeedWidening_Refusals(t *testing.T) {
	tenantID := shared.NewID()
	ctx := context.Background()

	t.Run("member", func(t *testing.T) {
		seeds, _, tr, notes, _ := seedService(t, 1, tenant.ScopeSettings{})
		_, err := addSeed(seeds, tenantID, member, "acme.com")
		var de *shared.DomainError
		if !errors.Is(err, shared.ErrForbidden) || !errors.As(err, &de) || de.Code != "WIDENING_NEEDS_APPROVER" {
			t.Fatalf("member seed: %v", err)
		}
		if n := len(tr.targets); n != 0 || len(notes.titles) != 0 {
			t.Fatalf("a member's seed left %d entries, %d notices", n, len(notes.titles))
		}
	})
	t.Run("no user", func(t *testing.T) {
		seeds, _, _, _, _ := seedService(t, 1, tenant.ScopeSettings{})
		if _, err := addSeed(seeds, tenantID, scope.Actor{CanApprove: true}, "acme.com"); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("a seed without a user: %v", err)
		}
	})
	t.Run("stale session", func(t *testing.T) {
		seeds, svc, tr, _, _ := seedService(t, 1, tenant.ScopeSettings{})
		svc.SetStepUpGate(staleGate{})
		if _, err := addSeed(seeds, tenantID, approverA, "acme.com"); !errors.Is(err, errNeedsStepUp) {
			t.Fatalf("no step-up: %v", err)
		}
		if len(tr.targets) != 0 {
			t.Fatal("a seed without step-up was stored")
		}
	})
	t.Run("step-up not wired", func(t *testing.T) {
		seeds, svc, _, _, _ := seedService(t, 1, tenant.ScopeSettings{})
		svc.SetStepUpGate(nil)
		if _, err := addSeed(seeds, tenantID, approverA, "acme.com"); !errors.Is(err, scope.ErrStepUpNotWired) {
			t.Fatalf("unwired step-up: %v", err)
		}
	})
	t.Run("guardrails", func(t *testing.T) {
		seeds, _, tr, _, _ := seedService(t, 1, tenant.ScopeSettings{})
		for _, v := range []string{"com", "com.vn", "shop.azurewebsites.net", "acme.local", "not a domain"} {
			if _, err := addSeed(seeds, tenantID, approverA, v); !errors.Is(err, shared.ErrValidation) {
				t.Errorf("%q: %v", v, err)
			}
		}
		if len(tr.targets) != 0 {
			t.Fatal("a refused seed was stored")
		}
	})
	t.Run("not attested", func(t *testing.T) {
		seeds, _, _, _, _ := seedService(t, 1, tenant.ScopeSettings{})
		if _, err := seeds.Create(ctx, tenantID, easmapp.CreateSeedInput{Kind: "root_domain", Value: "acme.com", Actor: approverA}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("unattested: %v", err)
		}
	})
	t.Run("discovery off", func(t *testing.T) {
		seeds, _, _, _, _ := seedService(t, 1, tenant.ScopeSettings{})
		off := false
		if _, err := seeds.Create(ctx, tenantID, easmapp.CreateSeedInput{Kind: "root_domain", Value: "acme.com", Attested: true,
			DiscoveryEnabled: &off, Actor: approverA}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("discovery off silently ignored: %v", err)
		}
	})
	t.Run("duplicates", func(t *testing.T) {
		seeds, _, _, _, store := seedService(t, 1, tenant.ScopeSettings{})
		if _, err := addSeed(seeds, tenantID, approverA, "acme.com"); err != nil {
			t.Fatal(err)
		}
		if _, err := addSeed(seeds, tenantID, approverA, "acme.com"); !errors.Is(err, scopedom.ErrTargetAlreadyExists) {
			t.Fatalf("same entry twice: %v", err)
		}
		store.byTenant[tenantID] = []easmseed.Seed{{ID: shared.NewID(), TenantID: tenantID, Kind: easmseed.KindRootDomain, Value: "legacy-acme.com"}}
		if _, err := addSeed(seeds, tenantID, approverA, "legacy-acme.com"); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("an existing seed again: %v", err)
		}
		if _, err := addSeed(seeds, tenantID, approverA, "eu.legacy-acme.com"); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("under an existing seed: %v", err)
		}
		// Another tenant's seed changes nothing for this one.
		if _, err := addSeed(seeds, shared.NewID(), approverA, "legacy-acme.com"); err != nil {
			t.Fatalf("another tenant's seed applied: %v", err)
		}
	})
	t.Run("entry path not wired", func(t *testing.T) {
		seeds := easmapp.NewSeedService(&legacySeeds{byTenant: map[shared.ID][]easmseed.Seed{}}, nil)
		if _, err := addSeed(seeds, tenantID, approverA, "acme.com"); err == nil {
			t.Fatal("a seed was added with no scope entry path (fail open)")
		}
	})
}

// Turning discovery on is reported so the handler can announce it.
func TestSeedWidening_DiscoveryTurnedOn(t *testing.T) {
	seeds, _, _, _, store := seedService(t, 1, tenant.ScopeSettings{})
	tenantID, id := shared.NewID(), shared.NewID()
	store.byTenant[tenantID] = []easmseed.Seed{{ID: id, TenantID: tenantID, Kind: easmseed.KindRootDomain, Value: "acme.com"}}
	on, off := true, false
	if _, turnedOn, err := seeds.Update(context.Background(), tenantID, id, nil, &on); err != nil || !turnedOn {
		t.Fatalf("off -> on: %v %v", turnedOn, err)
	}
	if _, turnedOn, err := seeds.Update(context.Background(), tenantID, id, nil, &on); err != nil || turnedOn {
		t.Fatalf("on -> on: %v %v", turnedOn, err)
	}
	if _, turnedOn, err := seeds.Update(context.Background(), tenantID, id, nil, &off); err != nil || turnedOn {
		t.Fatalf("on -> off: %v %v", turnedOn, err)
	}
	if _, _, err := seeds.Update(context.Background(), shared.NewID(), id, nil, &on); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
}

// The platform guardrails (RFC-054 §8.2) refuse a seed exactly as they
// refuse a scope entry: government suffixes and the operator's own deny
// list.
func TestSeedWidening_PlatformGuardrails(t *testing.T) {
	seeds, svc, tr, notes, _ := seedService(t, 1, tenant.ScopeSettings{})
	g, bad := scopedom.NewGuardrails(0, 0, []string{"operator-internal.com"})
	if len(bad) != 0 {
		t.Fatal(bad)
	}
	svc.SetGuardrails(g)
	tenantID := shared.NewID()
	for _, v := range []string{"agency.gov", "army.mil", "operator-internal.com", "eu.operator-internal.com"} {
		_, err := addSeed(seeds, tenantID, approverA, v)
		var de *shared.DomainError
		if !errors.As(err, &de) || (de.Code != "DENY_LIST" && de.Code != "PUBLIC_SUFFIX") {
			t.Errorf("%s: %v, want DENY_LIST or PUBLIC_SUFFIX", v, err)
		}
	}
	if len(tr.targets) != 0 || len(notes.titles) != 0 {
		t.Fatalf("a refused seed left %d entries, %d notices", len(tr.targets), len(notes.titles))
	}
}
