package integration

// Names that resolve only through a wildcard DNS record (RFC-088 decision
// A4), on a real database: the scope join never confirms them, the
// active-scan gate keeps them (and their services) passive until a person
// confirms them or a filtered resolution reports them, and every mark is the
// tenant's own.

import (
	"context"
	"slices"
	"testing"
	"time"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestWildcardOnlyNames(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	marks := postgres.NewAssetWildcardDNSRepository(&postgres.DB{DB: db})
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	seedScopeTarget(t, db, tenantA, "domain", "*.wc-a.example")
	seedScopeTarget(t, db, tenantB, "domain", "*.wc-b.example")

	pendingIn := func(tenant shared.ID, name, typ string) shared.ID {
		id := seedOwnedAsset(t, db, tenant, name, typ)
		automatic(t, db, tenant, id, attribution.StateNeedsReview)
		return id
	}
	phantom := pendingIn(tenantA, "guess.wc-a.example", "subdomain")
	realName := pendingIn(tenantA, "api.wc-a.example", "subdomain")
	phantomSvc := seedOwnedAsset(t, db, tenantA, "guess.wc-a.example:443:tcp", "service")
	bName := pendingIn(tenantB, "guess.wc-b.example", "subdomain")

	// Tenant A's resolution dropped its guess; a call naming tenant B's
	// asset under tenant A writes nothing.
	cmd := shared.NewID()
	if err := marks.MarkWildcardOnly(ctx, tenantA, []shared.ID{phantom, bName}, cmd, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := marks.WildcardOnly(ctx, tenantB, []shared.ID{phantom, bName})
	if err != nil || len(got) != 0 {
		t.Fatalf("tenant B reads tenant A's mark or got one through tenant A: %v %v", got, err)
	}
	got, err = marks.WildcardOnly(ctx, tenantA, []shared.ID{phantom, realName, bName})
	if err != nil || !got[phantom] || got[realName] || got[bName] {
		t.Fatalf("tenant A marks = %v (%v), want only the guess", got, err)
	}

	// The scope join confirms the real name, never the wildcard-only one.
	join := scopeJoin(db)
	join.SetWildcardDNS(marks)
	confirmed, err := join.Reevaluate(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(confirmed, []string{"api.wc-a.example"}) {
		t.Fatalf("confirmed = %v, want only api.wc-a.example", confirmed)
	}
	if st := attributionState(t, db, tenantA, phantom); st != attribution.StateNeedsReview {
		t.Fatalf("wildcard-only name = %s, want needs_review", st)
	}
	blocked, err := join.Blocked(ctx, tenantA, []easmapp.JoinItem{{ID: phantom.String(), Name: "guess.wc-a.example"}})
	if err != nil || blocked[phantom.String()] != "wildcard_only" {
		t.Fatalf("blocked = %v (%v), want wildcard_only", blocked, err)
	}

	// The gate: a scope entry covers both, the wildcard-only name and its
	// service stay passive; the real name is probed.
	gate := ownershipGate(db)
	gate.SetWildcardDNS(marks)
	ids := []string{phantom.String(), realName.String(), phantomSvc.String()}
	refused, err := gate.ActiveCheckBlocked(ctx, tenantA, ids)
	if err != nil {
		t.Fatal(err)
	}
	if refused[phantom.String()] != attribution.StateWildcardOnly || refused[phantomSvc.String()] != attribution.StateWildcardOnly {
		t.Fatalf("refused = %v, want the guess and its service wildcard_only", refused)
	}
	if s, no := refused[realName.String()]; no {
		t.Fatalf("real name refused: %s", s)
	}
	typed, err := gate.BlockedTargets(ctx, tenantA, []string{"https://guess.wc-a.example/login"})
	if err != nil || typed["https://guess.wc-a.example/login"] != attribution.StateWildcardOnly {
		t.Fatalf("typed URL on the guess = %v (%v), want wildcard_only", typed, err)
	}

	// A person confirming the name lifts it.
	decide(t, db, tenantA, phantom, attribution.StateConfirmed)
	if refused, err = gate.ActiveCheckBlocked(ctx, tenantA, []string{phantom.String()}); err != nil || len(refused) != 0 {
		t.Fatalf("after a person confirmed: %v %v", refused, err)
	}

	// A filtered resolution that reports the name clears the mark; a clear
	// asked by another tenant clears nothing.
	other := pendingIn(tenantA, "other.wc-a.example", "subdomain")
	if err := marks.MarkWildcardOnly(ctx, tenantA, []shared.ID{other}, cmd, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := marks.ClearWildcardOnly(ctx, tenantB, []shared.ID{other}); err != nil {
		t.Fatal(err)
	}
	if got, _ = marks.WildcardOnly(ctx, tenantA, []shared.ID{other}); !got[other] {
		t.Fatal("tenant B cleared tenant A's mark")
	}
	if err := marks.ClearWildcardOnly(ctx, tenantA, []shared.ID{other}); err != nil {
		t.Fatal(err)
	}
	if refused, err = gate.ActiveCheckBlocked(ctx, tenantA, []string{other.String()}); err != nil || len(refused) != 0 {
		t.Fatalf("after the mark cleared: %v %v", refused, err)
	}
}
