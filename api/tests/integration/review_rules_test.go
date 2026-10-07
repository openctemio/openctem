package integration

// Review by rule on a real database (RFC-054 §6.7): grouped suggestions,
// previews that change nothing, and the three actions through the scope
// service.

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	scopesvc "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type passStepUp struct{}

func (passStepUp) RequireRecentAuth(context.Context, string) error { return nil }

type oneAdmin struct{}

func (oneAdmin) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return []shared.ID{shared.NewID()}, nil
}

func ruleService(db *sql.DB) *easmapp.RuleService {
	pg := &postgres.DB{DB: db}
	sc := scopeService(db)
	sc.SetStepUpGate(passStepUp{})
	sc.SetEntryPolicy(nil, oneAdmin{}, nil)
	review := easmapp.NewReviewService(postgres.NewAttributionRepository(pg), nil)
	return easmapp.NewRuleService(review, scopeJoin(db), sc, postgres.NewAssetRepository(pg), ownershipGate(db), scopedom.DefaultGuardrails())
}

func TestReviewByRule(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	pending := func(tenant shared.ID, name, typ string) shared.ID {
		id := seedOwnedAsset(t, db, tenant, name, typ)
		automatic(t, db, tenant, id, attribution.StateNeedsReview)
		return id
	}
	a := pending(tenantA, "a.dev.ipas.example", "subdomain")
	b := pending(tenantA, "b.dev.ipas.example", "subdomain")
	c := pending(tenantA, "c.ipas.example", "subdomain")
	ex := pending(tenantA, "ex.dev.ipas.example", "subdomain")
	ip1 := pending(tenantA, "203.0.113.5", "ip_address")
	ip2 := pending(tenantA, "203.0.113.9", "ip_address")
	cdn := pending(tenantA, "104.16.1.1", "ip_address")
	exec(`UPDATE assets SET properties = '{"asn": 13335, "asn_org": "Cloudflare, Inc."}' WHERE id = $1`, cdn.String())
	exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_by, approved_at, created_by)
		VALUES ($1, 'domain', 'ex.dev.ipas.example', 'not ours', 'active', 'x', now(), 'y')`, tenantA.String())
	bOnly := pending(tenantB, "z.dev.ipas.example", "subdomain")

	svc := ruleService(db)
	admin := scopesvc.Actor{UserID: shared.NewID().String(), CanApprove: true}

	got, err := svc.Suggest(ctx, tenantA, nil, 50)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]easmapp.RuleSuggestion{}
	for _, s := range got.Suggestions {
		by[s.Pattern] = s
	}
	if s := by["*.dev.ipas.example"]; s.Covered != 2 || s.Blocked != 1 || s.TargetType != "domain" {
		t.Errorf("*.dev.ipas.example = %+v", s)
	}
	if s := by["*.ipas.example"]; s.Covered != 3 || s.Blocked != 1 {
		t.Errorf("*.ipas.example = %+v", s)
	}
	if s := by["203.0.113.0/24"]; s.Covered != 2 || s.TargetType != "cidr" {
		t.Errorf("203.0.113.0/24 = %+v", s)
	}
	for p := range by {
		if p == "*.example" || p == "104.16.1.0/24" {
			t.Errorf("suggested %s (public suffix or shared provider space)", p)
		}
		for _, sample := range by[p].CoveredSample {
			if sample == "z.dev.ipas.example" {
				t.Errorf("tenant B's item counted in tenant A's suggestion %s", p)
			}
		}
	}
	if !slices.ContainsFunc(got.Individual, func(i easmapp.IndividualItem) bool { return i.Name == "104.16.1.1" && i.SharedIP }) {
		t.Errorf("shared address not listed individually: %+v", got.Individual)
	}

	// Refusals come back in the preview and change nothing.
	p, err := svc.Preview(ctx, tenantA, easmapp.RuleActionInput{Action: easmapp.RuleAcceptRule, TargetType: "domain", Pattern: "*.com", Reason: "x", Actor: admin})
	if err != nil || p.Allowed || p.Refusal == nil || p.Refusal.Code != "PUBLIC_SUFFIX" {
		t.Fatalf("public suffix preview: %+v %v", p, err)
	}
	member := scopesvc.Actor{UserID: shared.NewID().String()}
	p, err = svc.Preview(ctx, tenantA, easmapp.RuleActionInput{Action: easmapp.RuleAcceptRule, TargetType: "domain", Pattern: "*.dev.ipas.example", Reason: "x", Actor: member})
	if err != nil || p.Allowed || p.Refusal == nil || p.Refusal.Code != "REQUEST_MUST_BE_ONE_OFF" {
		t.Fatalf("member accept_rule preview: %+v %v", p, err)
	}

	// Accept as a rule: preview, then apply; the entry is in effect (one
	// admin) and the pending items it covers are confirmed; the excluded one
	// stays; tenant B's twin is untouched.
	p, err = svc.Preview(ctx, tenantA, easmapp.RuleActionInput{Action: easmapp.RuleAcceptRule, TargetType: "domain", Pattern: "*.dev.ipas.example", Reason: "our dev", Actor: admin})
	if err != nil || !p.Allowed || len(p.WouldConfirm) != 2 || len(p.StaysBlocked) != 1 || p.Entry.Status != "active" || !p.StepUpRequired {
		t.Fatalf("accept_rule preview: %+v %v", p, err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM scope_targets WHERE tenant_id = $1`, tenantA); n != 0 {
		t.Fatalf("a preview created %d scope entries", n)
	}
	res, err := svc.Apply(ctx, tenantA, easmapp.RuleActionInput{Action: easmapp.RuleAcceptRule, TargetType: "domain", Pattern: "*.dev.ipas.example", Reason: "our dev", Actor: admin})
	if err != nil || res.Target == nil {
		t.Fatalf("accept_rule: %+v %v", res, err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM scope_targets WHERE tenant_id = $1 AND origin = 'review_rule'`, tenantA); n != 1 {
		t.Fatalf("accepted rule entries with origin review_rule = %d", n)
	}
	for id, want := range map[shared.ID]attribution.State{a: attribution.StateConfirmed, b: attribution.StateConfirmed, ex: attribution.StateNeedsReview, c: attribution.StateNeedsReview} {
		if st := attributionState(t, db, tenantA, id); st != want {
			t.Errorf("%s = %s, want %s", id, st, want)
		}
	}
	if st := attributionState(t, db, tenantB, bOnly); st != attribution.StateNeedsReview {
		t.Errorf("tenant B's item changed: %s", st)
	}

	// Reject as a rule: an exclusion (pending its approval) and the covered
	// pending addresses rejected.
	res, err = svc.Apply(ctx, tenantA, easmapp.RuleActionInput{Action: easmapp.RuleRejectRule, TargetType: "cidr", Pattern: "203.0.113.0/24", Reason: "provider range", Actor: admin})
	if err != nil || res.Exclusion == nil || res.Exclusion.Status() != scopedom.StatusPending || len(res.Preview.Rejected) != 2 {
		t.Fatalf("reject_rule: %+v %v", res, err)
	}
	if res.Exclusion.Origin() != scopedom.OriginReviewRule {
		t.Fatalf("reject_rule exclusion origin = %s", res.Exclusion.Origin())
	}
	for _, id := range []shared.ID{ip1, ip2} {
		if st := attributionState(t, db, tenantA, id); st != attribution.StateRejected {
			t.Errorf("%s = %s, want rejected", id, st)
		}
	}

	// Accept the shared address on its own.
	res, err = svc.Apply(ctx, tenantA, easmapp.RuleActionInput{Action: easmapp.RuleAcceptSelected, AssetIDs: []string{cdn.String(), bOnly.String()}, Actor: admin})
	if err != nil || len(res.Preview.Confirmed) != 1 {
		t.Fatalf("accept_selected: %+v %v", res, err)
	}
	if st := attributionState(t, db, tenantB, bOnly); st != attribution.StateNeedsReview {
		t.Errorf("accept_selected reached tenant B: %s", st)
	}
}
