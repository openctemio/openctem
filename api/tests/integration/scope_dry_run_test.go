package integration

// POST /scope/check is a dry run of the whole active-probe gate (RFC-054
// §6.4, §6.5): codes, the caller's own rule, and no dispatch.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestScopeDryRun(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	admin, member := seedActUser(t, db), seedActUser(t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	seedScopeTarget(t, db, tenantA, "domain", "*.dry.example")
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status, approvals_required) VALUES ($1, 'domain', 'pend.example', 'pending', 1)`, tenantA.String())
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status, expires_at, reason) VALUES ($1, 'domain', '*.old.example', 'active', now() - interval '1 hour', 'x')`, tenantA.String())
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, 'domain', 'off.example', 'inactive')`, tenantA.String())
	exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_by, approved_at, created_by)
		VALUES ($1, 'domain', 'excl.dry.example', 'fragile', 'active', 'a', now(), 'b')`, tenantA.String())
	exec(`INSERT INTO verified_domains (id, tenant_id, domain, verification_token, status, purpose) VALUES ($1, $2, 'proven.dry.example', 'tok', 'verified', 'easm')`,
		shared.NewID().String(), tenantA.String())
	// Tenant B covers what tenant A does not: it must not matter.
	seedScopeTarget(t, db, tenantB, "domain", "*.b-only.example")
	mine := seedActAsset(t, db, tenantA, "mine.dry.example")
	grantScope(t, db, tenantA, member, mine)

	gate := ownershipGate(db).WithPlatformPolicy(scopedom.DefaultGuardrails(), false)
	svc := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
		scansvc.WithAttributionGate(gate), scansvc.WithActScope(actScopeChecker(db, admin)),
		scansvc.WithActiveProof(scansvc.ActiveProofPlatformSensors))
	asAdmin := asCaller(ctx, datascope.Caller{UserID: admin.String(), IsAdmin: true})
	asMember := asCaller(ctx, datascope.Caller{UserID: member.String()})

	run := func(ctx context.Context, pref string, targets ...string) map[string]scansvc.DryRunResult {
		t.Helper()
		res, err := svc.DryRunTargets(ctx, scansvc.DryRunInput{TenantID: tenantA, Targets: targets, SensorPreference: pref, Tier: 1})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]scansvc.DryRunResult{}
		for _, r := range res {
			out[r.Target] = r
		}
		return out
	}

	got := run(asAdmin, "auto", "app.dry.example", "dry.example", "excl.dry.example", "pend.example", "x.old.example",
		"off.example", "x.b-only.example", "portal.gov.vn", "169.254.169.254")
	want := map[string]string{
		"app.dry.example": "", "dry.example": "",
		"excl.dry.example": scopedom.RefusalExcluded,
		"pend.example":     scopedom.RefusalNoEntry,
		"x.old.example":    scopedom.RefusalNoEntry,
		"off.example":      scopedom.RefusalNoEntry,
		"x.b-only.example": scopedom.RefusalNoEntry,
		"portal.gov.vn":    scopedom.RefusalDenyList,
		"169.254.169.254":  scopedom.RefusalInvalidTarget,
	}
	for target, code := range want {
		r := got[target]
		if code == "" {
			if !r.Allowed {
				t.Errorf("%s refused (%s %s), want allowed", target, r.Code, r.Reason)
			}
			continue
		}
		if r.Allowed || r.Code != code {
			t.Errorf("%s: allowed=%v code=%q, want %s", target, r.Allowed, r.Code, code)
		}
	}

	// Platform sensors need proof under platform_sensors.
	got = run(asAdmin, "platform", "app.dry.example", "www.proven.dry.example")
	if got["app.dry.example"].Code != scopedom.RefusalProofRequired || !got["www.proven.dry.example"].Allowed {
		t.Errorf("platform proof: %+v", got)
	}

	// A restricted member learns nothing about targets outside their data
	// scope: the act-scope answer comes first.
	got = run(asMember, "auto", "mine.dry.example", "excl.dry.example", "pend.example")
	if !got["mine.dry.example"].Allowed {
		t.Errorf("member's own asset: %+v", got["mine.dry.example"])
	}
	for _, target := range []string{"excl.dry.example", "pend.example"} {
		if got[target].Code != scopedom.RefusalNotAnAsset {
			t.Errorf("member %s: code %s, want not_an_asset (no detail leak)", target, got[target].Code)
		}
	}

	// The explainer names the caller's own entry that would cover it.
	ex, err := scopeService(db).NewExplainer(ctx, tenantA.String())
	if err != nil {
		t.Fatal(err)
	}
	for target, code := range map[string]string{
		"pend.example": scopedom.RefusalEntryPending, "x.old.example": scopedom.RefusalEntryExpired,
		"off.example": scopedom.RefusalEntryInactive, "x.b-only.example": scopedom.RefusalNoEntry,
	} {
		c, rule := ex.Uncovered(target)
		if c != code {
			t.Errorf("explain %s: %s, want %s", target, c, code)
		}
		if code == scopedom.RefusalNoEntry && rule != nil {
			t.Errorf("explain %s: names a rule %+v (another tenant's?)", target, rule)
		}
	}
	if r := ex.Exclusion("excl.dry.example"); r == nil || r.Pattern != "excl.dry.example" {
		t.Errorf("exclusion rule: %+v", r)
	}
	// No command was created by any dry run.
	if n := countRows(t, db, `SELECT count(*) FROM commands WHERE tenant_id = $1`, tenantA); n != 0 {
		t.Fatalf("a dry run created %d command(s)", n)
	}
}
