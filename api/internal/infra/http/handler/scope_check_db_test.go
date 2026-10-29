package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type fakeDryRun struct {
	results []scansvc.DryRunResult
	routing scansvc.DryRunRouting
}

func (f fakeDryRun) DryRun(context.Context, scansvc.DryRunInput) (*scansvc.DryRunOutcome, error) {
	return &scansvc.DryRunOutcome{Results: f.results, Routing: f.routing}, nil
}

type fakeCoverage struct{}

func (fakeCoverage) CoverOf(_ context.Context, _ shared.ID, targets []string) (map[string]scopeauth.Via, error) {
	out := map[string]scopeauth.Via{}
	for _, t := range targets {
		if strings.HasSuffix(t, "ok.example") {
			out[t] = scopeauth.Via{Kind: scopeauth.KindScopeTarget, ID: "t1", Pattern: "*.ok.example", Proof: scopeauth.ProofAsserted}
		}
	}
	return out, nil
}

// POST /scope/check names the caller's own entry behind a refusal and keeps
// only the fixes the caller may take (RFC-054 §6.4).
func TestScopeCheck_DryRunResponse_DB(t *testing.T) {
	db, ctx := openScopingTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, db)
	other := seedHandlerTenant(ctx, t, db)
	mustExec(ctx, t, db, `INSERT INTO scope_targets (tenant_id, target_type, pattern, status, approvals_required) VALUES ($1,'domain','pend.example','pending',1)`, tenantID)
	// Another tenant's pending entry for the same name explains nothing here.
	mustExec(ctx, t, db, `INSERT INTO scope_targets (tenant_id, target_type, pattern, status, approvals_required) VALUES ($1,'domain','*.b.example','pending',1)`, other)

	pg := &postgres.DB{DB: db}
	svc := scopeapp.NewService(postgres.NewScopeTargetRepository(pg), postgres.NewScopeExclusionRepository(pg), postgres.NewAssetRepository(pg), logger.NewNop())
	h := NewScopeHandler(svc, validator.New(), logger.NewNop())
	h.SetDryRun(fakeDryRun{results: []scansvc.DryRunResult{
		{Target: "app.ok.example", Allowed: true},
		{Target: "pend.example", Code: scopedom.RefusalNoEntry},
		{Target: "x.b.example", Code: scopedom.RefusalNoEntry},
		{Target: "portal.gov.vn", Code: scopedom.RefusalDenyList},
	}}, fakeCoverage{})

	call := func(admin bool, perms []string) CheckScopeResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scope/check", strings.NewReader(`{"targets":["app.ok.example","pend.example","x.b.example","portal.gov.vn"]}`))
		c := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
		c = context.WithValue(c, middleware.IsAdminKey, admin)
		c = context.WithValue(c, middleware.FetchedPermissionsKey, perms)
		rec := httptest.NewRecorder()
		h.CheckScope(rec, req.WithContext(c))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var out CheckScopeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	by := func(out CheckScopeResponse) map[string]ScopeCheckResult {
		m := map[string]ScopeCheckResult{}
		for _, r := range out.Results {
			m[r.Target] = r
		}
		return m
	}

	adm := by(call(true, nil))
	if r := adm["app.ok.example"]; !r.Allowed || r.Via == nil || r.Via.Pattern != "*.ok.example" {
		t.Errorf("allowed: %+v", r)
	}
	if r := adm["pend.example"]; r.Code != scopedom.RefusalEntryPending || r.Rule == nil || r.Rule.Pattern != "pend.example" {
		t.Errorf("pending entry: %+v", r)
	}
	if r := adm["x.b.example"]; r.Code != scopedom.RefusalNoEntry || r.Rule != nil {
		t.Errorf("another tenant's entry leaked into the explanation: %+v", r)
	}
	if r := adm["portal.gov.vn"]; r.Code != scopedom.RefusalDenyList || r.Rule == nil || r.Rule.Kind != scopedom.RulePlatformPolicy || r.Rule.Pattern != "" {
		t.Errorf("deny list: %+v", r)
	}
	hasAction := func(r ScopeCheckResult, a string) bool {
		for _, f := range r.Fixes {
			if f.Action == a {
				return true
			}
		}
		return false
	}
	if !hasAction(adm["x.b.example"], scopedom.FixAllowTemporarily) || hasAction(adm["x.b.example"], scopedom.FixRequestAccess) {
		t.Errorf("admin fixes: %+v", adm["x.b.example"].Fixes)
	}
	mem := by(call(false, []string{"attack_surface:scope:read", "attack_surface:scope:write"}))
	if hasAction(mem["x.b.example"], scopedom.FixAllowTemporarily) || !hasAction(mem["x.b.example"], scopedom.FixRequestAccess) {
		t.Errorf("member fixes: %+v", mem["x.b.example"].Fixes)
	}
	if hasAction(mem["pend.example"], scopedom.FixApproveEntry) {
		t.Errorf("a member was offered to approve: %+v", mem["pend.example"].Fixes)
	}
}

// tier_exceeds names the caller's entry with the highest ceiling and offers
// raising it to approvers only; another tenant's higher entry is never named
// (RFC-054 §6.5).
func TestScopeCheck_TierExceeds_DB(t *testing.T) {
	db, ctx := openScopingTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, db)
	other := seedHandlerTenant(ctx, t, db)
	mustExec(ctx, t, db, `INSERT INTO scope_targets (tenant_id, target_type, pattern, status, max_tier) VALUES ($1,'domain','*.low.example','active',0)`, tenantID)
	mustExec(ctx, t, db, `INSERT INTO scope_targets (tenant_id, target_type, pattern, status, max_tier, expires_at, reason, approvals_required)
		VALUES ($1,'domain','*.low.example','active',2, now() + interval '3 days', 'pentest', 1)`, other)

	pg := &postgres.DB{DB: db}
	svc := scopeapp.NewService(postgres.NewScopeTargetRepository(pg), postgres.NewScopeExclusionRepository(pg), postgres.NewAssetRepository(pg), logger.NewNop())
	h := NewScopeHandler(svc, validator.New(), logger.NewNop())
	h.SetDryRun(fakeDryRun{results: []scansvc.DryRunResult{{Target: "app.low.example", Code: scopedom.RefusalTierExceeds}}}, fakeCoverage{})

	call := func(admin bool, perms []string) ScopeCheckResult {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scope/check", strings.NewReader(`{"targets":["app.low.example"],"tier":1}`))
		c := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
		c = context.WithValue(c, middleware.IsAdminKey, admin)
		c = context.WithValue(c, middleware.FetchedPermissionsKey, perms)
		rec := httptest.NewRecorder()
		h.CheckScope(rec, req.WithContext(c))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var out CheckScopeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Results[0]
	}
	adm := call(true, nil)
	if adm.Code != scopedom.RefusalTierExceeds || adm.Rule == nil || adm.Rule.Pattern != "*.low.example" {
		t.Fatalf("admin: %+v", adm)
	}
	var mine string
	if err := db.QueryRowContext(ctx, `SELECT id FROM scope_targets WHERE tenant_id = $1`, tenantID).Scan(&mine); err != nil {
		t.Fatal(err)
	}
	if adm.Rule.ID != mine {
		t.Fatalf("the rule names %s, not the caller's entry %s", adm.Rule.ID, mine)
	}
	if len(adm.Fixes) != 1 || adm.Fixes[0].Action != scopedom.FixRaiseTier || adm.Fixes[0].ID != mine || adm.Fixes[0].Tier != "t1" {
		t.Fatalf("admin fixes: %+v", adm.Fixes)
	}
	mem := call(false, []string{"attack_surface:scope:read", "attack_surface:scope:write"})
	if mem.Code != scopedom.RefusalTierExceeds || len(mem.Fixes) != 0 {
		t.Fatalf("member: %+v (raising a tier is for approvers)", mem)
	}
}

type recordingDryRun struct {
	got     []scansvc.DryRunInput
	results []scansvc.DryRunResult
}

func (f *recordingDryRun) DryRun(_ context.Context, in scansvc.DryRunInput) (*scansvc.DryRunOutcome, error) {
	f.got = append(f.got, in)
	return &scansvc.DryRunOutcome{Results: f.results}, nil
}

// asset_ids reach the dry run as ids; an asset the caller may not see comes
// back by its id only, with no fixes, and the request is bounded
// (RFC-054 §6.4).
func TestScopeCheck_AssetIDs_DB(t *testing.T) {
	db, ctx := openScopingTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, db)
	pg := &postgres.DB{DB: db}
	svc := scopeapp.NewService(postgres.NewScopeTargetRepository(pg), postgres.NewScopeExclusionRepository(pg), postgres.NewAssetRepository(pg), logger.NewNop())
	h := NewScopeHandler(svc, validator.New(), logger.NewNop())
	mine, hidden := shared.NewID().String(), shared.NewID().String()
	dry := &recordingDryRun{results: []scansvc.DryRunResult{
		{Target: "app.ok.example", AssetID: mine, Allowed: true},
		{Target: hidden, AssetID: hidden, Code: scopedom.RefusalOutOfDataScope, Reason: "outside"},
	}}
	h.SetDryRun(dry, fakeCoverage{})

	call := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scope/check", strings.NewReader(body))
		c := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
		c = context.WithValue(c, middleware.IsAdminKey, true)
		rec := httptest.NewRecorder()
		h.CheckScope(rec, req.WithContext(c))
		return rec
	}

	rec := call(`{"asset_ids":["` + mine + `","` + hidden + `"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if len(dry.got) != 1 || len(dry.got[0].AssetIDs) != 2 || len(dry.got[0].Targets) != 0 || dry.got[0].Tier != 1 {
		t.Fatalf("dry-run input = %+v", dry.got)
	}
	var out CheckScopeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if r := out.Results[0]; !r.Allowed || r.AssetID != mine || r.Via == nil {
		t.Fatalf("own asset = %+v", r)
	}
	if r := out.Results[1]; r.Allowed || r.Target != hidden || r.AssetID != hidden || r.Code != scopedom.RefusalOutOfDataScope || len(r.Fixes) != 0 || r.Rule != nil {
		t.Fatalf("hidden asset = %+v", r)
	}

	many := make([]string, 0, 201)
	for range 201 {
		many = append(many, `"`+shared.NewID().String()+`"`)
	}
	for name, body := range map[string]string{
		"empty":             `{}`,
		"not a uuid":        `{"asset_ids":["nope"]}`,
		"too many assets":   `{"asset_ids":[` + strings.Join(many, ",") + `]}`,
		"too many together": `{"targets":["a.example"],"asset_ids":[` + strings.Join(many[:200], ",") + `]}`,
	} {
		// 400 for the size rule, 422 for a field validation error.
		if rec := call(body); rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 400 or 422", name, rec.Code)
		}
	}
	if len(dry.got) != 1 {
		t.Fatalf("a refused request reached the dry run: %d calls", len(dry.got))
	}
}

// The preview of a single-scanner scan checks at the scanner's own tier (the
// one its create refuses tier_exceeds at), unless the caller names a tier; an
// unknown scanner is safe active, like the create path.
func TestScopeCheck_ScannerNameSetsTier_DB(t *testing.T) {
	db, ctx := openScopingTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, db)
	pg := &postgres.DB{DB: db}
	svc := scopeapp.NewService(postgres.NewScopeTargetRepository(pg), postgres.NewScopeExclusionRepository(pg), postgres.NewAssetRepository(pg), logger.NewNop())
	h := NewScopeHandler(svc, validator.New(), logger.NewNop())
	rec := &recordingDryRun{results: []scansvc.DryRunResult{{Target: "app.example.com", Code: scopedom.RefusalNoEntry}}}
	h.SetDryRun(rec, fakeCoverage{})

	tierFor := func(body string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scope/check", strings.NewReader(body))
		c := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
		c = context.WithValue(c, middleware.IsAdminKey, true)
		w := httptest.NewRecorder()
		h.CheckScope(w, req.WithContext(c))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", body, w.Code, w.Body.String())
		}
		var out CheckScopeResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: decode: %v", body, err)
		}
		got := rec.got[len(rec.got)-1].Tier
		if out.Tier != got {
			t.Fatalf("%s: response tier %d, checked at %d", body, out.Tier, got)
		}
		return got
	}
	want := int(scansvc.ProbeTier("zap"))
	if want != 2 {
		t.Fatalf("catalog: zap probes at %d, this test expects the intrusive tier", want)
	}
	if got := tierFor(`{"targets":["app.example.com"],"scanner_name":"zap"}`); got != want {
		t.Fatalf("scanner_name zap: tier %d, want %d", got, want)
	}
	if got := tierFor(`{"targets":["app.example.com"],"scanner_name":"zap","tier":0}`); got != 0 {
		t.Fatalf("an explicit tier must win: got %d", got)
	}
	if got := tierFor(`{"targets":["app.example.com"],"scanner_name":"no-such-tool"}`); got != 1 {
		t.Fatalf("unknown scanner: tier %d, want 1", got)
	}
	if got := tierFor(`{"targets":["app.example.com"]}`); got != 1 {
		t.Fatalf("default: tier %d, want 1", got)
	}
}

// The scope check says where the scan would run (the organization's own
// sensor by name, never a platform sensor), shows the private address a
// refused hostname resolved to, and offers "use your own sensor" for proof
// at every tier (proof applies only to platform sensors).
func TestScopeCheck_RoutingResolvedAndProofFixes_DB(t *testing.T) {
	db, ctx := openScopingTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, db)
	pg := &postgres.DB{DB: db}
	svc := scopeapp.NewService(postgres.NewScopeTargetRepository(pg), postgres.NewScopeExclusionRepository(pg), postgres.NewAssetRepository(pg), logger.NewNop())
	h := NewScopeHandler(svc, validator.New(), logger.NewNop())
	h.SetDryRun(fakeDryRun{
		results: []scansvc.DryRunResult{
			{Target: "intra.acme.example", Code: scopedom.RefusalZoneNone, Resolved: []string{"10.20.0.7"}},
			{Target: "www.acme.example", Code: scopedom.RefusalProofRequired},
		},
		routing: scansvc.DryRunRouting{Preference: "auto", RunsOn: scansvc.RoutingTenant, Reason: scansvc.RoutingReasonProof,
			SensorID: "0192a7c4-0000-7000-8000-000000000001", SensorName: "sensor-docker-01"},
	}, fakeCoverage{})
	call := func(tier int) CheckScopeResponse {
		t.Helper()
		body := `{"targets":["intra.acme.example","www.acme.example"],"tier":` + strconv.Itoa(tier) + `}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scope/check", strings.NewReader(body))
		c := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
		c = context.WithValue(c, middleware.IsAdminKey, true)
		rec := httptest.NewRecorder()
		h.CheckScope(rec, req.WithContext(c))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var out CheckScopeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	out := call(1)
	if out.Routing.RunsOn != "tenant" || out.Routing.Reason != "platform_needs_proof" || out.Routing.Sensor == nil || out.Routing.Sensor.Name != "sensor-docker-01" {
		t.Fatalf("routing: %+v", out.Routing)
	}
	if len(out.Results[0].Resolved) != 1 || out.Results[0].Resolved[0] != "10.20.0.7" {
		t.Fatalf("resolved: %+v", out.Results[0])
	}
	hasFix := func(r ScopeCheckResult, action string) bool {
		for _, f := range r.Fixes {
			if f.Action == action {
				return true
			}
		}
		return false
	}
	if !hasFix(out.Results[1], scopedom.FixUseTenantSensor) || !hasFix(out.Results[1], scopedom.FixVerifyDomain) {
		t.Fatalf("safe-active proof fixes: %+v", out.Results[1].Fixes)
	}
	intrusive := call(2)
	// Proof is for platform sensors only, at any tier: the own sensor helps an
	// intrusive probe too.
	if !hasFix(intrusive.Results[1], scopedom.FixUseTenantSensor) || !hasFix(intrusive.Results[1], scopedom.FixVerifyDomain) {
		t.Fatalf("intrusive proof fixes: %+v", intrusive.Results[1].Fixes)
	}
}

// tierDryRun refuses tier_exceeds above maxTier and records the tenant of
// every call (the remedies' re-check runs for the caller's tenant only).
type tierDryRun struct {
	maxTier int
	routing scansvc.DryRunRouting
	tenants *[]string
	tiers   *[]int
}

func (f tierDryRun) DryRun(_ context.Context, in scansvc.DryRunInput) (*scansvc.DryRunOutcome, error) {
	*f.tenants = append(*f.tenants, in.TenantID.String())
	*f.tiers = append(*f.tiers, in.Tier)
	out := &scansvc.DryRunOutcome{Routing: f.routing}
	for _, t := range in.Targets {
		switch {
		case strings.HasPrefix(t, "proof."):
			out.Results = append(out.Results, scansvc.DryRunResult{Target: t, Code: scopedom.RefusalProofRequired})
		case in.Tier > f.maxTier:
			out.Results = append(out.Results, scansvc.DryRunResult{Target: t, Code: scopedom.RefusalTierExceeds})
		default:
			out.Results = append(out.Results, scansvc.DryRunResult{Target: t, Allowed: true})
		}
	}
	return out, nil
}

// POST /scope/check ranks the remedies of each refusal: run on the
// organization's own sensor (only when one is online), verify the domain
// (only for a caller who may), a lower intensity (only when the same gate
// lets the target through at that tier, and only for an explicit tier), and
// remove last.
func TestScopeCheck_Remedies_DB(t *testing.T) {
	db, ctx := openScopingTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, db)
	pg := &postgres.DB{DB: db}
	svc := scopeapp.NewService(postgres.NewScopeTargetRepository(pg), postgres.NewScopeExclusionRepository(pg), postgres.NewAssetRepository(pg), logger.NewNop())

	type call struct {
		body   string
		admin  bool
		perms  []string
		sensor bool
	}
	run := func(c call) (map[string][]scopedom.Remedy, []string, []int) {
		t.Helper()
		var tenants []string
		var tiers []int
		h := NewScopeHandler(svc, validator.New(), logger.NewNop())
		h.SetDryRun(tierDryRun{maxTier: 1, tenants: &tenants, tiers: &tiers,
			routing: scansvc.DryRunRouting{Preference: "platform", RunsOn: scansvc.RoutingPlatform, TenantSensor: c.sensor}}, fakeCoverage{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scope/check", strings.NewReader(c.body))
		cx := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
		cx = context.WithValue(cx, middleware.IsAdminKey, c.admin)
		cx = context.WithValue(cx, middleware.FetchedPermissionsKey, c.perms)
		rec := httptest.NewRecorder()
		h.CheckScope(rec, req.WithContext(cx))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var out CheckScopeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		m := map[string][]scopedom.Remedy{}
		for _, r := range out.Results {
			if r.Allowed && len(r.Remedies) > 0 {
				t.Errorf("an allowed target got remedies: %+v", r)
			}
			m[r.Target] = r.Remedies
		}
		return m, tenants, tiers
	}
	acts := func(rs []scopedom.Remedy) string {
		out := make([]string, 0, len(rs))
		for _, r := range rs {
			out = append(out, r.Action)
		}
		return strings.Join(out, ",")
	}
	body := `{"targets":["proof.acme.example","app.acme.example"],"sensor_preference":"platform","tier":2}`

	// Admin, own sensor online: run on it first, then verify, remove.
	got, tenants, tiers := run(call{body: body, admin: true, sensor: true})
	if a := acts(got["proof.acme.example"]); a != "run_on_tenant_sensor,verify_domain,remove" {
		t.Errorf("proof remedies (admin, sensor): %s", a)
	}
	if r := got["proof.acme.example"]; len(r) < 2 || r[1].Domain != "acme.example" {
		t.Errorf("verify names the registrable domain: %+v", r)
	}
	// Intrusive refused, safe active allowed: lower to tier 1.
	if a := acts(got["app.acme.example"]); a != "lower_intensity,remove" {
		t.Errorf("tier remedies: %s", a)
	}
	if r := got["app.acme.example"]; r[0].Tier == nil || *r[0].Tier != 1 {
		t.Errorf("lower intensity tier: %+v", r)
	}
	if len(tiers) != 2 || tiers[1] != 1 {
		t.Errorf("the re-check runs once at the next tier down: %v", tiers)
	}
	for _, tn := range tenants {
		if tn != tenantID {
			t.Errorf("a dry run ran for another tenant: %s", tn)
		}
	}

	// No own sensor: verify first; a member without approve gets remove only.
	got, _, _ = run(call{body: body, admin: true})
	if a := acts(got["proof.acme.example"]); a != "verify_domain,remove" {
		t.Errorf("proof remedies (admin, no sensor): %s", a)
	}
	got, _, _ = run(call{body: body, perms: []string{"attack_surface:scope:read"}})
	if a := acts(got["proof.acme.example"]); a != "remove" {
		t.Errorf("proof remedies (member without approve): %s", a)
	}

	// A single scanner's tier (no explicit tier) is never lowered.
	got, _, tiers = run(call{body: `{"targets":["app.acme.example"],"scanner_name":"zap"}`, admin: true})
	if a := acts(got["app.acme.example"]); a != "remove" {
		t.Errorf("scanner tier remedies: %s", a)
	}
	if len(tiers) != 1 {
		t.Errorf("no re-check without an explicit tier: %v", tiers)
	}
}
