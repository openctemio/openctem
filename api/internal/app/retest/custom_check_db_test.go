package retest_test

// A finding's custom retest check (docs/architecture/finding-retest-checks.md)
// end to end on the database: the check is sent with the retest command and
// its verdict follows the calibration rule. DB-gated like the rest.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	"github.com/openctemio/openctem/api/internal/app/retestcheck"
	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	checkdom "github.com/openctemio/openctem/api/pkg/domain/retestcheck"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// checkService is the retest check service over the test database.
func (fx *fixture) checkService() *retestcheck.Service {
	lib := retestcheck.LibraryTemplates{Svc: app.NewScannerTemplateService(postgres.NewScannerTemplateRepository(fx.pg), "", logger.NewNop())}
	return retestcheck.NewService(postgres.NewFindingRetestCheckRepository(fx.pg), postgres.NewFindingRepository(fx.pg), lib, nil, logger.NewNop())
}

// manualFinding is a finding no tool reported: no tool, no rule.
func (fx *fixture) manualFinding(asset shared.ID) shared.ID {
	f := fx.newFinding(asset, "confirmed", "x")
	fx.exec(`UPDATE findings SET source = 'manual', tool_name = '', rule_id = NULL WHERE id = $1`, f.String())
	return f
}

func adminAssertion() *checkdom.HTTPAssertion {
	return &checkdom.HTTPAssertion{Method: "GET", Path: "/admin", Matchers: []checkdom.Matcher{
		{Type: "status", Status: []int{200}}, {Type: "word", Part: "body", Words: []string{"Site administration"}}}}
}

func digestVerdict(ref shared.ID, v, digest string, withAttempt bool) []map[string]any {
	out := map[string]any{"ref": ref.String(), "verdict": v, "detail": "checked", "template_digest": digest}
	if withAttempt {
		out["evidence"] = attemptItems("https://shop.example.com/admin", 404)
	}
	return []map[string]any{out}
}

func (fx *fixture) settleWith(svc *retestapp.Service, rt *retestdom.Retest, verdicts []map[string]any) *retestdom.Retest {
	fx.t.Helper()
	fx.finishTool(rt.CheckCommandID, verdicts)
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.CheckCommandID)
	// The next attempt is not held back by the per-finding cooldown.
	fx.exec(`UPDATE finding_retests SET created_at = created_at - interval '1 day' WHERE id = $1`, rt.ID.String())
	return fx.retest(rt.ID)
}

func TestRetestDB_CustomCheckIsSentAndCalibrated(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	checks := fx.checkService()
	svc := fx.serviceWith(toolSensors{"nuclei": true, "templates:nuclei": true})
	svc.SetCheckSource(retestcheck.RetestSource{Svc: checks})
	f := fx.manualFinding(fx.asset)
	user := fx.user
	in := retestapp.RequestInput{TenantID: fx.tenant, FindingID: f, Trigger: retestdom.TriggerManual, RequestedBy: &user}

	// Without a check, a manual finding has nothing to re-run.
	if _, err := svc.Request(ctx, in); !errors.Is(err, retestdom.ErrNotEligible) {
		t.Fatalf("manual finding without a check: err = %v", err)
	}

	view, err := checks.Save(ctx, auditapp.AuditContext{}, fx.tenant, f, fx.user,
		retestcheck.Input{Kind: checkdom.KindHTTPAssertion, Assertion: adminAssertion()})
	if err != nil {
		t.Fatal(err)
	}
	digest := view.Digest()

	// A sensor that cannot run delivered templates is not enough.
	plain := fx.serviceWith(toolSensors{"nuclei": true})
	plain.SetCheckSource(retestcheck.RetestSource{Svc: checks})
	if _, err := plain.Request(ctx, in); !errors.Is(err, retestdom.ErrNoCheckSensor) {
		t.Fatalf("no retest-templates sensor: err = %v", err)
	}

	rt, err := svc.Request(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if rt.CheckID == nil || *rt.CheckID != view.Check.ID || rt.CheckDigest != digest || rt.CheckPath != "/admin" {
		t.Fatalf("retest provenance %+v", rt)
	}
	var raw []byte
	if err := fx.db.QueryRow(`SELECT payload FROM commands WHERE id = $1`, rt.CheckCommandID.String()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var p validation.RetestCommandPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.CustomTemplates) != 1 || p.Items[0].Template != view.Template.ID.String() ||
		p.Items[0].RuleID != checkdom.TemplateIDFor(f.String()) || p.Scanner != "nuclei" ||
		strings.Join(p.RequiredCapabilities, ",") != "retest:nuclei,retest-templates:nuclei" {
		t.Fatalf("payload %s", raw)
	}
	sent, _ := base64.StdEncoding.DecodeString(p.CustomTemplates[0].Content)
	if string(sent) != string(view.Template.Content) || p.CustomTemplates[0].TemplateType != "nuclei" {
		t.Fatalf("template sent %q", sent)
	}

	// SECURITY: a no-match of a check that never matched proves nothing.
	got := fx.settleWith(svc, rt, digestVerdict(f, "fixed", digest, true))
	if got.Outcome != retestdom.OutcomeNotReproduced || got.ReasonCode != retestdom.ReasonCheckUncalibrated {
		t.Fatalf("uncalibrated no-match: %+v", got)
	}

	// A verdict about other content than was sent does not count.
	rt, err = svc.Request(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	got = fx.settleWith(svc, rt, digestVerdict(f, "still_present", "sha256:"+strings.Repeat("0", 64), false))
	if got.Outcome != retestdom.OutcomeInconclusive || got.ReasonCode != retestdom.ReasonTemplateChanged {
		t.Fatalf("other digest: %+v", got)
	}

	// A match calibrates the check ...
	rt, err = svc.Request(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if got = fx.settleWith(svc, rt, digestVerdict(f, "still_present", digest, false)); got.Outcome != retestdom.OutcomeStillVulnerable {
		t.Fatalf("match: %+v", got)
	}
	if v, _ := checks.Get(ctx, fx.tenant, f); v == nil || !v.Check.Calibrated(digest) {
		t.Fatalf("the match did not calibrate the check: %+v", v)
	}
	// ... after which a no-match on the answered endpoint proves the fix.
	rt, err = svc.Request(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if got = fx.settleWith(svc, rt, digestVerdict(f, "fixed", digest, true)); got.Outcome != retestdom.OutcomeConfirmedFixed {
		t.Fatalf("calibrated no-match: %+v", got)
	}

	// Editing the check resets the calibration.
	edited := adminAssertion()
	edited.Path = "/admin/"
	if view, err = checks.Save(ctx, auditapp.AuditContext{}, fx.tenant, f, fx.user,
		retestcheck.Input{Kind: checkdom.KindHTTPAssertion, Assertion: edited}); err != nil {
		t.Fatal(err)
	}
	if view.Check.Calibrated(view.Digest()) || view.Digest() == digest {
		t.Fatal("an edited check kept its calibration")
	}
}

// SECURITY: an intrusive check runs only after a second person approved
// this exact version; a check that does not parse is never saved.
func TestRetestDB_CustomCheckGates(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	checks := fx.checkService()
	svc := fx.serviceWith(toolSensors{"nuclei": true, "templates:nuclei": true})
	svc.SetCheckSource(retestcheck.RetestSource{Svc: checks})
	f := fx.manualFinding(fx.asset)
	user := fx.user
	in := retestapp.RequestInput{TenantID: fx.tenant, FindingID: f, Trigger: retestdom.TriggerManual, RequestedBy: &user}

	if _, err := checks.Save(ctx, auditapp.AuditContext{}, fx.tenant, f, fx.user,
		retestcheck.Input{Kind: checkdom.KindNuclei, Content: "id: [broken"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("broken template saved: %v", err)
	}
	if v, _ := checks.Get(ctx, fx.tenant, f); v != nil {
		t.Fatal("a refused check was stored")
	}

	intrusive := `id: delete-probe
info:
  name: delete probe
  author: security-team
  severity: high
http:
  - method: DELETE
    path:
      - "{{BaseURL}}/api/items/1"
    matchers:
      - type: status
        status: [204]
`
	view, err := checks.Save(ctx, auditapp.AuditContext{}, fx.tenant, f, fx.user, retestcheck.Input{Kind: checkdom.KindNuclei, Content: intrusive})
	if err != nil {
		t.Fatal(err)
	}
	if view.Check.Tier != checkdom.TierT2 {
		t.Fatalf("tier %q", view.Check.Tier)
	}
	if _, err := svc.Request(ctx, in); !errors.Is(err, retestdom.ErrNotEligible) || !strings.Contains(err.Error(), "approved") {
		t.Fatalf("unapproved intrusive check: err = %v", err)
	}
	if can, _ := svc.CanRetest(ctx, fx.tenant, f); can {
		t.Fatal("CanRetest offers an unapproved intrusive check")
	}
	if _, err := checks.Approve(ctx, auditapp.AuditContext{}, fx.tenant, f, fx.user); !errors.Is(err, checkdom.ErrAuthorCannotApprove) {
		t.Fatalf("the author approved: %v", err)
	}
	if _, err := checks.Approve(ctx, auditapp.AuditContext{}, fx.tenant, f, shared.NewID()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Request(ctx, in); err != nil {
		t.Fatalf("approved intrusive check: %v", err)
	}
}

// SECURITY: tenant isolation of checks and of the templates they use.
func TestRetestDB_CustomCheckTenantIsolation(t *testing.T) {
	fx := newFixture(t)
	other := newFixture(t)
	ctx := context.Background()
	checks := fx.checkService()
	f := fx.manualFinding(fx.asset)
	view, err := checks.Save(ctx, auditapp.AuditContext{}, fx.tenant, f, fx.user,
		retestcheck.Input{Kind: checkdom.KindHTTPAssertion, Assertion: adminAssertion()})
	if err != nil {
		t.Fatal(err)
	}
	// The other tenant can neither read nor write a check on this finding.
	if _, err := checks.Get(ctx, other.tenant, f); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if _, err := checks.Save(ctx, auditapp.AuditContext{}, other.tenant, f, other.user,
		retestcheck.Input{Kind: checkdom.KindHTTPAssertion, Assertion: adminAssertion()}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant save: %v", err)
	}
	// Nor reuse this tenant's template on its own finding.
	of := other.manualFinding(other.asset)
	val, err := checks.Validate(ctx, other.tenant, of, retestcheck.Input{Kind: checkdom.KindNuclei, TemplateID: view.Template.ID.String()})
	if err != nil {
		t.Fatal(err)
	}
	if val.Valid {
		t.Fatal("another tenant's template was accepted")
	}
	// A template in use cannot be deleted from the library.
	if err := postgres.NewScannerTemplateRepository(fx.pg).Delete(ctx, fx.tenant, view.Template.ID); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("delete of a template in use: %v", err)
	}
	// Removing the check deletes the template made for it.
	if err := checks.Remove(ctx, auditapp.AuditContext{}, fx.tenant, f); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = fx.db.QueryRow(`SELECT COUNT(*) FROM scanner_templates WHERE id = $1`, view.Template.ID.String()).Scan(&n)
	if n != 0 {
		t.Fatal("the check's own template was left behind")
	}
}
