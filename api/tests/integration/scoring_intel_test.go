package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Intel updates recompute only the findings whose CVE changed in a way a
// model can see (docs/architecture/scoring-versions.md, "Intel updates"):
// an EPSS threshold of the classifier or of the tenant's own rules crossed,
// or KEV membership changed. Never the whole tenant, never closed findings,
// never another tenant's rule thresholds.
func TestScoringIntel_OnlyChangedCVEsAreQueued(t *testing.T) {
	fx := newScoringFixture(t)
	ctx := context.Background()
	ta, tb := fx.newTenant(t), fx.newTenant(t)
	sfx := strings.ToUpper(strings.ReplaceAll(uuid.NewString()[:8], "-", ""))
	cve := func(n string) string { return "CVE-2099-" + sfx + n }
	t.Cleanup(func() {
		_, _ = fx.db.Exec(`DELETE FROM epss_scores WHERE cve_id LIKE $1`, "CVE-2099-"+sfx+"%")
		_, _ = fx.db.Exec(`DELETE FROM kev_catalog WHERE cve_id LIKE $1`, "CVE-2099-"+sfx+"%")
	})

	type row struct {
		tenant shared.ID
		name   string
		cve    string
		stored float64
		status string
	}
	rows := []row{
		{ta, "crosses", cve("1"), 0.05, "new"},       // 0.05 -> 0.60 crosses 0.1 and 0.5
		{ta, "drifts", cve("2"), 0.20, "new"},        // 0.20 -> 0.21 crosses nothing
		{ta, "kev", cve("3"), 0.0, "new"},            // enters KEV
		{ta, "closed", cve("1"), 0.05, "resolved"},   // closed: frozen
		{ta, "rulethreshold", cve("5"), 0.25, "new"}, // 0.25 -> 0.35 crosses A's rule at 0.3
		{tb, "otherrule", cve("5"), 0.25, "new"},     // B has no rule at 0.3
	}
	assets := map[string]shared.ID{}
	for _, r := range rows {
		aid := fx.newAsset(t, r.tenant, "github.com/acme/intel-"+r.name)
		assets[r.name] = aid
		fid := fx.newFinding(t, r.tenant, aid, vulnerability.SeverityMedium, "intel-"+r.name)
		if _, err := fx.db.Exec(`UPDATE findings SET cve_id = $3, epss_score = $4, is_in_kev = false, status = $5
			WHERE tenant_id = $1 AND id = $2`, r.tenant.String(), fid.String(), r.cve, r.stored, r.status); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fx.db.Exec(`INSERT INTO priority_override_rules (tenant_id, name, description, priority_class, conditions, is_active)
		VALUES ($1, 'epss 0.3', '', 'P1', '[{"field":"epss_score","operator":"gte","value":0.3}]'::jsonb, true)`, ta.String()); err != nil {
		t.Fatal(err)
	}
	for _, aid := range assets {
		fx.drain(t, aid)
	}
	// The drain re-read the (empty) catalogs; put the stored values back.
	for _, r := range rows {
		if _, err := fx.db.Exec(`UPDATE findings SET epss_score = $3, is_in_kev = false WHERE tenant_id = $1 AND asset_id = $2`,
			r.tenant.String(), assets[r.name].String(), r.stored); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = fx.db.Exec(`DELETE FROM finding_priority_queue WHERE tenant_id = ANY($1::uuid[])`, "{"+ta.String()+","+tb.String()+"}")

	// The daily feeds arrive.
	for c, v := range map[string]float64{cve("1"): 0.60, cve("2"): 0.21, cve("5"): 0.35} {
		if _, err := fx.db.Exec(`INSERT INTO epss_scores (cve_id, epss_score) VALUES ($1, $2)`, c, v); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fx.db.Exec(`INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added) VALUES ($1, 'IT', CURRENT_DATE)`, cve("3")); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.scoring.EnqueueIntelChanges(ctx); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"crosses": true, "kev": true, "rulethreshold": true}
	for name, aid := range assets {
		if got := fx.queued(t, aid); got != want[name] {
			t.Errorf("%s: queued = %v, want %v", name, got, want[name])
		}
	}

	// The worker applies the intel; a second refresh with the same feeds
	// queues nothing.
	for name := range want {
		fx.drain(t, assets[name])
	}
	if _, err := fx.scoring.EnqueueIntelChanges(ctx); err != nil {
		t.Fatal(err)
	}
	for name, aid := range assets {
		if fx.queued(t, aid) {
			t.Errorf("%s: queued again by an unchanged feed", name)
		}
	}
}

// The stored EPSS follows the catalog for every changed CVE of an open
// finding, not only threshold crossings: the CI gate judges the stored score
// against the policy's own epss_threshold. 0.2 -> 0.4 crosses no model
// threshold, but a gate at 0.3 now blocks. Closed findings and other
// tenants' findings of other CVEs are not written.
func TestScoringIntel_StoredEPSSFeedsTheCIGate(t *testing.T) {
	fx := newScoringFixture(t)
	ctx := context.Background()
	ta, tb := fx.newTenant(t), fx.newTenant(t)
	sfx := strings.ToUpper(strings.ReplaceAll(uuid.NewString()[:8], "-", ""))
	cve := "CVE-2098-" + sfx
	t.Cleanup(func() { _, _ = fx.db.Exec(`DELETE FROM epss_scores WHERE cve_id = $1`, cve) })

	aid := fx.newAsset(t, ta, "github.com/acme/intel-gate")
	open := fx.newFinding(t, ta, aid, vulnerability.SeverityMedium, "intel-gate-open")
	closed := fx.newFinding(t, ta, aid, vulnerability.SeverityMedium, "intel-gate-closed")
	baid := fx.newAsset(t, tb, "github.com/acme/intel-gate-b")
	other := fx.newFinding(t, tb, baid, vulnerability.SeverityMedium, "intel-gate-other")
	fx.drain(t, aid, baid)
	set := func(tid, id shared.ID, c string, v float64, status string) {
		t.Helper()
		if _, err := fx.db.Exec(`UPDATE findings SET cve_id = $3, epss_score = $4, epss_percentile = 0.5, status = $5
			WHERE tenant_id = $1 AND id = $2`, tid.String(), id.String(), c, v, status); err != nil {
			t.Fatal(err)
		}
	}
	set(ta, open, cve, 0.2, "new")
	set(ta, closed, cve, 0.2, "resolved")
	set(tb, other, "CVE-2098-"+sfx+"X", 0.2, "new")
	if _, err := fx.db.Exec(`INSERT INTO epss_scores (cve_id, epss_score) VALUES ($1, 0.4)`, cve); err != nil {
		t.Fatal(err)
	}
	// Setting the CVE queues the asset (a classifier input); the test is about
	// the refresh, so start from an empty queue without running the worker.
	if _, err := fx.db.Exec(`DELETE FROM finding_priority_queue WHERE asset_id IN ($1, $2)`, aid.String(), baid.String()); err != nil {
		t.Fatal(err)
	}

	ci := postgres.NewCIRunRepository(&postgres.DB{DB: fx.db})
	thr := 0.3
	policy := cirun.DefaultGatePolicy()
	policy.FailOnSeverity = "critical"
	policy.EPSSThreshold = &thr
	verdict := func() cirun.GateVerdict {
		t.Helper()
		fs, err := ci.FindingsByFingerprints(ctx, ta, aid, []string{"intel-gate-open-" + aid.String()[:8]})
		if err != nil || len(fs) != 1 {
			t.Fatalf("gate findings = %v, %v", fs, err)
		}
		return cirun.Evaluate(cirun.GateInput{Policy: policy, Findings: fs})
	}
	if v := verdict(); v.Verdict == cirun.VerdictFail {
		t.Fatalf("before the refresh the gate already fails: %+v", v.Reasons)
	}

	// The daily refresh: no model threshold crossed (nothing queued for this
	// finding), but the stored score follows the catalog.
	if _, err := fx.scoring.EnqueueIntelChanges(ctx); err != nil {
		t.Fatal(err)
	}
	if fx.queued(t, aid) {
		t.Fatal("0.2 -> 0.4 crosses no model threshold, yet the asset was queued")
	}
	if _, err := fx.scoring.RefreshFindingEPSS(ctx); err != nil {
		t.Fatal(err)
	}
	if v := verdict(); v.Verdict != cirun.VerdictFail || len(v.Reasons) == 0 || v.Reasons[0].Code != cirun.ReasonEPSS {
		t.Fatalf("after the refresh the gate = %+v, want a failure for EPSS", v)
	}
	score := func(tid, id shared.ID) (float64, float64) {
		t.Helper()
		var s, p float64
		if err := fx.db.QueryRow(`SELECT epss_score, epss_percentile FROM findings WHERE tenant_id = $1 AND id = $2`,
			tid.String(), id.String()).Scan(&s, &p); err != nil {
			t.Fatal(err)
		}
		return s, p
	}
	if s, p := score(ta, open); s != 0.4 || p != 0.5 {
		t.Fatalf("open finding epss = %v / %v, want 0.4 / 0.5 (score refreshed, percentile left as scored)", s, p)
	}
	if s, _ := score(ta, closed); s != 0.2 {
		t.Fatalf("closed finding epss = %v, want kept at 0.2", s)
	}
	if s, _ := score(tb, other); s != 0.2 {
		t.Fatalf("other tenant's finding (another CVE) epss = %v, want 0.2", s)
	}
	// A second run writes nothing.
	if n, err := fx.scoring.RefreshFindingEPSS(ctx); err != nil || n != 0 {
		t.Fatalf("second refresh wrote %d rows (%v), want 0", n, err)
	}
}
