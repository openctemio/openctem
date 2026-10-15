package integration

import (
	"context"
	"strings"
	"testing"

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
		if _, err := fx.db.Exec(`INSERT INTO epss_scores (cve_id, epss_score, percentile, score_date) VALUES ($1, $2, 0.9, CURRENT_DATE)`, c, v); err != nil {
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
