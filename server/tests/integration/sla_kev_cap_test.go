package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Known exploited deadline cap (docs/architecture/scoring-versions.md,
// "Known exploited deadline cap"), end to end through the KEV refresh: the
// priority pass tightens an open finding's deadline to now + cap when its CVE
// enters CISA KEV, marks it, writes a kev_cap timeline entry, never extends
// it afterwards, and leaves another tenant's finding of the same CVE alone
// when that tenant turned the cap off.
func TestSLAKEVCap_LateKEVTightensAndMarks(t *testing.T) {
	fx := newScoringFixture(t)
	fx.withSLA(t)
	ctx := context.Background()
	ta, tb := fx.newTenant(t), fx.newTenant(t)
	t.Cleanup(func() {
		_, _ = fx.db.Exec(`DELETE FROM sla_policies WHERE tenant_id = ANY($1::uuid[])`, "{"+ta.String()+","+tb.String()+"}")
	})
	// Every window 90 days, P1 included: the exploitation floor (KEV => P1)
	// alone does not bring the deadline under two weeks.
	fx.setDefaultPolicy(t, ta, 90)
	fx.setDefaultPolicy(t, tb, 90)
	if _, err := fx.db.Exec(`UPDATE sla_policies SET kev_cap_days = 0 WHERE tenant_id = $1`, tb.String()); err != nil {
		t.Fatal(err)
	}
	sfx := strings.ToUpper(strings.ReplaceAll(uuid.NewString()[:8], "-", ""))
	cve := "CVE-2097-" + sfx
	t.Cleanup(func() { _, _ = fx.db.Exec(`DELETE FROM kev_catalog WHERE cve_id = $1`, cve) })

	aid := fx.newAsset(t, ta, "github.com/acme/kev-cap")
	fid := fx.newFinding(t, ta, aid, vulnerability.SeverityLow, "kev-cap")
	baid := fx.newAsset(t, tb, "github.com/acme/kev-cap-off")
	bfid := fx.newFinding(t, tb, baid, vulnerability.SeverityLow, "kev-cap-off")
	far := time.Now().Add(80 * 24 * time.Hour).UTC().Truncate(time.Second)
	for _, x := range [][2]string{{ta.String(), fid.String()}, {tb.String(), bfid.String()}} {
		if _, err := fx.db.Exec(`UPDATE findings SET cve_id = $3, is_in_kev = false, sla_deadline = $4
			WHERE tenant_id = $1 AND id = $2`, x[0], x[1], cve, far); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fx.db.Exec(`DELETE FROM finding_activities WHERE tenant_id = ANY($1::uuid[])`, "{"+ta.String()+","+tb.String()+"}"); err != nil {
		t.Fatal(err)
	}

	// CISA adds the CVE; the KEV refresh queues both assets.
	if _, err := fx.db.Exec(`INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added, known_ransomware_campaign_use)
		VALUES ($1, 'IT', CURRENT_DATE, 'Known')`, cve); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.scoring.EnqueueIntelChanges(ctx); err != nil {
		t.Fatal(err)
	}
	fx.drain(t, aid, baid)

	var deadline time.Time
	var capped, kev bool
	if err := fx.db.QueryRow(`SELECT sla_deadline, sla_kev_capped, is_in_kev FROM findings WHERE tenant_id = $1 AND id = $2`,
		ta.String(), fid.String()).Scan(&deadline, &capped, &kev); err != nil {
		t.Fatal(err)
	}
	if !kev || !capped || !near(deadline, time.Now().Add(14*24*time.Hour)) {
		t.Fatalf("after KEV: kev=%v capped=%v deadline=%v, want KEV, marked, now + 14 days", kev, capped, deadline)
	}
	if got := fx.tightenings(t, ta, fid); len(got) != 1 || got[0] != "kev_cap" {
		t.Fatalf("timeline = %v, want [kev_cap]", got)
	}

	// The tenant that turned the cap off keeps its class window (P1 = 90
	// days from now is later than the stored deadline: kept).
	var bDeadline time.Time
	var bCapped bool
	if err := fx.db.QueryRow(`SELECT sla_deadline, sla_kev_capped FROM findings WHERE tenant_id = $1 AND id = $2`,
		tb.String(), bfid.String()).Scan(&bDeadline, &bCapped); err != nil {
		t.Fatal(err)
	}
	if bCapped || !bDeadline.Equal(far) {
		t.Fatalf("cap off: capped=%v deadline=%v, want unmarked and kept at %v", bCapped, bDeadline, far)
	}

	// A later pass (and a longer cap) never moves the capped deadline.
	if _, err := fx.db.Exec(`UPDATE sla_policies SET kev_cap_days = 60 WHERE tenant_id = $1`, ta.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.db.Exec(`INSERT INTO finding_priority_queue (asset_id, tenant_id, reason) VALUES ($1, $2, 'intel')
		ON CONFLICT (asset_id) DO NOTHING`, aid.String(), ta.String()); err != nil {
		t.Fatal(err)
	}
	fx.drain(t, aid)
	var again time.Time
	if err := fx.db.QueryRow(`SELECT sla_deadline, sla_kev_capped FROM findings WHERE tenant_id = $1 AND id = $2`,
		ta.String(), fid.String()).Scan(&again, &capped); err != nil {
		t.Fatal(err)
	}
	if !again.Equal(deadline) || !capped {
		t.Fatalf("later pass: deadline=%v capped=%v, want kept at %v and marked", again, capped, deadline)
	}

	// The tighten-only guard keeps the flag with the deadline it keeps: a
	// writer holding an older copy (later deadline, flag false) changes
	// neither.
	if _, err := fx.db.Exec(`UPDATE findings SET sla_deadline = $3, sla_kev_capped = false WHERE tenant_id = $1 AND id = $2`,
		ta.String(), fid.String(), far); err != nil {
		t.Fatal(err)
	}
	if err := fx.db.QueryRow(`SELECT sla_deadline, sla_kev_capped FROM findings WHERE tenant_id = $1 AND id = $2`,
		ta.String(), fid.String()).Scan(&again, &capped); err != nil {
		t.Fatal(err)
	}
	if !again.Equal(deadline) || !capped {
		t.Fatalf("guard: deadline=%v capped=%v, want kept at %v and marked", again, capped, deadline)
	}
}

// The ingest upsert keeps the flag with the deadline it keeps.
func TestSLAKEVCap_UpsertKeepsFlagWithDeadline(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/kev-cap-upsert")
	ctx := context.Background()
	fp := "kev-cap-upsert-" + aid.String()[:8]

	mk := func(deadline time.Time, capped bool) *vulnerability.Finding {
		f, err := vulnerability.NewFinding(tid, aid, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh, "kev-cap-upsert")
		if err != nil {
			t.Fatal(err)
		}
		f.SetFingerprint(fp)
		if capped {
			f.SetSLADeadlineKEVCapped(deadline)
		} else {
			f.SetSLADeadline(deadline)
		}
		return f
	}
	read := func() (time.Time, bool) {
		t.Helper()
		var d time.Time
		var c bool
		if err := fx.db.QueryRow(`SELECT sla_deadline, sla_kev_capped FROM findings WHERE tenant_id = $1 AND fingerprint = $2`,
			tid.String(), fp).Scan(&d, &c); err != nil {
			t.Fatal(err)
		}
		return d, c
	}
	first := time.Now().Add(14 * 24 * time.Hour).UTC().Truncate(time.Second)
	if _, err := fx.findings.CreateBatchWithResult(ctx, []*vulnerability.Finding{mk(first, true)}); err != nil {
		t.Fatal(err)
	}
	if d, c := read(); !d.Equal(first) || !c {
		t.Fatalf("insert: deadline=%v capped=%v, want %v marked", d, c, first)
	}
	// A later deadline (unmarked) keeps both.
	if _, err := fx.findings.CreateBatchWithResult(ctx, []*vulnerability.Finding{mk(first.Add(30*24*time.Hour), false)}); err != nil {
		t.Fatal(err)
	}
	if d, c := read(); !d.Equal(first) || !c {
		t.Fatalf("later upsert: deadline=%v capped=%v, want %v marked", d, c, first)
	}
	// A shorter unmarked one replaces both.
	shorter := first.Add(-7 * 24 * time.Hour)
	if _, err := fx.findings.CreateBatchWithResult(ctx, []*vulnerability.Finding{mk(shorter, false)}); err != nil {
		t.Fatal(err)
	}
	if d, c := read(); !d.Equal(shorter) || c {
		t.Fatalf("shorter upsert: deadline=%v capped=%v, want %v unmarked", d, c, shorter)
	}
}
