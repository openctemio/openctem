package controller

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type captureWarningPub struct{ events []SLAWarningEvent }

func (p *captureWarningPub) PublishWarning(_ context.Context, ev SLAWarningEvent) error {
	p.events = append(p.events, ev)
	return nil
}

// The governing SLA policy decides when a finding enters "warning"
// (warning_threshold_percent of its window) and whether anyone is told
// (escalation_enabled). Both used to be ignored: the warning fired at a fixed
// 3 days before the deadline and notifications went out regardless.
func TestSLAEscalation_HonoursPolicyThresholdAndEscalation_DB(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping SLA escalation DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	seedTenant := func(warnPct int, escalation bool) (shared.ID, shared.ID) {
		tenant := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'sla policy test', $2)`,
			tenant.String(), "slap-"+tenant.String()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		t.Cleanup(func() {
			bg := context.Background()
			_, _ = db.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tenant.String())
			_, _ = db.ExecContext(bg, `DELETE FROM assets WHERE tenant_id = $1`, tenant.String())
			_, _ = db.ExecContext(bg, `DELETE FROM sla_policies WHERE tenant_id = $1`, tenant.String())
			_, _ = db.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tenant.String())
		})
		if _, err := db.ExecContext(ctx, `INSERT INTO sla_policies (id, tenant_id, name, is_default, warning_threshold_percent, escalation_enabled)
			VALUES ($1, $2, 'default', TRUE, $3, $4)`, shared.NewID().String(), tenant.String(), warnPct, escalation); err != nil {
			t.Fatalf("seed policy: %v", err)
		}
		asset := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`,
			asset.String(), tenant.String(), "slap-"+asset.String()); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
		return tenant, asset
	}
	seedFinding := func(tenant, asset shared.ID, detectedAgo, deadlineIn time.Duration) shared.ID {
		id := shared.NewID()
		now := time.Now()
		if _, err := db.ExecContext(ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, first_detected_at, sla_deadline, sla_status)
			VALUES ($1, $2, $3, 'sca', 'test', 'msg', 'high', $4, 'new', $5, $6, 'on_track')`,
			id.String(), tenant.String(), asset.String(), "fp-"+id.String(), now.Add(-detectedAgo), now.Add(deadlineIn)); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
		return id
	}
	status := func(id shared.ID) string {
		var s string
		if err := db.QueryRowContext(ctx, `SELECT sla_status FROM findings WHERE id = $1`, id.String()).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	day := 24 * time.Hour
	// Tenant A: warn at 50 %, escalation on. 6 of 10 days elapsed, 4 left: the
	// old fixed 3-day window would not warn yet; the policy says warn.
	tA, aA := seedTenant(50, true)
	warnA := seedFinding(tA, aA, 6*day, 4*day)
	calmA := seedFinding(tA, aA, 2*day, 8*day) // 20 % elapsed: stays on track
	// Tenant B: warn at 90 %, escalation off. 23 h left of ~10 days: warned
	// but nobody is told; a breached one is marked overdue but not notified.
	tB, aB := seedTenant(90, false)
	warnB := seedFinding(tB, aB, 9*day+time.Hour, 23*time.Hour)
	breachB := seedFinding(tB, aB, 11*day, -time.Hour)

	c := NewSLAEscalationController(db, logger.NewNop())
	bp := &captureBreachPub{}
	wp := &captureWarningPub{}
	c.SetBreachPublisher(bp)
	c.SetWarningPublisher(wp)
	if _, err := c.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if s := status(warnA); s != "warning" {
		t.Errorf("tenant A 60%%-elapsed finding status = %q, want warning (policy threshold 50%%)", s)
	}
	if s := status(calmA); s != "on_track" {
		t.Errorf("tenant A 20%%-elapsed finding status = %q, want on_track", s)
	}
	if s := status(warnB); s != "warning" {
		t.Errorf("tenant B 90%%-elapsed finding status = %q, want warning", s)
	}
	if s := status(breachB); s != "overdue" {
		t.Errorf("tenant B breached finding status = %q, want overdue (status changes even with escalation off)", s)
	}

	warned := map[shared.ID]bool{}
	for _, ev := range wp.events {
		warned[ev.FindingID] = true
	}
	if !warned[warnA] {
		t.Error("tenant A warning not notified (escalation on)")
	}
	if warned[warnB] {
		t.Error("tenant B warning notified although its policy has escalation off")
	}
	for _, ev := range bp.events {
		if ev.FindingID == breachB {
			t.Error("tenant B breach notified although its policy has escalation off")
		}
	}
}
