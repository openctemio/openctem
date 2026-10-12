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

// The breach notification is sent at max(high, finding severity), so the
// escalation query has to hand the finding's severity to the publisher. This
// runs the real UPDATE ... RETURNING against a migrated database.
func TestSLAEscalation_BreachEventCarriesFindingSeverity_DB(t *testing.T) {
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

	tenant := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'sla db test', $2)`,
		tenant.String(), "sla-"+tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tenant.String())
		_, _ = db.ExecContext(bg, `DELETE FROM assets WHERE tenant_id = $1`, tenant.String())
		_, _ = db.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tenant.String())
	})

	asset := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`,
		asset.String(), tenant.String(), "sla-"+asset.String()); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	want := map[string]string{}
	for _, sev := range []string{"critical", "medium"} {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, sla_deadline, sla_status)
			VALUES ($1, $2, $3, 'sca', 'test', 'msg', $4, $5, 'new', $6, 'on_track')`,
			id.String(), tenant.String(), asset.String(), sev, "fp-"+id.String(), time.Now().Add(-2*time.Hour)); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
		want[id.String()] = sev
	}

	c := NewSLAEscalationController(db, logger.NewNop())
	pub := &captureBreachPub{}
	c.SetBreachPublisher(pub)
	if _, err := c.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	got := 0
	for _, ev := range pub.events {
		sev, ok := want[ev.FindingID.String()]
		if !ok {
			continue // another test's rows
		}
		got++
		if ev.FindingSeverity != sev {
			t.Errorf("finding %s: event severity %q, want %q", ev.FindingID, ev.FindingSeverity, sev)
		}
	}
	if got != len(want) {
		t.Fatalf("got %d breach events for the seeded findings, want %d", got, len(want))
	}
}
