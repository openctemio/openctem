package controller

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Both escalation queries leave held findings alone
// (docs/architecture/held-findings.md).
func TestEscalationQueries_SkipHeld(t *testing.T) {
	held := vulnerability.NotHeldSQL("f.verification_state")
	for name, q := range map[string]string{"breach": breachSelectUpdateQuery, "warning": warningSelectUpdateQuery} {
		if !strings.Contains(q, held) {
			t.Errorf("%s query must skip held findings with %q", name, held)
		}
	}
}

// A held finding past its deadline is not escalated; the same finding
// unchecked is.
func TestSLAEscalation_HeldFindingNotEscalated_DB(t *testing.T) {
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
	tenant, asset := shared.NewID(), shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'sla held test', $2)`,
		tenant.String(), "slaheld-"+tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, q := range []string{
			`DELETE FROM findings WHERE tenant_id = $1`,
			`DELETE FROM assets WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = db.ExecContext(bg, q, tenant.String())
		}
	})
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`,
		asset.String(), tenant.String(), "slaheld-"+asset.String()); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	seed := func(state, reasons string) shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status,
				sla_deadline, sla_status, verification_state, hold_reasons)
			VALUES ($1, $2, $3, 'dast', 'nuclei', 'msg', 'critical', $4, 'new', $5, 'on_track', $6, $7::text[])`,
			id.String(), tenant.String(), asset.String(), "fp-"+id.String(), time.Now().Add(-2*time.Hour), state, reasons); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
		return id
	}
	heldID := seed("held", "{target_throttled}")
	openID := seed("unchecked", "{}")

	c := NewSLAEscalationController(db, logger.NewNop())
	pub := &captureBreachPub{}
	c.SetBreachPublisher(pub)
	if _, err := c.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	seen := map[string]bool{}
	for _, ev := range pub.events {
		seen[ev.FindingID.String()] = true
	}
	if seen[heldID.String()] {
		t.Error("a held finding was escalated")
	}
	if !seen[openID.String()] {
		t.Error("the unchecked finding past its deadline was not escalated")
	}
	var st string
	if err := db.QueryRowContext(ctx, `SELECT sla_status FROM findings WHERE id = $1`, heldID.String()).Scan(&st); err != nil || st == "overdue" {
		t.Errorf("held finding sla_status %q (%v), want unchanged", st, err)
	}

	// Released (a later clean run sighted it again): escalated on the next
	// pass like any other finding past its deadline.
	if _, err := db.ExecContext(ctx, `UPDATE findings SET verification_state = 'unchecked', hold_reasons = '{}' WHERE id = $1`, heldID.String()); err != nil {
		t.Fatalf("release: %v", err)
	}
	pub.events = nil
	if _, err := c.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile after release: %v", err)
	}
	released := false
	for _, ev := range pub.events {
		released = released || ev.FindingID.String() == heldID.String()
	}
	if !released {
		t.Error("the released finding past its deadline was not escalated")
	}
}
