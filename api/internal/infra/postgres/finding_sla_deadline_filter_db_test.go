package postgres

import (
	"context"
	"net/url"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// The SLA page counts breached findings by how long they have been past due
// with the same filter the Findings page runs: sla_status plus a range on
// sla_deadline. Every bucket is a stats read over the caller's findings, so
// the buckets add up to the breach total and a restricted caller or another
// tenant never changes them. Skipped unless DATABASE_URL is set.

func TestStatsBySpec_SLADeadlineBuckets(t *testing.T) {
	db := openStatsTestDB(t)
	ctx := context.Background()
	tenantID := seedTestTenant(ctx, t, db)
	visible := seedTestAsset(ctx, t, db, tenantID)
	hidden := seedTestAsset(ctx, t, db, tenantID)

	seed := func(tenant, asset shared.ID, status, sla string, daysPast float64) {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO findings
			   (id, tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint, sla_status, sla_deadline)
			 VALUES ($1, $2, $3, 'sca', 'sla-bucket', 'probe', 'high', $4, $5, $6, NOW() - make_interval(secs => $7))`,
			id.String(), tenant.String(), asset.String(), status, "sla-b-"+id.String(), sla, daysPast*86400); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// Breached, open: 2 within a week, 1 in 8-30, 1 in 31-90, 1 over 90.
	seed(tenantID, visible, "new", "overdue", 2)
	seed(tenantID, visible, "confirmed", "exceeded", 6)
	seed(tenantID, visible, "in_progress", "overdue", 15)
	seed(tenantID, visible, "new", "exceeded", 45)
	seed(tenantID, hidden, "new", "overdue", 120) // outside the restricted caller's scope
	// Not counted: closed, a pentest draft, and on-track.
	seed(tenantID, visible, "resolved", "overdue", 3)
	seed(tenantID, visible, "draft", "overdue", 3)
	seed(tenantID, visible, "new", "on_track", -5)
	// Another tenant.
	other := seedTestTenant(ctx, t, db)
	seed(other, seedTestAsset(ctx, t, db, other), "new", "overdue", 3)

	userID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'sla-bucket')`,
		userID.String(), userID.String()+"@sla-bucket.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, userID.String())
	})
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		userID.String(), tenantID.String(), visible.String()); err != nil {
		t.Fatalf("seed access: %v", err)
	}

	repo := NewFindingRepository(&DB{DB: db})
	count := func(actor filterspec.Actor, q string) int64 {
		t.Helper()
		v, err := url.ParseQuery("state=open&sla_status=overdue,exceeded&" + q)
		if err != nil {
			t.Fatal(err)
		}
		spec, err := filterspec.ParseValues(v, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict})
		if err != nil {
			t.Fatalf("parse %q: %v", q, err)
		}
		where, err := filterspec.Compile(spec, vulnerability.FindingFields, actor)
		if err != nil {
			t.Fatalf("compile %q: %v", q, err)
		}
		stats, err := repo.GetStatsWhere(ctx, where)
		if err != nil {
			t.Fatalf("stats %q: %v", q, err)
		}
		return stats.Total
	}

	admin, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tenantID, UserID: shared.NewID(), IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	buckets := []struct {
		name, q string
		want    int64
	}{
		{"all breached", "", 5},
		{"up to 7 days", "sla_deadline_gt=-P7D", 2},
		{"8-30 days", "sla_deadline_lte=-P7D&sla_deadline_gt=-P30D", 1},
		{"31-90 days", "sla_deadline_lte=-P30D&sla_deadline_gt=-P90D", 1},
		{"over 90 days", "sla_deadline_lte=-P90D", 1},
	}
	var sum int64
	for _, b := range buckets {
		if got := count(admin, b.q); got != b.want {
			t.Errorf("admin %s = %d, want %d", b.name, got, b.want)
		}
		if b.q != "" {
			sum += b.want
		}
	}
	if sum != 5 {
		t.Fatalf("test buckets must add up to the total, got %d", sum)
	}

	restricted, err := filterspec.UserActor(filterspec.UserActorInput{
		TenantID: tenantID, UserID: userID, Scope: &shared.DataScope{TenantID: tenantID, UserID: userID}})
	if err != nil {
		t.Fatal(err)
	}
	if got := count(restricted, ""); got != 4 {
		t.Errorf("restricted total = %d, want 4 (the hidden asset's finding is not counted)", got)
	}
	if got := count(restricted, "sla_deadline_lte=-P90D"); got != 0 {
		t.Errorf("restricted over-90 bucket = %d, want 0", got)
	}
}

// One breakdown read returns the standing tiles and the past-due age buckets
// over the caller's findings: the buckets add up to the past-due total, and
// neither another tenant nor an asset outside the caller's data scope changes
// any number.
func TestSLABreakdownWhere_BucketsAddUpAndStayInScope(t *testing.T) {
	db := openStatsTestDB(t)
	ctx := context.Background()
	tenantID := seedTestTenant(ctx, t, db)
	visible := seedTestAsset(ctx, t, db, tenantID)
	hidden := seedTestAsset(ctx, t, db, tenantID)

	seed := func(tenant, asset shared.ID, status, sla, sev string, daysPast float64) {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO findings
			   (id, tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint, sla_status, sla_deadline)
			 VALUES ($1, $2, $3, 'sca', 'sla-breakdown', 'probe', $4, $5, $6, $7, NOW() - make_interval(secs => $8))`,
			id.String(), tenant.String(), asset.String(), sev, status, "sla-d-"+id.String(), sla, daysPast*86400); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seed(tenantID, visible, "new", "overdue", "critical", 2)
	seed(tenantID, visible, "confirmed", "exceeded", "high", 6)
	seed(tenantID, visible, "in_progress", "overdue", "high", 15)
	seed(tenantID, visible, "new", "exceeded", "low", 45)
	seed(tenantID, hidden, "new", "overdue", "critical", 120) // outside the restricted caller's scope
	seed(tenantID, visible, "new", "warning", "medium", -1)
	seed(tenantID, visible, "new", "on_track", "medium", -5)
	seed(tenantID, visible, "new", "on_track", "medium", -6)
	seed(tenantID, visible, "resolved", "overdue", "high", 3) // closed: not in the Open lens
	other := seedTestTenant(ctx, t, db)
	seed(other, seedTestAsset(ctx, t, db, other), "new", "overdue", "critical", 3)

	userID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'sla-breakdown')`,
		userID.String(), userID.String()+"@sla-breakdown.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, userID.String())
	})
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		userID.String(), tenantID.String(), visible.String()); err != nil {
		t.Fatalf("seed access: %v", err)
	}

	repo := NewFindingRepository(&DB{DB: db})
	breakdown := func(actor filterspec.Actor) *vulnerability.SLABreakdown {
		t.Helper()
		v, _ := url.ParseQuery("state=open")
		spec, err := filterspec.ParseValues(v, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict})
		if err != nil {
			t.Fatal(err)
		}
		where, err := filterspec.Compile(spec, vulnerability.FindingFields, actor)
		if err != nil {
			t.Fatal(err)
		}
		b, err := repo.GetSLABreakdownWhere(ctx, where)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sum := func(b *vulnerability.SLABreakdown) int64 { return b.UpTo7 + b.D8to30 + b.D31to90 + b.Over90 }

	admin, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tenantID, UserID: shared.NewID(), IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	b := breakdown(admin)
	if b.Total != 8 || b.PastDue != 5 || b.DueSoon != 1 || b.OnTrack != 2 {
		t.Errorf("admin tiles = total %d past %d soon %d ok %d, want 8/5/1/2", b.Total, b.PastDue, b.DueSoon, b.OnTrack)
	}
	if b.UpTo7 != 2 || b.D8to30 != 1 || b.D31to90 != 1 || b.Over90 != 1 || sum(b) != b.PastDue {
		t.Errorf("admin buckets = %d/%d/%d/%d, want 2/1/1/1 adding up to %d", b.UpTo7, b.D8to30, b.D31to90, b.Over90, b.PastDue)
	}
	if b.PastDueBySeverity[vulnerability.SeverityCritical] != 2 || b.PastDueBySeverity[vulnerability.SeverityHigh] != 2 {
		t.Errorf("admin past-due by severity = %v", b.PastDueBySeverity)
	}

	restricted, err := filterspec.UserActor(filterspec.UserActorInput{
		TenantID: tenantID, UserID: userID, Scope: &shared.DataScope{TenantID: tenantID, UserID: userID}})
	if err != nil {
		t.Fatal(err)
	}
	r := breakdown(restricted)
	if r.PastDue != 4 || r.Over90 != 0 || sum(r) != r.PastDue || r.Total != 7 {
		t.Errorf("restricted = total %d past %d over90 %d sum %d, want 7/4/0/4 (hidden asset and other tenant excluded)", r.Total, r.PastDue, r.Over90, sum(r))
	}
	if r.PastDueBySeverity[vulnerability.SeverityCritical] != 1 {
		t.Errorf("restricted critical = %d, want 1", r.PastDueBySeverity[vulnerability.SeverityCritical])
	}
}
