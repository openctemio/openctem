package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The exposures stats card counts what the caller may list: a restricted
// member's numbers cover only exposures on in-scope assets (never the
// tenant's), a member without scope rows counts nothing, and another tenant's
// exposures are never counted. MTTR follows the same filter.
func TestExposureStats_FollowsDataScopeAndTenant(t *testing.T) {
	db := openStatsTestDB(t)
	ctx := context.Background()

	tenantID := seedTestTenant(ctx, t, db)
	otherTenant := seedTestTenant(ctx, t, db)
	visible := seedTestAsset(ctx, t, db, tenantID)
	hidden := seedTestAsset(ctx, t, db, tenantID)
	foreign := seedTestAsset(ctx, t, db, otherTenant)

	seed := func(tenant, asset shared.ID, eventType, severity, state, fp string) {
		t.Helper()
		resolved := "NULL"
		if state == "resolved" {
			resolved = "now()"
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO exposure_events
			(tenant_id, asset_id, event_type, severity, state, title, fingerprint, source, first_seen_at, last_seen_at, resolved_at)
			VALUES ($1, $2, $3, $4, $5, 'probe', $6, 'test', now() - interval '10 hours', now(), `+resolved+`)`,
			tenant.String(), asset.String(), eventType, severity, state, fp+tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	seed(tenantID, visible, "port_open", "medium", "active", "v1")
	seed(tenantID, visible, "port_open", "medium", "resolved", "v2")
	seed(tenantID, hidden, "credential_leaked", "critical", "active", "h1")
	seed(tenantID, hidden, "credential_leaked", "critical", "active", "h2")
	seed(otherTenant, foreign, "subdomain_takeover", "high", "active", "f1")

	scoped, empty := shared.NewID(), shared.NewID()
	for _, u := range []shared.ID{scoped, empty} {
		if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'expstats')`,
			u.String(), u.String()+"@exposure-stats.test"); err != nil {
			t.Fatal(err)
		}
		uid := u
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, uid.String()) })
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		scoped.String(), tenantID.String(), visible.String()); err != nil {
		t.Fatal(err)
	}

	repo := NewExposureRepository(&DB{DB: db})
	tid := tenantID.String()
	stats := func(scope *shared.DataScope) exposure.Stats {
		t.Helper()
		st, err := repo.Stats(ctx, exposure.Filter{TenantID: &tid, DataScope: scope})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	// Restricted member: only the visible asset's two port_open events.
	st := stats(&shared.DataScope{TenantID: tenantID, UserID: scoped})
	if st.ByState["active"] != 1 || st.ByState["resolved"] != 1 {
		t.Errorf("scoped by_state = %v, want active 1 resolved 1", st.ByState)
	}
	if st.BySeverity["critical"] != 0 || st.BySeverity["medium"] != 2 {
		t.Errorf("scoped by_severity = %v, want medium 2 and no critical (out of scope)", st.BySeverity)
	}
	if st.ByEventType["credential_leaked"] != 0 || st.ByEventType["port_open"] != 2 {
		t.Errorf("scoped by_event_type = %v, want port_open 2 only", st.ByEventType)
	}
	if !st.HasMTTR {
		t.Errorf("scoped MTTR missing: the in-scope resolved event has a timestamp")
	}

	// No scope rows: nothing, never the whole tenant.
	if st := stats(&shared.DataScope{TenantID: tenantID, UserID: empty}); len(st.ByState) != 0 || st.HasMTTR {
		t.Errorf("empty scope = %v (mttr %v), want nothing", st.ByState, st.HasMTTR)
	}

	// Unrestricted (owner/admin): the whole tenant, still not the other tenant.
	st = stats(nil)
	if st.ByState["active"] != 3 || st.ByState["resolved"] != 1 {
		t.Errorf("unscoped by_state = %v, want active 3 resolved 1", st.ByState)
	}
	if st.ByEventType["subdomain_takeover"] != 0 {
		t.Errorf("another tenant's exposure was counted: %v", st.ByEventType)
	}
}
