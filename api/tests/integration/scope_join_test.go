package integration

// Discovered names a permanent scope target or seed covers are confirmed
// (RFC-054 §4.3, owner decision S4 refined 2026-10-07), on a real database.

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func scopeJoin(db *sql.DB) *easmapp.ScopeJoin {
	pg := &postgres.DB{DB: db}
	j := easmapp.NewScopeJoin(scopeService(db), postgres.NewEASMSeedRepository(pg), scopeService(db),
		postgres.NewAttributionRepository(pg), postgres.NewAssetRepository(pg), logger.NewNop())
	j.SetAudit(auditapp.NewAuditService(postgres.NewAuditRepository(pg), logger.NewNop()))
	return j
}

func attributionState(t *testing.T, db *sql.DB, tenant, asset shared.ID) attribution.State {
	t.Helper()
	var st string
	if err := db.QueryRowContext(context.Background(),
		`SELECT state FROM asset_attributions WHERE tenant_id = $1 AND asset_id = $2`, tenant.String(), asset.String()).Scan(&st); err != nil {
		t.Fatalf("read attribution: %v", err)
	}
	return attribution.State(st)
}

func TestScopeJoin(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}

	// Tenant A declares *.join-a.example, the seed seeded-a.example and a
	// CIDR; an inactive target and an approved exclusion; a tombstone.
	seedScopeTarget(t, db, tenantA, "domain", "*.join-a.example")
	seedScopeTarget(t, db, tenantA, "cidr", "198.51.100.0/24")
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, 'domain', '*.paused-a.example', 'inactive')`, tenantA.String())
	exec(`INSERT INTO easm_seeds (id, tenant_id, kind, value) VALUES ($1, $2, 'root_domain', 'seeded-a.example')`, shared.NewID().String(), tenantA.String())
	exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_by, approved_at, created_by)
		VALUES ($1, 'domain', 'excl.join-a.example', 'not ours', 'active', 'approver', now(), 'requester')`, tenantA.String())
	exec(`INSERT INTO easm_tombstones (tenant_id, name) VALUES ($1, 'dead.join-a.example')`, tenantA.String())
	// A one-off (expiring) entry authorizes scanning only, never inventory.
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status, expires_at, reason) VALUES ($1, 'domain', '*.oneoff-a.example', 'active', now() + interval '1 day', 'one-off')`, tenantA.String())
	// Tenant B declares what tenant A does not.
	seedScopeTarget(t, db, tenantB, "domain", "*.join-b.example")

	pending := func(name, typ string) shared.ID {
		id := seedOwnedAsset(t, db, tenantA, name, typ)
		automatic(t, db, tenantA, id, attribution.StateNeedsReview)
		return id
	}
	apex := pending("join-a.example", "domain")
	sub := pending("api.join-a.example", "subdomain")
	seeded := pending("www.seeded-a.example", "subdomain")
	ipIn := pending("198.51.100.7", "ip_address")
	ipOut := pending("203.0.113.7", "ip_address")
	other := pending("other.example.net", "domain")
	paused := pending("app.paused-a.example", "subdomain")
	oneOff := pending("app.oneoff-a.example", "subdomain")
	excluded := pending("excl.join-a.example", "subdomain")
	tomb := pending("x.dead.join-a.example", "subdomain")
	foreign := pending("api.join-b.example", "subdomain")
	// A service follows its host, in every name form (stored host:port:proto,
	// reported host:port/proto); an address's service only through an IP entry.
	svcColon := pending("join-a.example:443:tcp", "service")
	svcSlash := pending("api.join-a.example:8443/tcp", "service")
	svcIPIn := pending("198.51.100.8:443:tcp", "service")
	svcIPOut := pending("203.0.113.8:443:tcp", "service")
	human := seedOwnedAsset(t, db, tenantA, "held.join-a.example", "subdomain")
	decide(t, db, tenantA, human, attribution.StateNeedsReview)
	// Tenant B's own pending name under tenant A's target.
	bName := seedOwnedAsset(t, db, tenantB, "api2.join-a.example", "subdomain")
	automatic(t, db, tenantB, bName, attribution.StateNeedsReview)

	join := scopeJoin(db)
	confirmed, err := join.Reevaluate(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(confirmed)
	// *.join-a.example covers its apex too (RFC-054 §4.1).
	want := []string{"198.51.100.7", "198.51.100.8:443:tcp", "api.join-a.example", "api.join-a.example:8443/tcp",
		"join-a.example", "join-a.example:443:tcp", "www.seeded-a.example"}
	if !slices.Equal(confirmed, want) {
		t.Fatalf("confirmed = %v, want %v", confirmed, want)
	}
	for _, id := range []shared.ID{apex, sub, seeded, ipIn, svcColon, svcSlash, svcIPIn} {
		if st := attributionState(t, db, tenantA, id); st != attribution.StateConfirmed {
			t.Errorf("%s = %s, want confirmed", id, st)
		}
	}
	for name, id := range map[string]shared.ID{
		"IP outside every IP entry": ipOut, "name outside everything": other, "under an inactive target": paused,
		"a service on an IP outside every IP entry": svcIPOut,
		"under an expiring (one-off) entry":         oneOff,
		"excluded":                                  excluded, "under a tombstone": tomb, "under another tenant's target": foreign,
		"a person's needs_review decision": human,
	} {
		if st := attributionState(t, db, tenantA, id); st != attribution.StateNeedsReview {
			t.Errorf("%s: %s, want needs_review", name, st)
		}
	}
	if st := attributionState(t, db, tenantB, bName); st != attribution.StateNeedsReview {
		t.Errorf("tenant B's name was confirmed by tenant A's scope target: %s", st)
	}

	// Audited once as a system decision in tenant A only.
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'asset.attribution_auto_confirmed' AND actor_id IS NULL`,
		tenantA.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("audit events in tenant A = %d (%v), want 1", n, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'asset.attribution_auto_confirmed'`,
		tenantB.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("audit events in tenant B = %d (%v), want 0", n, err)
	}

	// Idempotent: a second run confirms nothing and audits nothing.
	again, err := join.Reevaluate(ctx, tenantA)
	if err != nil || len(again) != 0 {
		t.Fatalf("second run = %v, %v; want nothing", again, err)
	}

	// The backfill entry point covers every tenant; B has nothing covered.
	if _, err := join.ReevaluateAll(ctx); err != nil {
		t.Fatal(err)
	}
	if st := attributionState(t, db, tenantB, bName); st != attribution.StateNeedsReview {
		t.Errorf("ReevaluateAll confirmed tenant B's name through tenant A's target: %s", st)
	}

	// Removing the scope target keeps the asset and its record but stops
	// active checks at once (out_of_scope).
	gate := ownershipGate(db)
	if b, err := gate.ActiveCheckBlocked(ctx, tenantA, []string{sub.String()}); err != nil || len(b) != 0 {
		t.Fatalf("confirmed covered asset blocked: %v %v", b, err)
	}
	exec(`DELETE FROM scope_targets WHERE tenant_id = $1 AND pattern = '*.join-a.example'`, tenantA.String())
	b, err := gate.ActiveCheckBlocked(ctx, tenantA, []string{sub.String()})
	if err != nil || b[sub.String()] != attribution.StateOutOfScope {
		t.Fatalf("after removing the target: %v %v, want out_of_scope", b, err)
	}
	if st := attributionState(t, db, tenantA, sub); st != attribution.StateConfirmed {
		t.Fatalf("the record changed on removal: %s", st)
	}
}
