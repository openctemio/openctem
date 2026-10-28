package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// An owner whose account is blocked (users.status 'suspended') or erased is
// not a usable owner: the organization shows in "without owner", the list
// filter and the overview agree, and the super admin's owner recovery is
// allowed. A healthy owner, and an organization nobody touched, are
// unaffected. Requires DATABASE_URL.
func TestUsableOwner_BlockedOrErasedOwnerNeedsRecovery_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.Ping(); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	ctx := context.Background()
	db := &DB{DB: raw}
	orgs := NewAdminOrganizationRepository(db)
	tenants := NewTenantRepository(db)
	marker := "usable" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	org := func(suffix string) string {
		id := uuid.NewString()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id, marker+"-"+suffix)
		t.Cleanup(func() {
			for _, q := range []string{
				`DELETE FROM users WHERE id IN (SELECT user_id FROM tenant_members WHERE tenant_id = $1)`,
				`DELETE FROM tenant_members WHERE tenant_id = $1`,
				`DELETE FROM tenants WHERE id = $1`,
			} {
				_, _ = raw.ExecContext(ctx, q, id)
			}
		})
		return id
	}
	owner := func(tenantID string) string {
		uid := uuid.NewString()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Owner IT')`, uid, uid+"@it.test")
		exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role, status) VALUES ($1, $2, $3, 'owner', 'active')`,
			uuid.NewString(), uid, tenantID)
		return uid
	}

	healthy, blocked, erased := org("healthy"), org("blocked"), org("erased")
	owner(healthy)
	blockedOwner, erasedOwner := owner(blocked), owner(erased)

	noOwner := func() map[string]bool {
		t.Helper()
		got, _, err := orgs.ListOrganizations(ctx, admin.OrganizationFilter{Search: marker, Limit: 50, Owner: admin.OrganizationOwnerNone})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, o := range got {
			out[o.ID.String()] = true
		}
		return out
	}
	inOverview := func() map[string]bool {
		t.Helper()
		c, err := ReadAdminOverview(ctx, raw, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, o := range c.OrganizationsWithoutOwnerSample {
			out[o.ID] = true
		}
		return out
	}
	usable := func(id string) int {
		t.Helper()
		sid, _ := shared.IDFromString(id)
		n, err := orgs.CountUsableOwners(ctx, sid)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	presence := func(id string) tenant.OwnerPresence {
		t.Helper()
		sid, _ := shared.IDFromString(id)
		p, err := tenants.OwnerPresence(ctx, sid)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Before: every organization has a usable owner.
	if got := noOwner(); len(got) != 0 {
		t.Fatalf("owner=none before any block: %v", got)
	}
	for _, id := range []string{healthy, blocked, erased} {
		if usable(id) != 1 || !presence(id).Active || presence(id).AllSuspended() {
			t.Fatalf("%s: want one usable owner, count=%d presence=%+v", id, usable(id), presence(id))
		}
	}

	// Block one sole owner (what an administrator's block writes), erase the other.
	exec(`UPDATE users SET status = 'suspended', blocked_at = now() WHERE id = $1`, blockedOwner)
	exec(`UPDATE users SET erased_at = now() WHERE id = $1`, erasedOwner)

	got := noOwner()
	if len(got) != 2 || !got[blocked] || !got[erased] || got[healthy] {
		t.Fatalf("owner=none after: %v, want the blocked and the erased organization only", got)
	}
	sample := inOverview()
	if !sample[blocked] || !sample[erased] || sample[healthy] {
		t.Fatalf("overview without-owner sample: %v", sample)
	}
	for id, want := range map[string]int{healthy: 1, blocked: 0, erased: 0} {
		if usable(id) != want {
			t.Fatalf("usable owners of %s = %d, want %d", id, usable(id), want)
		}
	}
	// The owner is still there (it owns the data), but none can act: recovery
	// is allowed, a plain bootstrap is not.
	for _, id := range []string{blocked, erased} {
		p := presence(id)
		if !p.Any || p.Active || !p.AllSuspended() || p.BlocksBootstrap(false) != true || p.BlocksBootstrap(true) {
			t.Fatalf("presence of %s = %+v", id, p)
		}
	}
	// Blocking an owner in one organization never touches another.
	if p := presence(healthy); !p.Active {
		t.Fatalf("healthy organization lost its owner: %+v", p)
	}

	// Recovery creates the new owner in the blocked organization; it is
	// refused in the healthy one.
	newOwner := func(tenantID string) *tenant.Membership {
		uid := uuid.NewString()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'New owner')`, uid, uid+"@it.test")
		u, _ := shared.IDFromString(uid)
		tid, _ := shared.IDFromString(tenantID)
		m, err := tenant.NewMembership(u, tid, tenant.RoleOwner, nil)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if err := tenants.CreateFirstOwnerMembership(ctx, newOwner(healthy), true); !errors.Is(err, tenant.ErrOrganizationHasOwner) {
		t.Fatalf("recovery in an organization with a usable owner: %v", err)
	}
	if err := tenants.CreateFirstOwnerMembership(ctx, newOwner(blocked), false); !errors.Is(err, tenant.ErrOrganizationHasOwner) {
		t.Fatalf("plain bootstrap must still refuse while an owner exists: %v", err)
	}
	for _, id := range []string{blocked, erased} {
		if err := tenants.CreateFirstOwnerMembership(ctx, newOwner(id), true); err != nil {
			t.Fatalf("recovery of %s: %v", id, err)
		}
		if usable(id) != 1 || !presence(id).Active {
			t.Fatalf("%s after recovery: count=%d presence=%+v", id, usable(id), presence(id))
		}
	}
	if got := noOwner(); len(got) != 0 {
		t.Fatalf("owner=none after recovery: %v", got)
	}
}
