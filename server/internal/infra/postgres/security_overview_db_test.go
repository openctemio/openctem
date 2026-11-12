package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/securityoverview"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The security overview counts are tenant-scoped and their windows have exact
// edges: 89 days is fresh, 91 days is stale. Requires DATABASE_URL.
func TestSecurityOverviewCounts_WindowsAndTenantIsolation(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewSecurityOverviewRepository(&DB{DB: sqlDB})
	a := seedTestTenant(ctx, t, sqlDB)
	b := seedTestTenant(ctx, t, sqlDB)
	now := time.Now().UTC().Truncate(time.Second)
	day := 24 * time.Hour
	ago := func(d time.Duration) time.Time { return now.Add(-d) }

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		roleOwner  = "00000000-0000-0000-0000-000000000001"
		roleAdmin  = "00000000-0000-0000-0000-000000000002"
		roleMember = "00000000-0000-0000-0000-000000000003"
	)
	// member adds a user and a membership. kind is 'person' or 'service';
	// provider 'local' or an identity provider.
	member := func(tenant shared.ID, role, roleID, provider, kind string, lastLogin *time.Time, joined time.Time, mfa bool, status string) shared.ID {
		t.Helper()
		id := shared.NewID()
		var svcTenant any
		if kind == "service" {
			svcTenant = tenant.String()
		}
		exec(`INSERT INTO users (id, email, name, auth_provider, kind, service_tenant_id, last_login_at) VALUES ($1, $2, 'so', $3, $4, $5, $6)`,
			id.String(), id.String()+"@so.example.com", provider, kind, svcTenant, lastLogin)
		exec(`INSERT INTO tenant_members (user_id, tenant_id, role, status, joined_at) VALUES ($1, $2, $3, $4, $5)`,
			id.String(), tenant.String(), role, status, joined)
		exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, id.String(), tenant.String(), roleID)
		if mfa {
			exec(`INSERT INTO user_mfa (user_id, enabled) VALUES ($1, true)`, id.String())
		}
		return id
	}
	lt := func(d time.Duration) *time.Time { x := ago(d); return &x }

	// Tenant A: admins. Counted: owner and admin with a local account and no
	// second factor. Not counted: with 2FA, via an identity provider,
	// suspended, a plain member.
	member(a, "owner", roleOwner, "local", "person", lt(1*day), ago(200*day), false, "active")
	member(a, "admin", roleAdmin, "local", "person", lt(1*day), ago(200*day), false, "active")
	member(a, "admin", roleAdmin, "local", "person", lt(1*day), ago(200*day), true, "active")
	member(a, "admin", roleAdmin, "saml", "person", lt(1*day), ago(200*day), false, "active")
	member(a, "admin", roleAdmin, "local", "person", lt(1*day), ago(200*day), false, "suspended")
	member(a, "member", roleMember, "local", "person", lt(1*day), ago(200*day), false, "active")
	// Dormant: signed in 91 days ago (counted), 89 (not), never signed in
	// and joined 31 days ago (counted), joined 29 days ago (not), a service
	// account that never signed in (not), a suspended member (not).
	member(a, "member", roleMember, "local", "person", lt(91*day), ago(300*day), true, "active")
	member(a, "member", roleMember, "local", "person", lt(89*day), ago(300*day), true, "active")
	member(a, "member", roleMember, "local", "person", nil, ago(31*day), true, "active")
	member(a, "member", roleMember, "local", "person", nil, ago(29*day), true, "active")
	member(a, "member", roleMember, "local", "service", nil, ago(300*day), true, "active")
	member(a, "member", roleMember, "local", "person", lt(200*day), ago(300*day), true, "suspended")
	// Tenant B has one of everything bad; none of it may reach tenant A.
	member(b, "owner", roleOwner, "local", "person", nil, ago(300*day), false, "active")

	// Join requests: pending and live (counted); decided, expired (not).
	req := func(tenant shared.ID, status string, expires time.Time) {
		u := shared.NewID()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'jr')`, u.String(), u.String()+"@jr.example.com")
		exec(`INSERT INTO organization_join_requests (tenant_id, user_id, status, expires_at) VALUES ($1, $2, $3, $4)`,
			tenant.String(), u.String(), status, expires)
	}
	req(a, "pending", now.Add(5*day))
	req(a, "approved", now.Add(5*day))
	req(a, "pending", ago(1*day))
	req(b, "pending", now.Add(5*day))

	// API keys.
	key := func(tenant shared.ID, status string, expires *time.Time, lastUsed *time.Time, created time.Time) {
		id := shared.NewID()
		exec(`INSERT INTO api_keys (tenant_id, name, key_hash, key_prefix, status, expires_at, last_used_at, created_at)
			VALUES ($1, $2, $2, 'ctem_x', $3, $4, $5, $6)`,
			tenant.String(), id.String(), status, expires, lastUsed, created)
	}
	exp := func(d time.Duration) *time.Time { x := now.Add(d); return &x }
	key(a, "active", exp(13*day), lt(1*day), ago(10*day)) // expiring (counted)
	key(a, "active", exp(15*day), lt(1*day), ago(10*day)) // later (not)
	key(a, "active", nil, lt(1*day), ago(10*day))         // no expiry (not)
	key(a, "revoked", exp(3*day), lt(1*day), ago(10*day)) // revoked (not)
	key(a, "active", nil, nil, ago(31*day))               // never used, old (unused)
	key(a, "active", nil, nil, ago(29*day))               // never used, new (not)
	key(a, "active", nil, lt(91*day), ago(300*day))       // stale (unused)
	key(a, "active", nil, lt(89*day), ago(300*day))       // fresh (not)
	key(a, "revoked", nil, lt(200*day), ago(300*day))     // revoked (not)
	key(b, "active", exp(1*day), nil, ago(300*day))       // other tenant

	// SCIM tokens.
	tok := func(tenant shared.ID, status string, lastUsed *time.Time, created time.Time) {
		id := shared.NewID()
		exec(`INSERT INTO scim_tokens (tenant_id, name, token_hash, token_prefix, status, last_used_at, created_at)
			VALUES ($1, $2, $2, 'scim_x', $3, $4, $5)`, tenant.String(), id.String(), status, lastUsed, created)
	}
	tok(a, "active", lt(91*day), ago(300*day)) // unused
	tok(a, "active", lt(89*day), ago(300*day)) // fresh
	tok(a, "active", nil, ago(31*day))         // never used, old
	tok(a, "revoked", nil, ago(300*day))       // revoked
	tok(b, "active", nil, ago(300*day))

	// Domains.
	dom := func(tenant shared.ID, domain, status, purpose string) {
		exec(`INSERT INTO verified_domains (id, tenant_id, domain, verification_token, status, purpose) VALUES ($1, $2, $3, 'tok', $4, $5)`,
			shared.NewID().String(), tenant.String(), domain, status, purpose)
	}
	suffix := shared.NewID().String()[24:]
	dom(a, "a-ok-"+suffix+".example.com", "verified", "sso")
	dom(a, "a-pending-"+suffix+".example.com", "pending", "sso")
	dom(a, "a-easm-"+suffix+".example.com", "verified", "easm")
	dom(b, "b-ok-"+suffix+".example.com", "verified", "sso")

	// Support grants.
	var adminID string = shared.NewID().String()
	exec(`INSERT INTO admin_users (id, email, name, role) VALUES ($1, $2, 'sup', 'super_admin')`, adminID, adminID+"@sup.example.com")
	grant := func(tenant shared.ID, start, end time.Time, revoked *time.Time) {
		exec(`INSERT INTO support_grants (tenant_id, admin_id, admin_email, scopes, reason, starts_at, expires_at, revoked_at)
			VALUES ($1, $2, 'sup@example.com', ARRAY['findings'], 'investigating the report', $3, $4, $5)`,
			tenant.String(), adminID, start, end, revoked)
	}
	rv := now
	grant(a, ago(1*time.Hour), now.Add(2*time.Hour), nil) // active
	grant(a, ago(10*time.Hour), ago(1*time.Hour), nil)    // expired
	grant(a, ago(1*time.Hour), now.Add(2*time.Hour), &rv) // revoked
	grant(b, ago(1*time.Hour), now.Add(2*time.Hour), nil)

	got, err := repo.Counts(ctx, a, now)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	want := securityoverview.Counts{
		AdminsWithoutMFA: 2, DormantMembers: 2, PendingJoinRequests: 1,
		APIKeysExpiring: 1, APIKeysUnused: 2, SCIMTokensActive: 3, SCIMTokensUnused: 2,
		VerifiedDomains: 1, ActiveSupportGrants: 1,
	}
	if got != want {
		t.Fatalf("tenant A counts\n got  %+v\n want %+v", got, want)
	}

	// Tenant B sees only its own rows.
	gotB, err := repo.Counts(ctx, b, now)
	if err != nil {
		t.Fatalf("counts B: %v", err)
	}
	wantB := securityoverview.Counts{
		AdminsWithoutMFA: 1, DormantMembers: 1, PendingJoinRequests: 1,
		APIKeysExpiring: 1, APIKeysUnused: 1, SCIMTokensActive: 1, SCIMTokensUnused: 1,
		VerifiedDomains: 1, ActiveSupportGrants: 1,
	}
	if gotB != wantB {
		t.Fatalf("tenant B counts\n got  %+v\n want %+v", gotB, wantB)
	}

	// A tenant with no rows counts zero; a zero tenant is refused.
	empty := seedTestTenant(ctx, t, sqlDB)
	if c, err := repo.Counts(ctx, empty, now); err != nil || c != (securityoverview.Counts{}) {
		t.Fatalf("empty tenant: %+v %v", c, err)
	}
	if _, err := repo.Counts(ctx, shared.ID{}, now); err == nil {
		t.Fatal("zero tenant must be refused")
	}
}
