package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TestSessionRepository_IDPTenantRoundTrip verifies sessions.idp_tenant_id
// (migration 000269): the organization whose IdP issued a federated session
// survives a write/read, a session without one reads back with none (the
// pre-migration / social OAuth / password case — exempt nowhere), and deleting
// the organization clears it rather than the session.
//
// DB-gated: needs DATABASE_URL pointing at a *_test database.
func TestSessionRepository_IDPTenantRoundTrip(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	// t.Cleanup, not defer: the row cleanups below run after the test body,
	// so the connection must outlive them (cleanups run last-registered first).
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	tenantID := shared.NewID()
	mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`,
		tenantID.String(), "idp-tenant-test", "idp-"+tenantID.String()[24:])
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID.String()) })
	userID := shared.NewID()
	mustExec(t, db, `INSERT INTO users (id, email, name) VALUES ($1,$2,$3)`,
		userID.String(), "idp-"+userID.String()[24:]+"@example.com", "IdP Tenant")
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, userID.String()) })

	repo := NewSessionRepository(db)

	fed, err := session.NewWithID(shared.NewID(), userID, "tok-fed", "", "", time.Hour)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	fed.SetAuthMethod(session.AuthMethodSAML)
	fed.SetIDPTenant(tenantID)
	if err := repo.Create(ctx, fed); err != nil {
		t.Fatalf("create federated session: %v", err)
	}

	social, err := session.NewWithID(shared.NewID(), userID, "tok-social", "", "", time.Hour)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	social.SetAuthMethod(session.AuthMethodSSO)
	if err := repo.Create(ctx, social); err != nil {
		t.Fatalf("create social session: %v", err)
	}

	got, err := repo.GetByID(ctx, fed.ID())
	if err != nil {
		t.Fatalf("get federated: %v", err)
	}
	if !got.IDPTenantID().Equals(tenantID) || !got.FederatedFor(tenantID.String()) {
		t.Fatalf("issuing tenant = %s, want %s", got.IDPTenantID(), tenantID)
	}
	if got.FederatedFor(shared.NewID().String()) {
		t.Fatal("must not count as SSO for another organization")
	}

	// Update must not clear the issuing organization.
	got.UpdateActivity()
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	active, err := repo.GetActiveByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("active sessions = %d, want 2", len(active))
	}
	for _, s := range active {
		switch s.ID() {
		case fed.ID():
			if !s.IDPTenantID().Equals(tenantID) {
				t.Fatalf("after update issuing tenant = %s, want %s", s.IDPTenantID(), tenantID)
			}
		case social.ID():
			if !s.IDPTenantID().IsZero() || s.FederatedFor(tenantID.String()) {
				t.Fatalf("social session must have no issuing tenant, got %s", s.IDPTenantID())
			}
		}
	}

	// Deleting the organization keeps the session but clears the issuer, so it
	// is exempt nowhere.
	mustExec(t, db, `DELETE FROM tenants WHERE id=$1`, tenantID.String())
	got, err = repo.GetByID(ctx, fed.ID())
	if err != nil {
		t.Fatalf("get after tenant delete: %v", err)
	}
	if !got.IDPTenantID().IsZero() {
		t.Fatalf("issuer should be cleared with the organization, got %s", got.IDPTenantID())
	}
}
