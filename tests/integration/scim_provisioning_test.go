package integration

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/app/scim"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// scimMemberMgr adapts the real TenantService to scim.MembershipManager,
// mirroring cmd/server's scimMembershipAdapter (zero inviter = system).
type scimMemberMgr struct{ svc *app.TenantService }

func (a scimMemberMgr) AddMember(ctx context.Context, tenantID, userID shared.ID, role string) error {
	_, err := a.svc.AddMember(ctx, tenantID.String(),
		app.AddMemberInput{UserID: userID, Role: role}, shared.ID{},
		app.AuditContext{TenantID: tenantID.String(), ActorEmail: "scim-provisioning"})
	return err
}

func (a scimMemberMgr) SuspendMember(ctx context.Context, tenantID, membershipID shared.ID) error {
	return a.svc.SuspendMember(ctx, membershipID.String(), app.AuditContext{TenantID: tenantID.String(), ActorEmail: "scim-provisioning"})
}

func (a scimMemberMgr) ReactivateMember(ctx context.Context, tenantID, membershipID shared.ID) error {
	return a.svc.ReactivateMember(ctx, membershipID.String(), app.AuditContext{TenantID: tenantID.String(), ActorEmail: "scim-provisioning"})
}

// TestSCIMProvisioning_RoundTrip_RealDB exercises the SCIM provisioning path
// against a real Postgres — the path the unit-test fakes bypassed, which hid
// the invited_by FK bug (api#199). Provision a new user, assert the membership
// row carries a NULL invited_by, then deprovision/reactivate, and round-trip a
// bearer token (mint → authenticate → revoke).
func TestSCIMProvisioning_RoundTrip_RealDB(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}
	log := logger.NewNop()
	ctx := context.Background()

	tenantID := createTestTenant(t, sqlDB, "scim")
	email := fmt.Sprintf("scim-%d@example.com", time.Now().UnixNano())
	t.Cleanup(func() {
		cleanupTestData(sqlDB, tenantID)
		_, _ = sqlDB.Exec("DELETE FROM users WHERE email = $1", email)
	})

	userRepo := postgres.NewUserRepository(db)
	tenantRepo := postgres.NewTenantRepository(db)
	tokenRepo := postgres.NewScimTokenRepository(db)
	tenantSvc := app.NewTenantService(tenantRepo, log)
	prov := scim.NewProvisioningService(userRepo, tenantRepo, scimMemberMgr{svc: tenantSvc}, log)
	tokenSvc := scim.NewTokenService(tokenRepo, "test-pepper", log)

	// 1. Provision a brand-new user. This is the api#199 bug path: AddMember
	//    with a zero inviter against the real invited_by → users(id) FK.
	res, created, err := prov.CreateOrActivate(ctx, tenantID, scim.ProvisionInput{
		UserName: email, DisplayName: "SCIM User", Active: true,
	})
	if err != nil {
		t.Fatalf("provision new user (FK regression): %v", err)
	}
	if !created {
		t.Error("expected created=true for a new membership")
	}
	if !res.Active {
		t.Error("expected the provisioned user to be active")
	}
	userID, err := shared.IDFromString(res.ID)
	if err != nil {
		t.Fatalf("parse user id: %v", err)
	}

	// 2. invited_by MUST be NULL (the regression — the all-zeros UUID would
	//    violate the FK).
	var invitedBy sql.NullString
	if qerr := sqlDB.QueryRow(
		`SELECT invited_by FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`,
		tenantID.String(), userID.String(),
	).Scan(&invitedBy); qerr != nil {
		t.Fatalf("query invited_by: %v", qerr)
	}
	if invitedBy.Valid {
		t.Errorf("invited_by should be NULL for system provisioning, got %q", invitedBy.String)
	}

	// 3. Idempotent re-provision returns created=false, no duplicate.
	if _, created2, rerr := prov.CreateOrActivate(ctx, tenantID, scim.ProvisionInput{UserName: email, Active: true}); rerr != nil || created2 {
		t.Errorf("re-provision should be idempotent (created=false), got created=%v err=%v", created2, rerr)
	}

	// 4. Deprovision → membership suspended → resource inactive.
	if r2, derr := prov.SetActive(ctx, tenantID, userID, false); derr != nil {
		t.Fatalf("deprovision: %v", derr)
	} else if r2.Active {
		t.Error("expected inactive after deprovision")
	}
	var status string
	if qerr := sqlDB.QueryRow(
		`SELECT status FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`,
		tenantID.String(), userID.String(),
	).Scan(&status); qerr != nil {
		t.Fatalf("query status: %v", qerr)
	}
	if status != "suspended" {
		t.Errorf("membership status = %q, want suspended", status)
	}

	// 5. Reactivate.
	if r3, aerr := prov.SetActive(ctx, tenantID, userID, true); aerr != nil {
		t.Fatalf("reactivate: %v", aerr)
	} else if !r3.Active {
		t.Error("expected active after reactivate")
	}

	// 6. Token round-trip against the real scim_tokens table.
	mint, terr := tokenSvc.Mint(ctx, tenantID, "okta", nil)
	if terr != nil {
		t.Fatalf("mint token: %v", terr)
	}
	tok, aerr := tokenSvc.Authenticate(ctx, mint.Plaintext)
	if aerr != nil || tok.TenantID() != tenantID {
		t.Fatalf("authenticate minted token: tok=%v err=%v", tok, aerr)
	}
	if rerr := tokenSvc.Revoke(ctx, tenantID, mint.Token.ID()); rerr != nil {
		t.Fatalf("revoke: %v", rerr)
	}
	if _, e := tokenSvc.Authenticate(ctx, mint.Plaintext); e == nil {
		t.Error("revoked token must not authenticate")
	}
}
