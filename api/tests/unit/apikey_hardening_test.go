package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/apikey"
	"github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// holds returns a CallerHolds func for a caller with exactly perms.
func holds(perms ...string) func(string) bool {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(s string) bool { return set[s] }
}

// ATTACK: a member allowed to create API keys must not mint a key with scopes
// beyond their own permissions.
func TestCreateAPIKey_RejectsScopeNotHeldByCaller(t *testing.T) {
	repo := newMockAPIKeyRepo()
	svc := newTestAPIKeyService(repo)

	_, err := svc.Create(context.Background(), apikey.CreateInput{
		TenantID:      shared.NewID().String(),
		ExpiresInDays: 90,
		Name:          "escalate",
		Scopes:        []string{"findings:read", "team:delete"},
		CallerHolds:   holds("findings:read"),
	})
	if err == nil {
		t.Fatal("expected creation with a scope the caller lacks to fail")
	}
	if !errors.Is(err, shared.ErrForbidden) || !errors.Is(err, apikey.ErrScopeNotHeld) {
		t.Fatalf("expected ErrForbidden/ErrScopeNotHeld, got %v", err)
	}
	if repo.createCalls != 0 {
		t.Fatal("no key may be stored when a scope is rejected")
	}
}

func TestCreateAPIKey_AllowsScopesHeldByCaller(t *testing.T) {
	repo := newMockAPIKeyRepo()
	svc := newTestAPIKeyService(repo)

	res, err := svc.Create(context.Background(), apikey.CreateInput{
		TenantID:      shared.NewID().String(),
		ExpiresInDays: 90,
		Name:          "ok",
		Scopes:        []string{"findings:read"},
		CallerHolds:   holds("findings:read", "assets:read"),
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if len(res.Key.Scopes()) != 1 {
		t.Fatalf("scopes = %v", res.Key.Scopes())
	}
}

// Owner/admin bypass is expressed by CallerHolds returning true for everything
// (middleware.HasPermission does that for IsAdmin callers).
func TestCreateAPIKey_AdminCallerMayGrantAnyValidScope(t *testing.T) {
	svc := newTestAPIKeyService(newMockAPIKeyRepo())
	_, err := svc.Create(context.Background(), apikey.CreateInput{
		TenantID:      shared.NewID().String(),
		ExpiresInDays: 90,
		Name:          "admin-key",
		Scopes:        []string{"findings:read", "team:delete"},
		CallerHolds:   func(string) bool { return true },
	})
	if err != nil {
		t.Fatalf("admin caller should be able to grant valid scopes: %v", err)
	}
}

func TestAPIKeyLifecycle_WritesAuditEvents(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newMockAPIKeyRepo()
	svc := newTestAPIKeyService(repo)
	svc.SetAuditService(auditSvc)

	tenantID := shared.NewID()
	actor := shared.NewID()
	actx := &audit.AuditContext{TenantID: tenantID.String(), ActorID: actor.String()}

	res, err := svc.Create(context.Background(), apikey.CreateInput{
		TenantID: tenantID.String(), Name: "audited", AuditContext: actx,
		ExpiresInDays: 90,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if auditRepo.lastCreated == nil || auditRepo.lastCreated.Action() != auditdom.ActionAPIKeyCreated {
		t.Fatalf("expected api_key.created audit event")
	}

	if _, err := svc.Revoke(context.Background(), apikey.RevokeInput{
		ID: res.Key.ID().String(), TenantID: tenantID.String(), RevokedBy: actor.String(), AuditContext: actx,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if auditRepo.lastCreated.Action() != auditdom.ActionAPIKeyRevoked {
		t.Fatalf("expected api_key.revoked, got %s", auditRepo.lastCreated.Action())
	}

	if err := svc.Delete(context.Background(), res.Key.ID().String(), tenantID.String(), actx); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if auditRepo.lastCreated.Action() != auditdom.ActionAPIKeyDeleted {
		t.Fatalf("expected api_key.deleted, got %s", auditRepo.lastCreated.Action())
	}
	if auditRepo.createCalls != 3 {
		t.Errorf("expected 3 audit events, got %d", auditRepo.createCalls)
	}
}
