package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/apikey"
	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/integration"
	apikeydom "github.com/openctemio/openctem/api/pkg/domain/apikey"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/secretstore"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// failingAuditRepo is an audit store that is down.
type failingAuditRepo struct{ secretMockAuditRepo }

func (*failingAuditRepo) Create(context.Context, *audit.AuditLog) error {
	return errors.New("audit store down")
}

// A key whose creation cannot be audited is never returned and never usable.
func TestCreateAPIKey_AuditFailureRevokesTheKey(t *testing.T) {
	repo := newMockAPIKeyRepo()
	svc := newTestAPIKeyService(repo)
	svc.SetAuditService(auditsvc.NewAuditService(&failingAuditRepo{}, logger.NewNop()))

	tenant, user := shared.NewID(), shared.NewID()
	res, err := svc.Create(context.Background(), apikey.CreateInput{
		TenantID: tenant.String(), UserID: user.String(), CreatedBy: user.String(),
		ExpiresInDays: 30, Name: "audited key",
		AuditContext: &auditsvc.AuditContext{TenantID: tenant.String(), ActorID: user.String()},
	})
	if !errors.Is(err, auditsvc.ErrNotRecorded) {
		t.Fatalf("err = %v, want ErrNotRecorded", err)
	}
	if res != nil {
		t.Fatal("the key (and its plaintext) was returned although it could not be audited")
	}
	if len(repo.keys) != 1 {
		t.Fatalf("stored keys = %d, want 1 (revoked)", len(repo.keys))
	}
	for _, k := range repo.keys {
		if k.Status() != apikeydom.StatusRevoked || k.IsActive() {
			t.Fatalf("unaudited key status = %s, want revoked", k.Status())
		}
	}
}

// When revoking fails too, the key is deleted.
func TestCreateAPIKey_AuditFailureFallsBackToDelete(t *testing.T) {
	repo := newMockAPIKeyRepo()
	svc := newTestAPIKeyService(repo)
	svc.SetAuditService(auditsvc.NewAuditService(&failingAuditRepo{}, logger.NewNop()))
	repo.updateErr = errors.New("db down")

	tenant := shared.NewID()
	_, err := svc.Create(context.Background(), apikey.CreateInput{
		TenantID: tenant.String(), ExpiresInDays: 30, Name: "audited key",
		AuditContext: &auditsvc.AuditContext{TenantID: tenant.String()},
	})
	if !errors.Is(err, auditsvc.ErrNotRecorded) {
		t.Fatalf("err = %v, want ErrNotRecorded", err)
	}
	if repo.deleteCalls != 1 || len(repo.keys) != 0 {
		t.Fatalf("deleteCalls=%d keys=%d, want the key deleted", repo.deleteCalls, len(repo.keys))
	}
}

// A stored credential whose creation cannot be audited is removed again.
func TestCreateCredential_AuditFailureDeletesIt(t *testing.T) {
	repo := newSecretMockRepo()
	log := logger.NewNop()
	svc, err := integration.NewSecretStoreService(repo, secretTestKey, auditsvc.NewAuditService(&failingAuditRepo{}, log), log)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := svc.CreateCredential(context.Background(), integration.CreateCredentialInput{
		TenantID: shared.NewID(), UserID: shared.NewID(), Name: "k",
		CredentialType: secretstore.CredentialTypeAPIKey, Data: &secretstore.APIKeyData{Key: "sk-test-123"},
	})
	if !errors.Is(err, auditsvc.ErrNotRecorded) || cred != nil {
		t.Fatalf("cred=%v err=%v, want ErrNotRecorded and no credential", cred, err)
	}
	if len(repo.credentials) != 0 {
		t.Fatalf("credentials left after a failed audit = %d, want 0", len(repo.credentials))
	}
}
