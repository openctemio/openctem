package unit

import (
	"context"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
)

// An action taken with an `oct_` API key is recorded against the key's user
// AND the key, and a handler's own metadata cannot overwrite the key id.
func TestAuditService_LogEvent_StampsAPIKey(t *testing.T) {
	svc, repo := newTestAuditService()
	actx := newTestAuditContext()
	ctx := auditapp.WithAPIKeyActor(context.Background(), "key-123", "oct_abcd")

	event := auditapp.NewSuccessEvent(audit.ActionUserCreated, audit.ResourceTypeUser, "user-1").
		WithMetadata("api_key_id", "spoofed")
	if err := svc.LogEvent(ctx, actx, event); err != nil {
		t.Fatalf("LogEvent: %v", err)
	}
	md := repo.lastCreated.Metadata()
	if md["api_key_id"] != "key-123" || md["api_key_prefix"] != "oct_abcd" || md["auth_method"] != "api_key" {
		t.Errorf("metadata = %v, want the key stamped", md)
	}
	if repo.lastCreated.ActorID() == nil || repo.lastCreated.ActorID().String() != actx.ActorID {
		t.Errorf("actor = %v, want the key's user %s", repo.lastCreated.ActorID(), actx.ActorID)
	}
}

func TestAuditService_LogEvent_SessionHasNoAPIKey(t *testing.T) {
	svc, repo := newTestAuditService()
	if err := svc.LogEvent(context.Background(), newTestAuditContext(), auditapp.NewSuccessEvent(audit.ActionUserCreated, audit.ResourceTypeUser, "user-1")); err != nil {
		t.Fatalf("LogEvent: %v", err)
	}
	if _, ok := repo.lastCreated.Metadata()["api_key_id"]; ok {
		t.Errorf("a session action was attributed to an API key: %v", repo.lastCreated.Metadata())
	}
}
