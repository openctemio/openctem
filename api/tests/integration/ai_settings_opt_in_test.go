package integration

// An organization administrator turns AI triage on or off (consent to send
// finding content to the AI provider): the change is stored on that
// organization only, is idempotent, needs a signed-in actor to turn on, and
// is audited as critical.

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestAISettingsOptIn(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	log := logger.NewNop()

	orgA := createTestTenant(t, db, "ai-optin-a")
	orgB := createTestTenant(t, db, "ai-optin-b")
	admin := createTestUser(t, db, "admin-"+shared.NewID().String()+"@ai-optin.example", "Admin")
	t.Cleanup(func() {
		for _, tid := range []shared.ID{orgA, orgB} {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM audit_logs WHERE tenant_id = $1`, tid.String())
		}
		cleanupTestData(db, orgA, orgB)
	})

	svc := tenant.NewTenantService(postgres.NewTenantRepository(pg), log,
		tenant.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(pg), log)))
	actx := auditapp.AuditContext{ActorID: admin.String()}

	// Off by default.
	ai, err := svc.GetAISettings(ctx, orgA.String())
	if err != nil || ai.OptedIn() {
		t.Fatalf("new organization: opted in=%v err=%v, want off", ai != nil && ai.OptedIn(), err)
	}

	// Turning on needs a signed-in actor.
	if _, err := svc.UpdateAIOptIn(ctx, orgA.String(), true, auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("on without an actor: %v, want a validation error", err)
	}

	ai, err = svc.UpdateAIOptIn(ctx, orgA.String(), true, actx)
	if err != nil || !ai.OptedIn() || ai.EnabledBy != admin.String() {
		t.Fatalf("turn on: %+v %v", ai, err)
	}
	first := *ai.EnabledAt
	// Again: the original consent is kept.
	ai, err = svc.UpdateAIOptIn(ctx, orgA.String(), true, actx)
	if err != nil || !ai.EnabledAt.Equal(first) {
		t.Fatalf("turn on again changed the consent: %+v %v", ai, err)
	}
	// The other organization is untouched.
	if b, err := svc.GetAISettings(ctx, orgB.String()); err != nil || b.OptedIn() {
		t.Fatalf("organization B opted in=%v err=%v, want off", b != nil && b.OptedIn(), err)
	}
	// Stored, and read back the way the worker reads it.
	var stored string
	if err := db.QueryRowContext(ctx, `SELECT settings->'ai'->>'enabled_by' FROM tenants WHERE id = $1`, orgA.String()).Scan(&stored); err != nil || stored != admin.String() {
		t.Fatalf("stored enabled_by=%q err=%v", stored, err)
	}

	ai, err = svc.UpdateAIOptIn(ctx, orgA.String(), false, actx)
	if err != nil || ai.OptedIn() || ai.EnabledBy != "" {
		t.Fatalf("turn off: %+v %v", ai, err)
	}

	// One critical audit row per change (on, off), none for the no-op.
	deadline := time.Now().Add(3 * time.Second)
	var n int
	for {
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'ai_settings.updated' AND severity = 'critical'`, orgA.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n != 2 {
		t.Fatalf("audit rows = %d, want 2 (on, off)", n)
	}
}
