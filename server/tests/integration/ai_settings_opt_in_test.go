package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/tenantai"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/llm"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The organization AI settings on a real database: consent (audited
// critical), per-organization isolation, an own provider whose key is
// encrypted at rest, never read back and never written to the audit log.
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

	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc := tenantai.NewService(postgres.NewTenantAISettingsRepository(pg), cipher,
		auditapp.NewAuditService(postgres.NewAuditRepository(pg), log),
		llm.NewFactory(config.AITriageConfig{}), nil, log)
	actx := auditapp.AuditContext{ActorID: admin.String()}
	yes, no := true, false

	// Off by default.
	v, err := svc.Get(ctx, orgA.String())
	if err != nil || v.Enabled || v.Source != "platform" || v.KeySet {
		t.Fatalf("new organization: %+v %v, want off", v, err)
	}

	// Turning on needs a signed-in actor.
	if _, err := svc.Save(ctx, orgA.String(), tenantai.Update{Enabled: &yes}, auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("on without an actor: %v, want a validation error", err)
	}
	v, err = svc.Save(ctx, orgA.String(), tenantai.Update{Enabled: &yes}, actx)
	if err != nil || !v.Enabled || v.EnabledBy != admin.String() {
		t.Fatalf("turn on: %+v %v", v, err)
	}
	first := *v.EnabledAt
	// Again: the original consent is kept.
	v, err = svc.Save(ctx, orgA.String(), tenantai.Update{Enabled: &yes}, actx)
	if err != nil || !v.EnabledAt.Equal(first) {
		t.Fatalf("turn on again changed the consent: %+v %v", v, err)
	}
	// The other organization is untouched.
	if b, err := svc.Get(ctx, orgB.String()); err != nil || b.Enabled {
		t.Fatalf("organization B enabled=%v err=%v, want off", b.Enabled, err)
	}

	// An own provider: the key is stored encrypted, shown only as set + last 4.
	const secret = "sk-test-secret-key-0123456789"
	src, prov, model, key := "own", "openai", "gpt-4o", secret
	v, err = svc.Save(ctx, orgA.String(), tenantai.Update{Source: &src, Provider: &prov, Model: &model, APIKey: &key}, actx)
	if err != nil || v.Source != "own" || !v.KeySet || v.KeyLast4 != "6789" || v.KeyUpdatedBy != admin.String() {
		t.Fatalf("own provider: %+v %v", v, err)
	}
	var stored string
	if err := db.QueryRowContext(ctx, `SELECT key_enc FROM tenant_ai_settings WHERE tenant_id = $1`, orgA.String()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "" || strings.Contains(stored, secret) {
		t.Fatalf("the key must be stored encrypted, got %q", stored)
	}
	if plain, err := cipher.DecryptString(stored); err != nil || plain != secret {
		t.Fatalf("stored key must decrypt with the server key: %v", err)
	}
	// The other organization has no key; the key survives an unrelated change.
	if b, _ := svc.Get(ctx, orgB.String()); b.KeySet || b.Provider != "" {
		t.Fatalf("organization B must not see A's provider: %+v", b)
	}
	model2 := "gpt-4o-mini"
	if v, err = svc.Save(ctx, orgA.String(), tenantai.Update{Model: &model2}, actx); err != nil || !v.KeySet {
		t.Fatalf("a model change keeps the key: %+v %v", v, err)
	}
	// Switching the provider drops the key (it was entered for another endpoint).
	prov2 := "gemini"
	if v, err = svc.Save(ctx, orgA.String(), tenantai.Update{Provider: &prov2, Source: strp("platform")}, actx); err != nil || v.KeySet {
		t.Fatalf("a provider change must drop the key: %+v %v", v, err)
	}

	v, err = svc.Save(ctx, orgA.String(), tenantai.Update{Enabled: &no}, actx)
	if err != nil || v.Enabled || v.EnabledBy != "" {
		t.Fatalf("turn off: %+v %v", v, err)
	}

	// Critical audit rows for each change, none for the no-op, and never the key.
	deadline := time.Now().Add(3 * time.Second)
	var n int
	for {
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'ai_settings.updated' AND severity = 'critical'`, orgA.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n >= 5 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n != 5 {
		t.Fatalf("audit rows = %d, want 5 (on, own provider, model, provider change, off)", n)
	}
	var leaked int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND (metadata::text LIKE '%' || $2 || '%' OR changes::text LIKE '%' || $2 || '%' OR message LIKE '%' || $2 || '%')`,
		orgA.String(), secret).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("the key must never reach the audit log: %d %v", leaked, err)
	}
}

func strp(s string) *string { return &s }
