package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// The organization AI settings table: defaults without a row, a round trip,
// per-organization isolation, a stored auto-triage policy overriding the
// platform default key by key, and the key being stored as given (the caller
// encrypts) and deleted with the organization. Requires DATABASE_URL.
func TestTenantAISettingsRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewTenantAISettingsRepository(&DB{DB: sqlDB})

	a, b := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{a, b} {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'ai settings', $2)`, id.String(), "tai-"+id.String()); err != nil {
			t.Fatal(err)
		}
		id := id
		t.Cleanup(func() {
			_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
		})
	}

	defaults := tenant.AISettings{AutoTriageEnabled: true, AutoTriageSeverities: []string{"critical"}, AutoTriageDelaySeconds: 60}
	got, err := r.Get(ctx, a, defaults)
	if err != nil || got.OptedIn() || got.Mode != "" || !got.AutoTriageEnabled || got.APIKey != "" {
		t.Fatalf("no row must give the defaults: %+v %v", got, err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := shared.NewID().String()
	in := tenant.AISettings{
		Mode: tenant.AIModeBYOK, Provider: tenant.LLMProviderOpenAICompatible, BaseURL: "https://llm.example.com/v1", ModelOverride: "llama3",
		APIKey: "Y2lwaGVydGV4dA==", KeyLast4: "wxyz", KeyUpdatedAt: &now, KeyUpdatedBy: userID,
		EnabledAt: &now, EnabledBy: userID, UpdatedBy: userID,
	}
	if err := r.Save(ctx, a, in, nil); err != nil {
		t.Fatal(err)
	}
	// A second first-write (nil expected) must not overwrite the row.
	if err := r.Save(ctx, a, in, nil); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("insert over an existing row: err = %v, want conflict", err)
	}
	got, err = r.Get(ctx, a, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != tenant.AIModeBYOK || got.Provider != in.Provider || got.BaseURL != in.BaseURL || got.ModelOverride != "llama3" ||
		got.APIKey != in.APIKey || got.KeyLast4 != "wxyz" || got.KeyUpdatedBy != userID || !got.OptedIn() || got.EnabledBy != userID ||
		got.KeyUpdatedAt == nil || !got.KeyUpdatedAt.Equal(now) {
		t.Fatalf("round trip: %+v", got)
	}
	if !got.AutoTriageEnabled || got.AutoTriageDelaySeconds != 60 {
		t.Fatalf("an unset policy keeps the platform defaults: %+v", got)
	}

	// Isolation: another organization sees none of it.
	other, err := r.Get(ctx, b, defaults)
	if err != nil || other.OptedIn() || other.APIKey != "" || other.Provider != "" {
		t.Fatalf("organization B must be untouched: %+v %v", other, err)
	}

	// An explicit policy wins over the platform default, key by key, and Save
	// does not touch it.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE tenant_ai_settings SET policy = '{"auto_triage_enabled": false}' WHERE tenant_id = $1`, a.String()); err != nil {
		t.Fatal(err)
	}
	in.ModelOverride = "llama3.1"
	read := got.UpdatedAt
	if err := r.Save(ctx, a, in, read); err != nil {
		t.Fatal(err)
	}
	// A save based on the older read is refused and changes nothing.
	stale := in
	stale.ModelOverride = "stale"
	if err := r.Save(ctx, a, stale, read); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale save: err = %v, want conflict", err)
	}
	got, _ = r.Get(ctx, a, defaults)
	if got.AutoTriageEnabled || got.AutoTriageDelaySeconds != 60 || len(got.AutoTriageSeverities) != 1 || got.ModelOverride != "llama3.1" {
		t.Fatalf("explicit opt-out must stay sticky and the rest default: %+v", got)
	}

	// Removing the key stores NULL, not an empty string.
	in.APIKey, in.KeyLast4, in.KeyUpdatedAt, in.KeyUpdatedBy = "", "", nil, ""
	got, _ = r.Get(ctx, a, defaults)
	if got.ModelOverride != "llama3.1" {
		t.Fatalf("the stale save must not be applied: %+v", got)
	}
	if err := r.Save(ctx, a, in, got.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	var isNull bool
	if err := sqlDB.QueryRowContext(ctx, `SELECT key_enc IS NULL FROM tenant_ai_settings WHERE tenant_id = $1`, a.String()).Scan(&isNull); err != nil || !isNull {
		t.Fatalf("key_enc must be NULL after removing the key: %v %v", isNull, err)
	}

	// Deleted with the organization.
	if _, err := sqlDB.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, a.String()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM tenant_ai_settings WHERE tenant_id = $1`, a.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("settings must go with the organization: %d %v", n, err)
	}
}
