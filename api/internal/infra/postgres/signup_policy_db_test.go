package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/signup"
)

// The sign-up policy row (migration 001313) as the application role: seeding
// never overwrites, and an update with a stale version is refused.
// Requires DATABASE_URL.
func TestSignupPolicyRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewSignupPolicyRepository(&DB{DB: sqlDB})
	// Start from a clean row; restore whatever was there afterwards.
	before, berr := r.Get(ctx)
	if _, err := sqlDB.ExecContext(ctx, `DELETE FROM platform_settings WHERE key = $1`, signup.SettingKey); err != nil {
		t.Fatalf("clean: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM platform_settings WHERE key = $1`, signup.SettingKey)
		if berr == nil {
			_, _ = r.CreateIfAbsent(context.Background(), before)
		}
	})

	if _, err := r.Get(ctx); !errors.Is(err, signup.ErrNotFound) {
		t.Fatalf("empty: expected ErrNotFound, got %v", err)
	}
	created, err := r.CreateIfAbsent(ctx, signup.State{
		Policy: signup.Policy{Mode: signup.ModeAdminOnly}, Source: signup.SourceEnvironment, UpdatedAt: time.Now(),
	})
	if err != nil || !created {
		t.Fatalf("seed: created=%v err=%v", created, err)
	}
	again, err := r.CreateIfAbsent(ctx, signup.State{
		Policy: signup.Policy{Mode: signup.ModeSelfService}, Source: signup.SourceEnvironment, UpdatedAt: time.Now(),
	})
	if err != nil || again {
		t.Fatalf("a second seed must not overwrite: created=%v err=%v", again, err)
	}
	st, err := r.Get(ctx)
	if err != nil || st.Policy.Mode != signup.ModeAdminOnly || st.Version != 1 || st.Source != signup.SourceEnvironment || st.UpdatedBy != nil {
		t.Fatalf("unexpected seeded state %+v %v", st, err)
	}

	by := shared.NewID()
	next, err := r.Update(ctx, signup.Policy{Mode: signup.ModeSelfService, RequestAccess: true}, 1, by, time.Now())
	if err != nil || next.Version != 2 {
		t.Fatalf("update: %+v %v", next, err)
	}
	if _, err := r.Update(ctx, signup.Policy{Mode: signup.ModeAdminOnly}, 1, by, time.Now()); !errors.Is(err, signup.ErrVersionConflict) {
		t.Fatalf("a stale version must be refused, got %v", err)
	}
	st, _ = r.Get(ctx)
	if !st.Policy.AllowsSelfService() || !st.Policy.RequestAccess || st.Source != signup.SourceConsole || st.UpdatedBy == nil || *st.UpdatedBy != by {
		t.Fatalf("unexpected stored state %+v", st)
	}
}
