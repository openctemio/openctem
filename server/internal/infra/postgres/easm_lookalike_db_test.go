package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/lookalike"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Lookalike watches and candidates against the real schema. Requires DATABASE_URL.
func TestEASMLookalikeRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	repo := NewEASMLookalikeRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, 'domain', '*.example.com', 'active')`, tenant.String())
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status, expires_at) VALUES ($1, 'domain', 'oneoff.example', 'active', now() + interval '1 day')`, tenant.String())
	exec(`INSERT INTO verified_domains (id, tenant_id, domain, verification_token, status, purpose) VALUES ($1, $2, 'proven.example', 'x', 'verified', 'easm')`,
		shared.NewID().String(), tenant.String())

	for domain, want := range map[string]bool{"example.com": true, "proven.example": true, "oneoff.example": false, "other.example": false} {
		got, err := repo.OwnsRoot(ctx, tenant, domain)
		if err != nil || got != want {
			t.Errorf("OwnsRoot(%s) = %v, %v; want %v", domain, got, err, want)
		}
	}
	if own, _ := repo.OwnsRoot(ctx, other, "example.com"); own {
		t.Fatal("another tenant owns this tenant's root")
	}

	w, err := repo.CreateWatch(ctx, tenant, "example.com", []lookalike.Technique{lookalike.TechTLD}, 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateWatch(ctx, tenant, "example.com", nil, 50, nil); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	now := time.Now().UTC()
	cands := lookalike.Generate("example.com", []lookalike.Technique{lookalike.TechTLD}, 50)
	if err := repo.ReplaceCandidates(ctx, tenant, w.ID, cands, now); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.GetWatch(ctx, tenant, w.ID)
	if got.Candidates != len(cands) || got.GeneratedAt == nil {
		t.Fatalf("watch counts: %+v", got)
	}
	due, err := repo.DueCandidates(ctx, tenant, w.ID, now, now, 5)
	if err != nil || len(due) != 5 {
		t.Fatalf("due: %v %d", err, len(due))
	}
	if err := repo.SaveObservation(ctx, tenant, w.ID, due[0].Domain, lookalike.Observation{Registered: true, HasMX: true, NS: []string{"ns1.x"}, CTCerts: 3}, true, now); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveObservation(ctx, tenant, w.ID, due[1].Domain, lookalike.Observation{}, false, now); err != nil {
		t.Fatal(err)
	}
	reg, err := repo.Registered(ctx, tenant, w.ID, 10)
	if err != nil || len(reg) != 1 || reg[0].Domain != due[0].Domain || !reg[0].HasMX || reg[0].CTCerts != 3 || reg[0].FirstRegisteredAt == nil {
		t.Fatalf("registered: %v %+v", err, reg)
	}
	// Recently checked candidates are not due again.
	again, _ := repo.DueCandidates(ctx, tenant, w.ID, now.Add(-time.Hour), now.Add(-time.Hour), 100)
	for _, c := range again {
		if c.Domain == due[0].Domain || c.Domain == due[1].Domain {
			t.Fatalf("checked candidate due again: %s", c.Domain)
		}
	}
	// Regenerating with fewer candidates keeps observations of the kept ones.
	if err := repo.ReplaceCandidates(ctx, tenant, w.ID, []lookalike.Candidate{{Domain: due[0].Domain, Technique: lookalike.TechTLD}}, now); err != nil {
		t.Fatal(err)
	}
	reg, _ = repo.Registered(ctx, tenant, w.ID, 10)
	if len(reg) != 1 {
		t.Fatal("observation lost on regeneration")
	}
	// Changing techniques clears generated_at.
	upd, err := repo.UpdateWatch(ctx, tenant, w.ID, false, []lookalike.Technique{lookalike.TechOmission}, 50)
	if err != nil || upd.Enabled || upd.GeneratedAt != nil {
		t.Fatalf("update: %v %+v", err, upd)
	}

	// Tenant isolation.
	if _, err := repo.GetWatch(ctx, other, w.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if _, err := repo.UpdateWatch(ctx, other, w.ID, true, nil, 50); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
	if err := repo.DeleteWatch(ctx, other, w.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	if l, _ := repo.ListWatches(ctx, other); len(l) != 0 {
		t.Fatal("other tenant lists this tenant's watch")
	}
	if err := repo.DeleteWatch(ctx, tenant, w.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM easm_lookalike_candidates WHERE watch_id = $1`, w.ID).Scan(&n)
	if n != 0 {
		t.Fatal("candidates outlived their watch")
	}

	// The exposure type is accepted by the schema.
	exec(`INSERT INTO exposure_events (tenant_id, event_type, severity, title, fingerprint, source) VALUES ($1, 'lookalike_domain', 'medium', 'x', $2, 'easm_lookalike')`,
		tenant.String(), shared.NewID().String())
}
