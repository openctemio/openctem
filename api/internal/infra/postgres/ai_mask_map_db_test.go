package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/aimaskmap"
	"github.com/openctemio/openctem/api/pkg/aimask"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// AI run masking maps (docs/architecture/ai-context-masking.md): stored
// encrypted, readable only by the run's own organization, gone once
// expired, one per run; and the masking policy round trip per organization.
// Requires DATABASE_URL.
func TestAIMaskMaps_IsolationEncryptionExpiry(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	tA, tB := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{tA, tB} {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'mask', $2)`, id.String(), "mask-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM tenants WHERE id IN ($1, $2)`, tA.String(), tB.String())
	})
	appKey := make([]byte, 32)
	_, _ = rand.Read(appKey)
	cipher, err := crypto.NewCipher(appKey)
	if err != nil {
		t.Fatal(err)
	}
	store := aimaskmap.NewStore(NewAIMaskMapRepository(db), cipher, time.Hour)

	runKey := make([]byte, aimask.KeySize)
	_, _ = rand.Read(runKey)
	m, err := aimask.New(runKey, aimask.FullPolicy())
	if err != nil {
		t.Fatal(err)
	}
	m.MaskText("db01.corp.example.com at 10.9.8.7")
	run := shared.NewID()
	if err := store.Save(ctx, tA, run, runKey, m.Snapshot()); err != nil {
		t.Fatal(err)
	}
	// One map per run.
	if err := store.Save(ctx, tA, run, runKey, m.Snapshot()); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second map for a run: %v", err)
	}
	// Ciphertext only in the database.
	var keyEnc, mapEnc string
	if err := sqlDB.QueryRowContext(ctx, `SELECT key_enc, map_enc FROM ai_mask_maps WHERE run_id = $1`, run.String()).Scan(&keyEnc, &mapEnc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(mapEnc, "example.com") || strings.Contains(mapEnc, "10.9.8.7") || strings.Contains(keyEnc, string(runKey)) {
		t.Fatal("plaintext stored")
	}
	gotKey, snap, err := store.Load(ctx, tA, run)
	if err != nil || string(gotKey) != string(runKey) {
		t.Fatalf("load: %v", err)
	}
	if back, unknown := aimask.NewUnmasker(snap).Unmask(m.MaskText("db01.corp.example.com")); back != "db01.corp.example.com" || len(unknown) != 0 {
		t.Fatalf("unmask after load: %q %v", back, unknown)
	}
	// Another organization cannot read the run's map, even with its id.
	if _, _, err := store.Load(ctx, tB, run); !errors.Is(err, aimaskmap.ErrNotFound) {
		t.Fatalf("cross-tenant load: %v", err)
	}
	// Expired maps are not returned and are purged.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE ai_mask_maps SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 minute' WHERE run_id = $1`, run.String()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(ctx, tA, run); !errors.Is(err, aimaskmap.ErrNotFound) {
		t.Fatalf("expired map loaded: %v", err)
	}
	if n, err := store.Purge(ctx); err != nil || n < 1 {
		t.Fatalf("purge: %d %v", n, err)
	}

	// Masking policy: per organization.
	repo := NewTenantAISettingsRepository(db)
	p, err := repo.GetMasking(ctx, tA)
	if err != nil || len(p.Off) != 0 {
		t.Fatalf("default policy: %+v %v", p, err)
	}
	if err := repo.SaveMasking(ctx, tA, tenant.AIMaskingPolicy{Off: []tenant.AIMaskClass{tenant.AIMaskIPs}, Terms: []string{"Acme"}}); err != nil {
		t.Fatal(err)
	}
	if p, _ := repo.GetMasking(ctx, tA); p.Masked(tenant.AIMaskIPs) || len(p.Terms) != 1 {
		t.Fatalf("saved policy: %+v", p)
	}
	if p, _ := repo.GetMasking(ctx, tB); !p.Masked(tenant.AIMaskIPs) {
		t.Fatal("another organization's policy changed")
	}
	// The row created for the policy leaves AI off (no consent).
	s, err := repo.Get(ctx, tA, tenant.AISettings{})
	if err != nil || s.OptedIn() {
		t.Fatalf("creating the masking row turned AI on: %v %v", s.OptedIn(), err)
	}
}
