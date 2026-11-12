package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	apikeyapp "github.com/openctemio/openctem/api/internal/app/apikey"
	"github.com/openctemio/openctem/api/internal/testdb"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fixedLifetime map[shared.ID]int

func (f fixedLifetime) MaxAPIKeyLifetimeDays(_ context.Context, tid shared.ID) (int, error) {
	if n, ok := f[tid]; ok {
		return n, nil
	}
	return 0, errors.New("organization policy unreadable")
}

type expiryInApp struct {
	mu sync.Mutex
	to []string
}

func (e *expiryInApp) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.AudienceID != nil {
		e.to = append(e.to, p.TenantID.String()+"/"+p.AudienceID.String())
	}
	return nil
}

// The organization's maximum key lifetime on create, and the expiry notice,
// against the real api_keys table: a key longer than the organization's
// maximum is refused (and nothing stored), an unreadable policy refuses
// (fail closed), a key within it is created; a key that expires within a
// week is noticed once, to its creator, in its own organization; a key that
// expires later is not; the mark is tenant-scoped. Requires DATABASE_URL.
func TestAPIKeyLifetimeAndExpiryNotice(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	newTenant := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'key-lifetime', $2)`, id.String(), "klt-"+id.String()[24:])
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id.String()) })
		return id
	}
	newUser := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'klt')`, id.String(), "klt-"+id.String()[24:]+"@it.test")
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id.String()) })
		return id
	}
	a, b, unreadable := newTenant(), newTenant(), newTenant()
	alice, bob := newUser(), newUser()

	repo := NewAPIKeyRepository(&DB{DB: db})
	svc := apikeyapp.NewService(repo, "pepper", logger.NewNop())
	svc.SetLifetimePolicy(fixedLifetime{a: 30, b: 90})
	inApp := &expiryInApp{}
	svc.SetExpiryNotifier(inApp)

	create := func(tid, uid shared.ID, name string, days int) error {
		_, err := svc.Create(ctx, apikeyapp.CreateInput{TenantID: tid.String(), UserID: uid.String(), CreatedBy: uid.String(), Name: name, ExpiresInDays: days})
		return err
	}
	if err := create(a, alice, "too-long", 31); !errors.Is(err, apikeyapp.ErrExpiryOverOrgMax) {
		t.Fatalf("31 days under a 30-day maximum: err = %v", err)
	}
	if err := create(unreadable, alice, "no-policy", 1); err == nil {
		t.Fatal("an unreadable policy must refuse (fail closed)")
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM api_keys WHERE tenant_id = ANY($1::uuid[])`,
		"{"+a.String()+","+unreadable.String()+"}").Scan(&n); err != nil || n != 0 {
		t.Fatalf("refused keys were stored: %d %v", n, err)
	}
	if err := create(a, alice, "a-soon", 5); err != nil {
		t.Fatalf("5 days: %v", err)
	}
	if err := create(b, bob, "b-later", 60); err != nil {
		t.Fatalf("60 days under 90: %v", err)
	}
	if err := create(b, bob, "b-soon", 2); err != nil {
		t.Fatalf("2 days: %v", err)
	}

	now := time.Now()
	sent, err := svc.NotifyExpiring(ctx, now, 1000)
	if err != nil {
		t.Fatal(err)
	}
	mine := map[string]bool{}
	for _, to := range inApp.to {
		mine[to] = true
	}
	if !mine[a.String()+"/"+alice.String()] || !mine[b.String()+"/"+bob.String()] || mine[a.String()+"/"+bob.String()] || mine[b.String()+"/"+alice.String()] {
		t.Fatalf("notices went to %v", inApp.to)
	}
	if sent < 2 {
		t.Fatalf("sent = %d, want at least the two soon keys", sent)
	}
	var later sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT expiry_notified_at FROM api_keys WHERE tenant_id = $1 AND name = 'b-later'`, b.String()).Scan(&later); err != nil || later.Valid {
		t.Fatalf("a key 60 days out was noticed: %v %v", later, err)
	}

	// Once only.
	before := len(inApp.to)
	if _, err := svc.NotifyExpiring(ctx, now, 1000); err != nil {
		t.Fatal(err)
	}
	for _, to := range inApp.to[before:] {
		if to == a.String()+"/"+alice.String() || to == b.String()+"/"+bob.String() {
			t.Fatalf("a key was noticed twice: %v", inApp.to)
		}
	}

	// The mark is tenant-scoped: another organization's id never marks a key.
	var keyID string
	if err := db.QueryRowContext(ctx, `SELECT id FROM api_keys WHERE tenant_id = $1 AND name = 'b-later'`, b.String()).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.MarkExpiryNoticed(ctx, a, shared.MustIDFromString(keyID)); err != nil || ok {
		t.Fatalf("cross-organization mark = %v %v, want false", ok, err)
	}
}
