package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Console factors: the per-administrator cap, the counter guard, the floor on
// removal, single-use ceremonies and recovery codes, and that one
// administrator never reaches another's rows. Requires DATABASE_URL.
func TestAdminFactorRepository_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.Ping(); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	ctx := context.Background()
	repo := NewAdminFactorRepository(&DB{DB: raw})

	seed := func() shared.ID {
		id := uuid.NewString()
		if _, err := raw.ExecContext(ctx, `INSERT INTO admin_users (id, email, name, role) VALUES ($1, $2, 'Factor IT', 'super_admin')`,
			id, "factor-"+id[:8]+"@example.com"); err != nil {
			t.Fatalf("seed admin: %v", err)
		}
		t.Cleanup(func() { _, _ = raw.ExecContext(ctx, `DELETE FROM admin_users WHERE id = $1`, id) })
		sid, _ := shared.IDFromString(id)
		return sid
	}
	mine, other := seed(), seed()
	now := time.Now().UTC().Truncate(time.Microsecond)
	cred := func(aid shared.ID, n int) *admin.WebAuthnCredential {
		return &admin.WebAuthnCredential{ID: shared.NewID(), AdminID: aid, CredentialID: []byte(uuid.NewString()),
			PublicKey: []byte{1, 2, 3}, AAGUID: make([]byte, 16), Transports: []string{"usb"}, Name: "key", CreatedAt: now.Add(time.Duration(n) * time.Second)}
	}

	first := cred(mine, 0)
	if err := repo.CreateWebAuthnCredential(ctx, first); err != nil {
		t.Fatalf("create: %v", err)
	}
	dup := cred(other, 0)
	dup.CredentialID = first.CredentialID
	if err := repo.CreateWebAuthnCredential(ctx, dup); !errors.Is(err, admin.ErrWebAuthnCredentialExists) {
		t.Fatalf("duplicate credential id: %v", err)
	}
	for i := 1; i < admin.MaxWebAuthnCredentials; i++ {
		if err := repo.CreateWebAuthnCredential(ctx, cred(mine, i)); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if err := repo.CreateWebAuthnCredential(ctx, cred(mine, 99)); !errors.Is(err, admin.ErrTooManyWebAuthnCredentials) {
		t.Fatalf("over the cap: %v", err)
	}
	list, err := repo.ListWebAuthnCredentials(ctx, mine)
	if err != nil || len(list) != admin.MaxWebAuthnCredentials || list[0].ID != first.ID || list[0].Transports[0] != "usb" {
		t.Fatalf("list: %d %v", len(list), err)
	}
	if l, _ := repo.ListWebAuthnCredentials(ctx, other); len(l) != 0 {
		t.Fatalf("another administrator sees %d keys", len(l))
	}

	// Counter: forward only; 0/0 (synced passkeys) allowed.
	if ok, _ := repo.RecordWebAuthnUse(ctx, mine, first.ID, 0, true, now); !ok {
		t.Fatal("0 -> 0 must pass")
	}
	if ok, _ := repo.RecordWebAuthnUse(ctx, mine, first.ID, 5, true, now); !ok {
		t.Fatal("0 -> 5 must pass")
	}
	if ok, _ := repo.RecordWebAuthnUse(ctx, mine, first.ID, 5, true, now); ok {
		t.Fatal("5 -> 5 must be refused")
	}
	if ok, _ := repo.RecordWebAuthnUse(ctx, mine, first.ID, 0, true, now); ok {
		t.Fatal("5 -> 0 must be refused")
	}
	if ok, _ := repo.RecordWebAuthnUse(ctx, other, first.ID, 9, true, now); ok {
		t.Fatal("another administrator must not move my counter")
	}

	// Rename and delete are keyed on the owner.
	if err := repo.RenameWebAuthnCredential(ctx, other, first.ID, "x"); !errors.Is(err, admin.ErrWebAuthnCredentialNotFound) {
		t.Fatalf("rename someone else's: %v", err)
	}
	if err := repo.DeleteWebAuthnCredential(ctx, other, first.ID, 0); !errors.Is(err, admin.ErrWebAuthnCredentialNotFound) {
		t.Fatalf("delete someone else's: %v", err)
	}
	if err := repo.DeleteWebAuthnCredential(ctx, mine, first.ID, admin.MaxWebAuthnCredentials); !errors.Is(err, admin.ErrLastWebAuthnCredential) {
		t.Fatalf("below the floor: %v", err)
	}
	if err := repo.DeleteWebAuthnCredential(ctx, mine, first.ID, 2); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Recovery codes.
	if err := repo.ReplaceRecoveryCodes(ctx, mine, []string{"h1", "h2"}, now); err != nil {
		t.Fatal(err)
	}
	if ok, _ := repo.UseRecoveryCode(ctx, other, "h1", now); ok {
		t.Fatal("another administrator used my code")
	}
	if ok, _ := repo.UseRecoveryCode(ctx, mine, "h1", now); !ok {
		t.Fatal("use h1")
	}
	if ok, _ := repo.UseRecoveryCode(ctx, mine, "h1", now); ok {
		t.Fatal("h1 twice")
	}
	if n, _ := repo.CountRecoveryCodes(ctx, mine); n != 1 {
		t.Fatalf("left %d", n)
	}
	if err := repo.ReplaceRecoveryCodes(ctx, mine, []string{"h3"}, now); err != nil {
		t.Fatal(err)
	}
	if ok, _ := repo.UseRecoveryCode(ctx, mine, "h2", now); ok {
		t.Fatal("a replaced code still works")
	}

	// Ceremonies: single use, expiry, cascade with the session.
	sessID := shared.NewID()
	if _, err := raw.ExecContext(ctx, `INSERT INTO admin_sessions (id, admin_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)`,
		sessID.String(), mine.String(), uuid.NewString(), now.Add(time.Hour)); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := repo.SaveCeremony(ctx, sessID, admin.CeremonyLogin, []byte("a"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveCeremony(ctx, sessID, admin.CeremonyLogin, []byte("b"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if d, err := repo.TakeCeremony(ctx, sessID, admin.CeremonyLogin, now); err != nil || string(d) != "b" {
		t.Fatalf("take: %q %v", d, err)
	}
	if _, err := repo.TakeCeremony(ctx, sessID, admin.CeremonyLogin, now); !errors.Is(err, admin.ErrCeremonyNotFound) {
		t.Fatalf("second take: %v", err)
	}
	_ = repo.SaveCeremony(ctx, sessID, admin.CeremonyStepUp, []byte("c"), now.Add(time.Minute))
	if _, err := repo.TakeCeremony(ctx, sessID, admin.CeremonyStepUp, now.Add(2*time.Minute)); !errors.Is(err, admin.ErrCeremonyNotFound) {
		t.Fatalf("expired: %v", err)
	}

	// The super-admin reset removes everything of one administrator only.
	_ = repo.CreateWebAuthnCredential(ctx, cred(other, 0))
	if err := repo.DeleteFactorsForAdmin(ctx, mine); err != nil {
		t.Fatal(err)
	}
	if l, _ := repo.ListWebAuthnCredentials(ctx, mine); len(l) != 0 {
		t.Fatalf("after reset: %d keys", len(l))
	}
	if n, _ := repo.CountRecoveryCodes(ctx, mine); n != 0 {
		t.Fatalf("after reset: %d codes", n)
	}
	if l, _ := repo.ListWebAuthnCredentials(ctx, other); len(l) != 1 {
		t.Fatal("reset touched another administrator")
	}
}
