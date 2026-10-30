package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
)

// An address in another case finds the account, and a second account for the
// same mailbox in another case is refused by the database
// (uq_users_email_lower).
func TestUserRepository_EmailIsCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewUserRepository(&DB{DB: db})
	id := seedGroupsUser(ctx, t, db, "case.example")
	stored := id.String() + "@case.example"

	for _, probe := range []string{stored, strings.ToUpper(stored), "  " + strings.ToUpper(stored[:1]) + stored[1:]} {
		u, err := repo.GetByEmail(ctx, strings.TrimSpace(probe))
		if err != nil || u.ID() != id {
			t.Fatalf("GetByEmail(%q): %v", probe, err)
		}
		if ok, err := repo.ExistsByEmail(ctx, strings.TrimSpace(probe)); err != nil || !ok {
			t.Fatalf("ExistsByEmail(%q): %v %v", probe, ok, err)
		}
	}

	other := shared.NewID()
	_, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'dup')`,
		other.String(), strings.ToUpper(stored))
	if err == nil {
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, other.String())
		t.Fatal("a second account for the same mailbox in another case was stored")
	}
	if !isUniqueViolation(err) {
		t.Fatalf("want a unique violation, got %v", err)
	}
}

// The source of an identity is stored, read back, and only ever moves to sso.
func TestUserIdentityRepository_Source(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewUserIdentityRepository(&DB{DB: db})
	alice := seedGroupsUser(ctx, t, db, "src.example")
	iss := "https://login.microsoftonline.com/" + shared.NewID().String() + "/v2.0"

	social, _ := useridentity.New(alice, useridentity.Key{Issuer: iss, Subject: "oid-a"})
	if err := repo.Create(ctx, social); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByKey(ctx, social.Key)
	if err != nil || got.Source != useridentity.SourceSocial || got.ManagedBySSO() {
		t.Fatalf("social identity %+v / %v", got, err)
	}
	if err := repo.MarkSSO(ctx, social.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetByKey(ctx, social.Key)
	if got.Source != useridentity.SourceSSO || !got.ManagedBySSO() {
		t.Fatalf("after MarkSSO: %q", got.Source)
	}

	bad, _ := useridentity.New(alice, useridentity.Key{Issuer: "https://other-" + shared.NewID().String() + ".example", Subject: "s"})
	bad.Source = "anything"
	if err := repo.Create(ctx, bad); err == nil {
		t.Fatal("an unknown source was stored")
	}
}
