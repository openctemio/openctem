package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Authorization letters (migration 001549): a letter entry authorizes only
// while its letter is valid (the in-effect read joins it); revocation and
// expiry stop it at once; letters and entries stay inside their tenant.
// Requires DATABASE_URL.
func TestAuthorizationLetters(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	tenant := seedBatchTenant(t, db)
	other := seedBatchTenant(t, db)
	letters := NewAuthorizationLetterRepository(pdb)
	targets := NewScopeTargetRepository(pdb)
	now := time.Now().UTC().Truncate(time.Microsecond)
	user := shared.NewID()

	letter := func(tid shared.ID, from, until time.Time) *scope.Letter {
		l := &scope.Letter{ID: shared.NewID(), TenantID: tid, Title: "Engagement", ValidFrom: from, ValidUntil: until,
			AttachmentID: shared.NewID(), FileSHA256: strings.Repeat("ab", 32), UploadedBy: &user, CreatedAt: now}
		if err := letters.Create(ctx, l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	valid := letter(tenant, now.Add(-time.Hour), now.Add(30*24*time.Hour))
	future := letter(tenant, now.Add(24*time.Hour), now.Add(48*time.Hour))
	foreign := letter(other, now.Add(-time.Hour), now.Add(time.Hour))

	entry := func(pattern string, l *scope.Letter) *scope.Target {
		e, err := scope.NewEntry(tenant, scope.TargetTypeDomain, pattern, "", user.String(), scope.EntryOptions{MaxTier: scope.TierActive})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.SetAuthorization(scope.AuthLetter, &l.ID); err != nil {
			t.Fatal(err)
		}
		return e
	}
	ok := entry("client.example", valid)
	notYet := entry("later.example", future)
	for _, e := range []*scope.Target{ok, notYet} {
		if err := targets.Create(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	// SECURITY: an entry cannot name another tenant's letter.
	if err := targets.Create(ctx, entry("foreign.example", foreign)); err == nil {
		t.Fatal("a letter of another tenant must not be named")
	}

	active := func() map[string]bool {
		list, err := targets.ListActive(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, x := range list {
			out[x.Pattern()] = true
		}
		return out
	}
	a := active()
	if !a["client.example"] || a["later.example"] {
		t.Fatalf("in effect: %v", a)
	}
	got, err := targets.GetByID(ctx, tenant, ok.ID())
	if err != nil || got.LetterID() == nil || !got.LetterID().Equals(valid.ID) || got.AuthorizationSource() != scope.AuthLetter {
		t.Fatalf("round trip: %+v %v", got, err)
	}

	// Revocation stops the entry at once; revoking twice is a conflict.
	if err := letters.Revoke(ctx, tenant, valid.ID, user, now); err != nil {
		t.Fatal(err)
	}
	if active()["client.example"] {
		t.Fatal("a revoked letter must stop its entries")
	}
	if err := letters.Revoke(ctx, tenant, valid.ID, user, now); !errors.Is(err, scope.ErrLetterRevoked) {
		t.Fatalf("second revoke: %v", err)
	}
	if err := letters.Revoke(ctx, other, valid.ID, user, now); !errors.Is(err, scope.ErrLetterNotFound) {
		t.Fatalf("another tenant must not revoke the letter: %v", err)
	}
	if _, err := letters.GetByID(ctx, other, valid.ID); !errors.Is(err, scope.ErrLetterNotFound) {
		t.Fatalf("another tenant must not read the letter: %v", err)
	}
	if n, _ := letters.CountEntries(ctx, tenant, valid.ID); n != 1 {
		t.Fatalf("entries naming the letter: %d", n)
	}
	if l, _ := letters.List(ctx, tenant); len(l) != 2 {
		t.Fatalf("list: %d", len(l))
	}

	// The window check: valid_until within 2 years of valid_from.
	long := &scope.Letter{ID: shared.NewID(), TenantID: tenant, Title: "x", ValidFrom: now, ValidUntil: now.Add(800 * 24 * time.Hour),
		AttachmentID: shared.NewID(), FileSHA256: strings.Repeat("ab", 32), CreatedAt: now}
	if err := letters.Create(ctx, long); err == nil {
		t.Fatal("a letter longer than 2 years must be refused by the schema")
	}
}
