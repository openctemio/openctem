package unit

// Authorization letters (RFC-065 §13): upload records the file hash and
// refuses bad files and dates; a letter entry names a valid letter of the
// tenant and follows the approval policy.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type memLetters struct {
	byID map[shared.ID]*scopedom.Letter
}

func (m *memLetters) Create(_ context.Context, l *scopedom.Letter) error {
	m.byID[l.ID] = l
	return nil
}
func (m *memLetters) GetByID(_ context.Context, tid, id shared.ID) (*scopedom.Letter, error) {
	l := m.byID[id]
	if l == nil || !l.TenantID.Equals(tid) {
		return nil, scopedom.ErrLetterNotFound
	}
	return l, nil
}
func (m *memLetters) List(context.Context, shared.ID) ([]*scopedom.Letter, error) { return nil, nil }
func (m *memLetters) Revoke(_ context.Context, tid, id, by shared.ID, at time.Time) error {
	l, err := m.GetByID(context.Background(), tid, id)
	if err != nil {
		return err
	}
	if l.RevokedAt != nil {
		return scopedom.ErrLetterRevoked
	}
	l.RevokedAt, l.RevokedBy = &at, &by
	return nil
}
func (m *memLetters) CountEntries(context.Context, shared.ID, shared.ID) (int, error) { return 0, nil }

type memFiles struct{ got []byte }

func (m *memFiles) Store(_ context.Context, _, _ shared.ID, _, _ string, _ int64, r io.Reader) (shared.ID, error) {
	b, err := io.ReadAll(r)
	m.got = b
	return shared.NewID(), err
}
func (m *memFiles) Open(context.Context, shared.ID, shared.ID) (io.ReadCloser, string, string, error) {
	return io.NopCloser(bytes.NewReader(nil)), "application/pdf", "x.pdf", nil
}

func TestLetterUpload(t *testing.T) {
	ctx := context.Background()
	repo := &memLetters{byID: map[shared.ID]*scopedom.Letter{}}
	files := &memFiles{}
	notes := 0
	svc := scope.NewLetterService(repo, files, func(context.Context, shared.ID, string, string) { notes++ })
	tid, user := shared.NewID(), shared.NewID()
	body := []byte("%PDF-1.7 letter")
	in := scope.UploadLetterInput{TenantID: tid, UploadedBy: user, Title: "Acme engagement", Issuer: "Acme Ltd",
		ValidUntil: time.Now().Add(90 * 24 * time.Hour), Filename: "loa.pdf", ContentType: "application/pdf",
		Size: int64(len(body)), File: bytes.NewReader(body)}
	l, err := svc.Upload(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if l.FileSHA256 != hex.EncodeToString(sum[:]) || !bytes.Equal(files.got, body) || !l.InEffect(time.Now()) {
		t.Fatalf("letter: %+v", l)
	}

	bad := []func(*scope.UploadLetterInput){
		func(i *scope.UploadLetterInput) { i.ContentType = "text/html" },
		func(i *scope.UploadLetterInput) { i.ContentType = "image/svg+xml" },
		func(i *scope.UploadLetterInput) { i.Title = " " },
		func(i *scope.UploadLetterInput) { i.ValidUntil = time.Now().Add(-time.Hour) },
		func(i *scope.UploadLetterInput) { i.ValidUntil = time.Now().Add(3 * 365 * 24 * time.Hour) },
		func(i *scope.UploadLetterInput) { i.Size = scope.MaxLetterFileSize + 1 },
		func(i *scope.UploadLetterInput) { i.Size = 0 },
	}
	for n, mut := range bad {
		c := in
		c.File = bytes.NewReader(body)
		mut(&c)
		if _, err := svc.Upload(ctx, c); err == nil {
			t.Errorf("case %d must be refused", n)
		}
	}

	if _, err := svc.Revoke(ctx, tid, l.ID, user); err != nil || notes != 1 {
		t.Fatalf("revoke: %v notes=%d", err, notes)
	}
	if _, err := svc.Revoke(ctx, shared.NewID(), l.ID, user); !errors.Is(err, scopedom.ErrLetterNotFound) {
		t.Fatalf("another tenant: %v", err)
	}
}

func TestScopeEntry_LetterSource(t *testing.T) {
	svc, _, _ := entryService(t, 2, tenant.ScopeSettings{})
	tid := shared.NewID()
	repo := &memLetters{byID: map[shared.ID]*scopedom.Letter{}}
	now := time.Now()
	mk := func(tenantID shared.ID, from, until time.Time, revoked bool) *scopedom.Letter {
		l := &scopedom.Letter{ID: shared.NewID(), TenantID: tenantID, Title: "x", ValidFrom: from, ValidUntil: until}
		if revoked {
			l.RevokedAt = &now
		}
		repo.byID[l.ID] = l
		return l
	}
	valid := mk(tid, now.Add(-time.Hour), now.Add(time.Hour), false)
	expired := mk(tid, now.Add(-2*time.Hour), now.Add(-time.Hour), false)
	revoked := mk(tid, now.Add(-time.Hour), now.Add(time.Hour), true)
	foreign := mk(shared.NewID(), now.Add(-time.Hour), now.Add(time.Hour), false)

	letter := func(id string) func(*scope.CreateTargetInput) {
		return func(in *scope.CreateTargetInput) { in.AuthorizationSource = "authorization_letter"; in.LetterID = id }
	}
	// Not wired: refused (fail closed).
	if _, err := create(svc, tid, approverA, "a.client.example", letter(valid.ID.String())); !errors.Is(err, scopedom.ErrLetterNotValid) {
		t.Fatalf("not wired: %v", err)
	}
	svc.SetLetters(repo)
	for name, c := range map[string]struct {
		id   string
		want error
	}{
		"no letter":      {"", scopedom.ErrLetterRequired},
		"expired":        {expired.ID.String(), scopedom.ErrLetterNotValid},
		"revoked":        {revoked.ID.String(), scopedom.ErrLetterNotValid},
		"another tenant": {foreign.ID.String(), scopedom.ErrLetterNotFound},
		"not an id":      {"nope", scopedom.ErrLetterNotFound},
	} {
		if _, err := create(svc, tid, approverA, "b.client.example", letter(c.id)); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	e, err := create(svc, tid, approverA, "c.client.example", letter(valid.ID.String()))
	if err != nil {
		t.Fatal(err)
	}
	// The approval policy applies: a two-admin organization needs the other admin.
	if !e.IsPending() || e.AuthorizationSource() != scopedom.AuthLetter || !e.LetterID().Equals(valid.ID) {
		t.Fatalf("letter entry: pending=%v source=%v", e.IsPending(), e.AuthorizationSource())
	}
}
