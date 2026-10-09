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
	byID    map[shared.ID]*scopedom.Letter
	entries []shared.ID
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
func (m *memLetters) EntryIDs(context.Context, shared.ID, shared.ID) ([]shared.ID, error) {
	return m.entries, nil
}

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

// letterLedger records what a revocation sends to the signer ledger hook.
type letterLedger struct {
	removed []shared.ID
	saved   bool
}

func (l *letterLedger) CommitEntries(_ context.Context, _ shared.ID, _ string, put []*scopedom.Target, removed []shared.ID,
	_ string, save func() error,
) error {
	if len(put) > 0 {
		return errors.New("a revocation never puts entries")
	}
	if err := save(); err != nil {
		return err
	}
	l.saved, l.removed = true, removed
	return nil
}

// Revoking a letter takes every entry naming it out of the job signer's
// ledger, after the revocation is saved (RFC-040 §11.5).
func TestLetterRevoke_FeedsTheSignerLedger(t *testing.T) {
	ctx := context.Background()
	tid, user := shared.NewID(), shared.NewID()
	now := time.Now()
	l := &scopedom.Letter{ID: shared.NewID(), TenantID: tid, Title: "x", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	e1, e2 := shared.NewID(), shared.NewID()
	repo := &memLetters{byID: map[shared.ID]*scopedom.Letter{l.ID: l}, entries: []shared.ID{e1, e2}}
	svc := scope.NewLetterService(repo, &memFiles{}, nil)
	ledger := &letterLedger{}
	svc.SetLedger(ledger)
	if _, err := svc.Revoke(ctx, tid, l.ID, user); err != nil {
		t.Fatal(err)
	}
	if !ledger.saved || len(ledger.removed) != 2 || l.RevokedAt == nil {
		t.Fatalf("revocation: saved=%v removed=%v revoked=%v", ledger.saved, ledger.removed, l.RevokedAt)
	}
	// A second revocation fails in the save; nothing more is sent.
	ledger.saved = false
	if _, err := svc.Revoke(ctx, tid, l.ID, user); !errors.Is(err, scopedom.ErrLetterRevoked) || ledger.saved {
		t.Fatalf("second revocation: %v", err)
	}
}

// A letter entry is in the signer's ledger only while its letter is in
// effect, and never past the letter's end.
func TestScopeLedger_LetterEntriesEndWithTheirLetter(t *testing.T) {
	ctx := context.Background()
	svc, _, _, ledger := ledgerScopeService(t, 1)
	tid := shared.NewID()
	now := time.Now().UTC()
	l := &scopedom.Letter{ID: shared.NewID(), TenantID: tid, Title: "x", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(48 * time.Hour)}
	repo := &memLetters{byID: map[shared.ID]*scopedom.Letter{l.ID: l}}
	svc.SetLetters(repo)
	e, err := create(svc, tid, uuidActor(), "a.client.example", func(in *scope.CreateTargetInput) {
		in.AuthorizationSource, in.LetterID = "authorization_letter", l.ID.String()
	})
	if err != nil || !e.IsActive() {
		t.Fatalf("letter entry: %v active=%v", err, e != nil && e.IsActive())
	}
	if len(ledger.changes) != 1 || len(ledger.changes[0].Ops) != 1 || ledger.changes[0].Ops[0].Entry == nil {
		t.Fatalf("ledger changes: %+v", ledger.changes)
	}
	got := ledger.changes[0].Ops[0].Entry.ExpiresAt
	if got == nil || !got.Equal(l.ValidUntil) {
		t.Fatalf("ledger expiry %v, want the letter end %v", got, l.ValidUntil)
	}

	snap, err := svc.LedgerSnapshot(ctx, tid.String())
	if err != nil || len(snap.Entries) != 1 || !snap.Entries[0].ExpiresAt.Equal(l.ValidUntil) {
		t.Fatalf("snapshot: %+v %v", snap.Entries, err)
	}
	// Revoked (or expired): out of the snapshot, so the next sync narrows it.
	l.RevokedAt = &now
	if snap, _ := svc.LedgerSnapshot(ctx, tid.String()); len(snap.Entries) != 0 {
		t.Fatalf("a revoked letter entry stays in the snapshot: %+v", snap.Entries)
	}
}
