package unit

// Letter entries (RFC-065 §13) and the job signer's ledger: a letter entry
// authorizes only while its letter does, so the ledger holds it with the
// letter's valid_until as its latest expiry, and a revoked letter's entries
// leave the ledger at once instead of at the next periodic sync.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeLetters struct {
	byID map[shared.ID]*scopedom.Letter
}

func (f *fakeLetters) Create(_ context.Context, l *scopedom.Letter) error {
	f.byID[l.ID] = l
	return nil
}

func (f *fakeLetters) GetByID(_ context.Context, tenantID, id shared.ID) (*scopedom.Letter, error) {
	l, ok := f.byID[id]
	if !ok || l.TenantID != tenantID {
		return nil, scopedom.ErrLetterNotFound
	}
	return l, nil
}

func (f *fakeLetters) List(context.Context, shared.ID) ([]*scopedom.Letter, error) { return nil, nil }

func (f *fakeLetters) Revoke(_ context.Context, tenantID, id, by shared.ID, at time.Time) error {
	l, ok := f.byID[id]
	if !ok || l.TenantID != tenantID {
		return scopedom.ErrLetterNotFound
	}
	l.RevokedAt, l.RevokedBy = &at, &by
	return nil
}

func (f *fakeLetters) CountEntries(context.Context, shared.ID, shared.ID) (int, error) { return 1, nil }

func letterLedgerService(t *testing.T, until time.Time) (*scope.Service, *fakeLedger, *fakeLetters, *scopedom.Letter, shared.ID) {
	t.Helper()
	svc, _, _, l := ledgerScopeService(t, 1) // one admin: the approver's entry is in effect at once
	tenantID := shared.NewID()
	letter := &scopedom.Letter{ID: shared.NewID(), TenantID: tenantID, Title: "LoA",
		ValidFrom: time.Now().Add(-time.Hour), ValidUntil: until}
	letters := &fakeLetters{byID: map[shared.ID]*scopedom.Letter{letter.ID: letter}}
	svc.SetLetters(letters)
	return svc, l, letters, letter, tenantID
}

func createLetterEntry(t *testing.T, svc *scope.Service, tenantID shared.ID, letter *scopedom.Letter, expires *time.Time) *scopedom.Target {
	t.Helper()
	e, err := create(svc, tenantID, uuidActor(), "*.client.example", func(in *scope.CreateTargetInput) {
		in.AuthorizationSource = string(scopedom.AuthLetter)
		in.LetterID = letter.ID.String()
		in.ExpiresAt = expires
		in.Reason = "engagement window"
	})
	if err != nil {
		t.Fatal(err)
	}
	if !e.InEffect(time.Now()) {
		t.Fatalf("entry not in effect: %s", e.Status())
	}
	return e
}

func TestScopeLedger_LetterEntryExpiresWithItsLetter(t *testing.T) {
	until := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	svc, l, _, letter, tenantID := letterLedgerService(t, until)
	createLetterEntry(t, svc, tenantID, letter, nil) // the entry itself never expires
	if len(l.changes) != 1 {
		t.Fatalf("changes %d", len(l.changes))
	}
	got := l.changes[0].Ops[0].Entry
	if got == nil || got.ExpiresAt == nil || !got.ExpiresAt.Equal(until) {
		t.Fatalf("ledger entry %+v: want expiry at the letter's valid_until %s", got, until)
	}
}

func TestScopeLedger_LetterEntryKeepsItsOwnEarlierExpiry(t *testing.T) {
	svc, l, _, letter, tenantID := letterLedgerService(t, time.Now().Add(30*24*time.Hour))
	own := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	createLetterEntry(t, svc, tenantID, letter, &own)
	got := l.changes[0].Ops[0].Entry
	if got == nil || got.ExpiresAt == nil || !got.ExpiresAt.Equal(own) {
		t.Fatalf("ledger entry %+v: want the entry's own earlier expiry %s", got, own)
	}
}

func TestScopeLedger_RevokedLetterLeavesTheLedgerAtOnce(t *testing.T) {
	svc, l, letters, letter, tenantID := letterLedgerService(t, time.Now().Add(72*time.Hour))
	e := createLetterEntry(t, svc, tenantID, letter, nil)

	ls := scope.NewLetterService(letters, nil, nil)
	ls.OnRevoke(svc.NarrowLetter)
	if _, err := ls.Revoke(context.Background(), tenantID, letter.ID, shared.NewID()); err != nil {
		t.Fatal(err)
	}
	if len(l.syncs) != 1 {
		t.Fatalf("revoking the letter sent %d syncs, want 1", len(l.syncs))
	}
	snap := l.syncs[0]
	if snap.TenantID != tenantID.String() {
		t.Fatalf("sync for tenant %s", snap.TenantID)
	}
	for _, x := range snap.Entries {
		if x.ID == e.ID().String() {
			t.Fatalf("the revoked letter's entry is still in the snapshot: %+v", x)
		}
	}
}

func TestScopeLedger_SnapshotLeavesOutEntriesOfALetterNotInEffect(t *testing.T) {
	svc, _, _, letter, tenantID := letterLedgerService(t, time.Now().Add(72*time.Hour))
	e := createLetterEntry(t, svc, tenantID, letter, nil)
	letter.ValidUntil = time.Now().Add(-time.Minute) // the letter ran out
	snap, err := svc.LedgerSnapshot(context.Background(), tenantID.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range snap.Entries {
		if x.ID == e.ID().String() {
			t.Fatalf("an expired letter's entry is in the snapshot: %+v", x)
		}
	}
}
