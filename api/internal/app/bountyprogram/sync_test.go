package bountyprogram

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (f *fakeRepo) SaveSync(_ context.Context, p *bp.Program) error {
	f.programs[p.ID] = p
	return nil
}

func (f *fakeRepo) SyncDue(context.Context, time.Time, int) ([]bp.ProgramRef, error) {
	var out []bp.ProgramRef
	for _, p := range f.programs {
		if p.ScopeSource != bp.ScopeSourcePaste && p.Status == bp.StatusActive {
			out = append(out, bp.ProgramRef{TenantID: p.TenantID, ProgramID: p.ID})
		}
	}
	return out, nil
}

type fakeFetcher struct {
	text  string
	open  bool
	err   error
	user  string
	token string
}

func (f *fakeFetcher) FetchFile(context.Context, string) ([]bp.Item, error) {
	if f.err != nil {
		return nil, f.err
	}
	return bp.ParseScope(f.text)
}

func (f *fakeFetcher) FetchAPI(_ context.Context, _, user, token string) ([]bp.Item, bool, error) {
	f.user, f.token = user, token
	if f.err != nil {
		return nil, false, f.err
	}
	items, err := bp.ParseScope(f.text)
	return items, f.open, err
}

// rot13ish: a reversible fake cipher that never stores the plain token.
type fakeCipher struct{ fail bool }

func (c fakeCipher) EncryptString(p string) (string, error) { return "enc:" + strings.ToUpper(p), nil }
func (c fakeCipher) DecryptString(e string) (string, error) {
	if c.fail || !strings.HasPrefix(e, "enc:") {
		return "", errors.New("cannot decrypt")
	}
	return strings.ToLower(strings.TrimPrefix(e, "enc:")), nil
}

var errGone = errors.New("gone")

func syncService(t *testing.T) (*Service, *fakeRepo, *fakeFetcher, *bp.Program, shared.ID) {
	t.Helper()
	repo := newFakeRepo()
	svc := NewService(repo, fullData(false), nil)
	fetch := &fakeFetcher{open: true}
	svc.SetSync(fetch, fakeCipher{}, func(err error) bool { return errors.Is(err, errGone) }, nil)
	tenant, user := shared.NewID(), shared.NewID()
	in := input()
	in.ScopeText = "*.acme.example\nacme.example\n-admin.acme.example\nshop.acme.example\n"
	pv, err := svc.Preview(context.Background(), tenant, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	in.AcceptTermsSHA256 = pv.TermsSHA256
	p, _, err := svc.Import(context.Background(), tenant, user, in)
	if err != nil {
		t.Fatal(err)
	}
	return svc, repo, fetch, p, user
}

func patterns(t *testing.T, repo *fakeRepo, p *bp.Program) map[string]bool {
	t.Helper()
	es, _ := repo.Entries(context.Background(), p.TenantID, p.ID)
	out := map[string]bool{}
	for _, e := range es {
		out[e.Pattern()] = true
	}
	return out
}

func TestSetSource(t *testing.T) {
	ctx := context.Background()
	svc, repo, _, p, user := syncService(t)
	// A scope file must be on the program's own domain.
	if _, err := svc.ConfigureSource(ctx, p.TenantID, user, p.ID, bp.SyncSourceInput{Source: bp.ScopeSourceFile,
		URL: "https://evil.example/scope.txt"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("foreign scope file: %v", err)
	}
	if _, err := svc.ConfigureSource(ctx, p.TenantID, user, p.ID, bp.SyncSourceInput{Source: bp.ScopeSourceFile,
		URL: "http://acme.example/scope.txt"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("http scope file: %v", err)
	}
	if _, err := svc.ConfigureSource(ctx, p.TenantID, user, p.ID, bp.SyncSourceInput{Source: bp.ScopeSourceFile,
		URL: "https://security.acme.example/scope.txt"}); err != nil {
		t.Fatal(err)
	}
	// The API needs a token the first time; it is stored encrypted only.
	if _, err := svc.ConfigureSource(ctx, p.TenantID, user, p.ID, bp.SyncSourceInput{Source: bp.ScopeSourceAPI,
		Handle: "acme", Username: "jdoe"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no token: %v", err)
	}
	got, err := svc.ConfigureSource(ctx, p.TenantID, user, p.ID, bp.SyncSourceInput{Source: bp.ScopeSourceAPI,
		Handle: "acme", Username: "jdoe", Token: "secret"})
	if err != nil || got.Sync.TokenEncrypted != "enc:SECRET" || strings.Contains(got.Sync.TokenEncrypted, "secret") {
		t.Fatalf("token: %+v %v", got.Sync, err)
	}
	// An empty token keeps the stored one.
	got, _ = svc.ConfigureSource(ctx, p.TenantID, user, p.ID, bp.SyncSourceInput{Source: bp.ScopeSourceAPI,
		Handle: "acme2", Username: "jdoe"})
	if got.Sync.TokenEncrypted != "enc:SECRET" || got.Sync.Handle != "acme2" {
		t.Fatalf("kept token: %+v", got.Sync)
	}
	// An outsider gets not found.
	if _, err := svc.ConfigureSource(ctx, p.TenantID, shared.NewID(), p.ID, bp.SyncSourceInput{Source: bp.ScopeSourcePaste}); !errors.Is(err, bp.ErrNotFound) {
		t.Fatalf("outsider: %v", err)
	}
	_ = repo
}

func TestSync_NarrowsAtOnceAndWidensOnAcceptance(t *testing.T) {
	ctx := context.Background()
	svc, repo, fetch, p, user := syncService(t)
	if _, err := svc.Sync(ctx, p.TenantID, user, p.ID); !errors.Is(err, bp.ErrSyncNotConfigured) {
		t.Fatalf("paste program: %v", err)
	}
	if _, err := svc.ConfigureSource(ctx, p.TenantID, user, p.ID, bp.SyncSourceInput{Source: bp.ScopeSourceAPI,
		Handle: "acme", Username: "jdoe", Token: "secret"}); err != nil {
		t.Fatal(err)
	}

	// The source dropped shop.acme.example, added api.acme.example and a new
	// out-of-scope name.
	fetch.text = "*.acme.example\nacme.example\napi.other.example\n-admin.acme.example\n-old.acme.example\n"
	res, err := svc.Sync(ctx, p.TenantID, user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetch.user != "jdoe" || fetch.token != "secret" {
		t.Fatalf("credentials: %s %s", fetch.user, fetch.token)
	}
	got := patterns(t, repo, p)
	if got["shop.acme.example"] || !got["*.acme.example"] || got["api.other.example"] {
		t.Fatalf("narrowing at once, widening pending: %v", got)
	}
	if res.RemovedEntries != 1 || res.AddedExclusions != 1 || res.PendingAdditions != 1 {
		t.Fatalf("result: %+v", res)
	}
	ex, _ := repo.Exclusions(ctx, p.TenantID, &p.ID)
	hasOld := false
	for _, x := range ex {
		hasOld = hasOld || x.Pattern == "old.acme.example"
	}
	if !hasOld {
		t.Fatalf("new out-of-scope item: %+v", ex)
	}
	cur := repo.programs[p.ID]
	if cur.Pending == nil || cur.Sync.LastSyncedAt == nil || cur.Sync.LastError != "" {
		t.Fatalf("pending: %+v %+v", cur.Pending, cur.Sync)
	}

	// Accepting needs the pending hash.
	if _, _, err := svc.Accept(ctx, p.TenantID, user, p.ID, cur.TermsSHA256); !errors.Is(err, bp.ErrTermsChanged) {
		t.Fatalf("old hash: %v", err)
	}
	pv, err := svc.Pending(ctx, p.TenantID, user, p.ID)
	if err != nil || pv.TermsSHA256 != cur.Pending.TermsSHA256 {
		t.Fatalf("pending preview: %v", err)
	}
	if _, _, err := svc.Accept(ctx, p.TenantID, user, p.ID, cur.Pending.TermsSHA256); err != nil {
		t.Fatal(err)
	}
	if !patterns(t, repo, p)["api.other.example"] || repo.programs[p.ID].Pending != nil {
		t.Fatal("accepting adds the new entries and clears the pending terms")
	}
	if _, _, err := svc.Accept(ctx, p.TenantID, user, p.ID, "x"); !errors.Is(err, bp.ErrNoPendingTerms) {
		t.Fatalf("nothing pending: %v", err)
	}

	// A source that no longer widens clears an older pending.
	fetch.text = "*.acme.example\nacme.example\napi.other.example\n-admin.acme.example\n-old.acme.example\n"
	if _, err := svc.Sync(ctx, p.TenantID, user, p.ID); err != nil || repo.programs[p.ID].Pending != nil {
		t.Fatalf("same scope: %v %+v", err, repo.programs[p.ID].Pending)
	}
}

func TestSync_ClosedAndFailing(t *testing.T) {
	ctx := context.Background()
	svc, repo, fetch, p, user := syncService(t)
	if _, err := svc.ConfigureSource(ctx, p.TenantID, user, p.ID, bp.SyncSourceInput{Source: bp.ScopeSourceAPI,
		Handle: "acme", Username: "jdoe", Token: "secret"}); err != nil {
		t.Fatal(err)
	}
	// A failing source keeps the scope and records the error.
	fetch.err = errors.New("timeout")
	if _, err := svc.Sync(ctx, p.TenantID, user, p.ID); !errors.Is(err, bp.ErrSyncFailed) {
		t.Fatalf("failing: %v", err)
	}
	if repo.programs[p.ID].Sync.LastError == "" || repo.programs[p.ID].Status != bp.StatusActive || len(patterns(t, repo, p)) == 0 {
		t.Fatal("a failing source keeps the scope")
	}
	// Gone and never synced: suspended.
	fetch.err = errGone
	res, err := svc.Sync(ctx, p.TenantID, user, p.ID)
	if !errors.Is(err, bp.ErrSyncFailed) || res == nil || !res.Suspended || repo.programs[p.ID].Status != bp.StatusPaused {
		t.Fatalf("gone: %+v %v", res, err)
	}

	// A closed program is suspended.
	svc2, repo2, fetch2, p2, user2 := syncService(t)
	_, _ = svc2.ConfigureSource(ctx, p2.TenantID, user2, p2.ID, bp.SyncSourceInput{Source: bp.ScopeSourceAPI,
		Handle: "acme", Username: "jdoe", Token: "secret"})
	fetch2.open = false
	fetch2.text = "*.acme.example\nacme.example\n-admin.acme.example\nshop.acme.example\n"
	if res, err := svc2.Sync(ctx, p2.TenantID, user2, p2.ID); err != nil || !res.Suspended || repo2.programs[p2.ID].Status != bp.StatusPaused {
		t.Fatalf("closed: %+v %v", res, err)
	}

	// SECURITY: a token that does not decrypt is never used (fail closed).
	svc3, _, fetch3, p3, user3 := syncService(t)
	_, _ = svc3.ConfigureSource(ctx, p3.TenantID, user3, p3.ID, bp.SyncSourceInput{Source: bp.ScopeSourceAPI,
		Handle: "acme", Username: "jdoe", Token: "secret"})
	svc3.cipher = fakeCipher{fail: true}
	if _, err := svc3.Sync(ctx, p3.TenantID, user3, p3.ID); !errors.Is(err, bp.ErrSyncFailed) || fetch3.token != "" {
		t.Fatalf("undecryptable token: %v token=%q", err, fetch3.token)
	}

	// The controller syncs due programs as the system.
	svc4, _, fetch4, p4, user4 := syncService(t)
	_, _ = svc4.ConfigureSource(ctx, p4.TenantID, user4, p4.ID, bp.SyncSourceInput{Source: bp.ScopeSourceAPI,
		Handle: "acme", Username: "jdoe", Token: "secret"})
	fetch4.text = "*.acme.example\nacme.example\n-admin.acme.example\nshop.acme.example\n"
	if n, err := svc4.SyncDue(ctx, time.Hour, 10); err != nil || n != 1 {
		t.Fatalf("due: %d %v", n, err)
	}
}

// A sync writes through the job signer ledger hook (RFC-040 §11.5): its
// narrowing takes entries out, an accepted widening puts entries in under
// the program attestation (refused: nothing saved), a closed program takes
// every entry out.
func TestSync_FeedsTheSignerLedger(t *testing.T) {
	ctx := context.Background()
	svc, repo, fetch, p, user := syncService(t)
	l := &fakeLedger{}
	svc.SetLedger(l)
	if _, err := svc.ConfigureSource(ctx, p.TenantID, user, p.ID, bp.SyncSourceInput{Source: bp.ScopeSourceAPI,
		Handle: "acme", Username: "jdoe", Token: "secret"}); err != nil {
		t.Fatal(err)
	}
	fetch.text = "*.acme.example\nacme.example\napi.other.example\n-admin.acme.example\n"
	if _, err := svc.Sync(ctx, p.TenantID, user, p.ID); err != nil {
		t.Fatal(err)
	}
	if l.removed != 1 || l.put != 0 {
		t.Fatalf("narrowing sent put=%d removed=%d", l.put, l.removed)
	}

	pending := repo.programs[p.ID].Pending.TermsSHA256
	stored := *repo.programs[p.ID] // the fake hands out its own pointer; a database read would not
	l.refuse = true
	if _, _, err := svc.Accept(ctx, p.TenantID, user, p.ID, pending); err == nil || patterns(t, repo, p)["api.other.example"] {
		t.Fatalf("a widening the signer refused was saved: %v", err)
	}
	repo.programs[p.ID] = &stored
	l.refuse = false
	if _, _, err := svc.Accept(ctx, p.TenantID, user, p.ID, pending); err != nil {
		t.Fatal(err)
	}
	if l.put == 0 || l.policy != programAttestation {
		t.Fatalf("accepted widening sent %d entries under %q", l.put, l.policy)
	}

	fetch.open = false
	before := l.removed
	if res, err := svc.Sync(ctx, p.TenantID, user, p.ID); err != nil || !res.Suspended {
		t.Fatalf("closed: %+v %v", res, err)
	}
	if n := len(patterns(t, repo, p)); l.removed-before != n || n == 0 {
		t.Fatalf("suspension removed %d of %d entries", l.removed-before, n)
	}
}
