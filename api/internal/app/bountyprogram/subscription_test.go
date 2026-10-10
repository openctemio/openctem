package bountyprogram

import (
	"context"
	"errors"
	"testing"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeCatalog struct {
	programs map[shared.ID]*bp.PublicProgram
}

func (f *fakeCatalog) FeedState(context.Context) (bp.FeedState, error) { return bp.FeedState{}, nil }
func (f *fakeCatalog) ApplySnapshot(context.Context, bp.FeedState, []bp.PublicProgram) ([]bp.CatalogChange, error) {
	return nil, nil
}
func (f *fakeCatalog) ListPublic(context.Context, string, int, int) ([]bp.PublicProgram, int, error) {
	return nil, 0, nil
}
func (f *fakeCatalog) GetPublic(_ context.Context, id shared.ID) (*bp.PublicProgram, error) {
	p := f.programs[id]
	if p == nil {
		return nil, bp.ErrNotFound
	}
	cp := *p
	return &cp, nil
}
func (f *fakeCatalog) StaleSubscriptions(context.Context, int) ([]bp.ProgramRef, error) {
	return nil, nil
}

func publicProgram(t *testing.T, inScope ...string) *bp.PublicProgram {
	t.Helper()
	items := make([]bp.Item, 0, len(inScope)+1)
	for _, s := range inScope {
		it := bp.Classify(s)
		it.InScope = true
		items = append(items, it)
	}
	items = append(items, bp.Classify("admin.pub.example"))
	p := &bp.PublicProgram{ID: shared.NewID(), FeedID: "acme-bounty:pub", Platform: "acme-bounty", Handle: "pub",
		Name: "Pub", URL: "https://acme-bounty.example/pub", Open: true, Items: items, Source: "fixture",
		AsOf: time.Now()}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func activeCount(t *testing.T, repo *fakeRepo, tenant, id shared.ID) (active, total int) {
	t.Helper()
	es, _ := repo.Entries(context.Background(), tenant, id)
	for _, e := range es {
		if e.IsActive() {
			active++
		}
	}
	return active, len(es)
}

func TestSubscribe_PassiveUntilAccepted(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	cat := &fakeCatalog{programs: map[shared.ID]*bp.PublicProgram{}}
	pub := publicProgram(t, "*.pub.example", "api.other-pub.example")
	cat.programs[pub.ID] = pub
	l := &fakeLedger{}
	n := &notes{}
	svc := NewService(repo, fullData(false), nil)
	svc.SetCatalog(cat)
	svc.SetLedger(l)
	svc.SetNotifier(n)
	tenant, user := shared.NewID(), shared.NewID()

	p, _, err := svc.Subscribe(ctx, tenant, user, pub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != bp.StatusPendingAttestation || p.ScopeSource != bp.ScopeSourcePublicFeed || p.PublicProgramID == nil {
		t.Fatalf("program = %+v", p)
	}
	// No entry is in effect, nothing reached the signer ledger.
	if a, total := activeCount(t, repo, tenant, p.ID); a != 0 || total != 2 {
		t.Fatalf("active %d of %d entries before acceptance", a, total)
	}
	if l.put != 0 {
		t.Fatalf("ledger put %d before acceptance", l.put)
	}
	// A system call cannot subscribe; a second subscription is the repo's
	// uniqueness (not in the fake); another tenant gets its own.
	if _, _, err := svc.Subscribe(ctx, tenant, shared.ID{}, pub.ID); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("system subscribe: %v", err)
	}
	other := shared.NewID()
	if _, err := svc.Get(ctx, other, user, p.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}

	// Accepting the terms (Resume) puts the entries into effect through the
	// ledger with the attestation label.
	if _, err := svc.Resume(ctx, tenant, user, p.ID, "f00"); !errors.Is(err, bp.ErrTermsChanged) {
		t.Fatalf("stale acceptance: %v", err)
	}
	if _, err := svc.Resume(ctx, tenant, user, p.ID, p.TermsSHA256); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if a, _ := activeCount(t, repo, tenant, p.ID); a != 2 || l.put == 0 || l.policy != programAttestation {
		t.Fatalf("after acceptance: active %d, ledger put %d policy %q", a, l.put, l.policy)
	}

	// The feed only narrows: applied at once, still in effect.
	narrowed := publicProgram(t, "*.pub.example")
	narrowed.ID = pub.ID
	cat.programs[pub.ID] = narrowed
	out, err := svc.ApplyFeedChange(ctx, bp.ProgramRef{TenantID: tenant, ProgramID: p.ID})
	if err != nil || out != "narrowed" {
		t.Fatalf("narrow: %q %v", out, err)
	}
	if a, total := activeCount(t, repo, tenant, p.ID); a != 1 || total != 1 {
		t.Fatalf("after narrowing: active %d of %d", a, total)
	}
	got, _ := repo.GetByID(ctx, tenant, p.ID)
	if got.Status != bp.StatusActive || got.TermsSHA256 != narrowed.TermsSHA256 {
		t.Fatalf("after narrowing: %+v", got)
	}
	// Applying the same catalog again changes nothing.
	if out, _ := svc.ApplyFeedChange(ctx, bp.ProgramRef{TenantID: tenant, ProgramID: p.ID}); out != "" {
		t.Fatalf("idempotent: %q", out)
	}

	// The feed widens: every entry stops until a member accepts again.
	widened := publicProgram(t, "*.pub.example", "new.pub-two.example")
	widened.ID = pub.ID
	cat.programs[pub.ID] = widened
	before := n.n
	out, err = svc.ApplyFeedChange(ctx, bp.ProgramRef{TenantID: tenant, ProgramID: p.ID})
	if err != nil || out != "needs_acceptance" {
		t.Fatalf("widen: %q %v", out, err)
	}
	if a, total := activeCount(t, repo, tenant, p.ID); a != 0 || total != 2 {
		t.Fatalf("after widening: active %d of %d", a, total)
	}
	if got, _ = repo.GetByID(ctx, tenant, p.ID); got.Status != bp.StatusPendingAttestation || n.n == before {
		t.Fatalf("after widening: status %s, notified %v", got.Status, n.n > before)
	}

	// Changed rules alone also ask again.
	if _, err := svc.Resume(ctx, tenant, user, p.ID, got.TermsSHA256); err != nil {
		t.Fatal(err)
	}
	rules := publicProgram(t, "*.pub.example", "new.pub-two.example")
	rules.ID, rules.Rules = pub.ID, bp.Rules{RateLimitRPS: 1}
	if err := rules.Validate(); err != nil {
		t.Fatal(err)
	}
	cat.programs[pub.ID] = rules
	if out, _ := svc.ApplyFeedChange(ctx, bp.ProgramRef{TenantID: tenant, ProgramID: p.ID}); out != "needs_acceptance" {
		t.Fatalf("rules change: %q", out)
	}

	// A closed program suspends an active subscription.
	if _, err := svc.Resume(ctx, tenant, user, p.ID, rules.TermsSHA256); err != nil {
		t.Fatal(err)
	}
	closed := *rules
	closed.Open = false
	cat.programs[pub.ID] = &closed
	if out, _ := svc.ApplyFeedChange(ctx, bp.ProgramRef{TenantID: tenant, ProgramID: p.ID}); out != "suspended" {
		t.Fatalf("closed: %q", out)
	}
	if a, _ := activeCount(t, repo, tenant, p.ID); a != 0 {
		t.Fatalf("active entries after the program closed: %d", a)
	}
	// A closed program cannot be followed.
	if _, _, err := svc.Subscribe(ctx, other, user, pub.ID); !errors.Is(err, bp.ErrPublicProgramGone) {
		t.Fatalf("subscribe to a closed program: %v", err)
	}
}

func TestSubscribe_GuardrailsApply(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	cat := &fakeCatalog{programs: map[shared.ID]*bp.PublicProgram{}}
	pub := publicProgram(t, "*.com", "ok.pub.example")
	cat.programs[pub.ID] = pub
	svc := NewService(repo, fullData(false), nil)
	svc.SetCatalog(cat)
	tenant := shared.NewID()
	p, pv, err := svc.Subscribe(ctx, tenant, shared.NewID(), pub.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range pv.Entries {
		if e.Pattern == "*.com" && e.Status != PlanRefused {
			t.Fatalf("*.com: %s", e.Status)
		}
	}
	es, _ := repo.Entries(ctx, tenant, p.ID)
	for _, e := range es {
		if e.Pattern() == "*.com" || e.Status() == scopedom.StatusActive {
			t.Fatalf("entry %s %s", e.Pattern(), e.Status())
		}
	}
}
