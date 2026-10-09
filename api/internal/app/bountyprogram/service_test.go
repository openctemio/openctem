package bountyprogram

import (
	"context"
	"errors"
	"testing"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeRepo keeps programs, entries and memberships in memory, per tenant.
type fakeRepo struct {
	programs map[shared.ID]*bp.Program
	entries  map[shared.ID]*scopedom.Target
	excl     map[shared.ID][]bp.Exclusion
	members  map[shared.ID]map[shared.ID]bool // program -> users
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{programs: map[shared.ID]*bp.Program{}, entries: map[shared.ID]*scopedom.Target{},
		excl: map[shared.ID][]bp.Exclusion{}, members: map[shared.ID]map[shared.ID]bool{}}
}

func (f *fakeRepo) Import(_ context.Context, w bp.ImportWrite) error {
	for _, p := range f.programs {
		if p.TenantID.Equals(w.Program.TenantID) && p.Name == w.Program.Name {
			return bp.ErrNameTaken
		}
	}
	gid := w.Group.ID
	w.Program.GroupID = &gid
	f.programs[w.Program.ID] = w.Program
	f.members[w.Program.ID] = map[shared.ID]bool{}
	if w.Group.Member != nil {
		f.members[w.Program.ID][*w.Group.Member] = true
	}
	for _, e := range w.Entries {
		f.entries[e.ID()] = e
	}
	f.excl[w.Program.ID] = w.Exclusions
	return nil
}

func (f *fakeRepo) ReplaceScope(_ context.Context, w bp.ScopeWrite) error {
	for _, id := range w.DeleteEntryIDs {
		delete(f.entries, id)
	}
	for _, e := range w.CreateEntries {
		f.entries[e.ID()] = e
	}
	f.excl[w.Program.ID] = w.Exclusions
	return nil
}

func (f *fakeRepo) SetStatus(_ context.Context, p *bp.Program, st scopedom.Status) error {
	for _, e := range f.entries {
		if e.ProgramID() != nil && e.ProgramID().Equals(p.ID) {
			if st == scopedom.StatusActive {
				e.Activate()
			} else {
				e.Deactivate()
			}
		}
	}
	return nil
}

func (f *fakeRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*bp.Program, error) {
	p := f.programs[id]
	if p == nil || !p.TenantID.Equals(tenantID) {
		return nil, bp.ErrNotFound
	}
	return p, nil
}

func (f *fakeRepo) List(_ context.Context, tenantID shared.ID, memberOf *shared.ID) ([]*bp.Program, error) {
	var out []*bp.Program
	for id, p := range f.programs {
		if p.TenantID.Equals(tenantID) && (memberOf == nil || f.members[id][*memberOf]) {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeRepo) Entries(_ context.Context, tenantID, programID shared.ID) ([]*scopedom.Target, error) {
	var out []*scopedom.Target
	for _, e := range f.entries {
		if e.TenantID().Equals(tenantID) && e.ProgramID() != nil && e.ProgramID().Equals(programID) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeRepo) TenantEntries(_ context.Context, tenantID shared.ID) ([]*scopedom.Target, error) {
	var out []*scopedom.Target
	for _, e := range f.entries {
		if e.TenantID().Equals(tenantID) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeRepo) Exclusions(_ context.Context, _ shared.ID, programID *shared.ID) ([]bp.Exclusion, error) {
	if programID != nil {
		return f.excl[*programID], nil
	}
	var out []bp.Exclusion
	for _, x := range f.excl {
		out = append(out, x...)
	}
	return out, nil
}

func (f *fakeRepo) IsMember(_ context.Context, tenantID, programID, userID shared.ID) (bool, error) {
	p := f.programs[programID]
	return p != nil && p.TenantID.Equals(tenantID) && f.members[programID][userID], nil
}

func (f *fakeRepo) MemberProgramIDs(context.Context, shared.ID, shared.ID) ([]shared.ID, error) {
	return nil, nil
}

type fullData bool

func (f fullData) FullDataCaller(context.Context, shared.ID) (bool, error) { return bool(f), nil }

type notes struct{ n int }

func (n *notes) NotifyAdmins(context.Context, shared.ID, string, string) { n.n++ }

const paste = "*.acme.example\nshop.other.example\n-admin.acme.example\ncom\n"

func input() Input {
	return Input{Name: "Acme", Platform: "self", Handle: "jdoe", ProgramURL: "https://acme.example/security",
		ScopeText: paste, Rules: bp.Rules{RateLimitRPS: 5}}
}

func TestPreviewAndImport(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	tenant, user := shared.NewID(), shared.NewID()
	// An ownership entry the organization already has.
	own, _ := scopedom.NewEntry(tenant, scopedom.TargetTypeDomain, "*.admin.acme.example", "", "o", scopedom.EntryOptions{MaxTier: scopedom.TierActive})
	repo.entries[own.ID()] = own
	n := &notes{}
	svc := NewService(repo, fullData(false), nil)
	svc.SetNotifier(n)

	pv, err := svc.Preview(ctx, tenant, input(), nil)
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, e := range pv.Entries {
		status[e.Pattern] = e.Status
	}
	if status["*.acme.example"] != PlanCreate || status["shop.other.example"] != PlanCreate {
		t.Fatalf("entries: %+v", pv.Entries)
	}
	// "com" is not a host name: not scannable, never an entry.
	if _, ok := status["com"]; ok {
		t.Fatalf("a bare label must not become an entry: %+v", pv.Entries)
	}
	var apex, overlap bool
	for _, x := range pv.Exclusions {
		if x.Pattern == "acme.example" && x.Reason == bp.ReasonApexNotListed {
			apex = true
		}
		if x.Pattern == "admin.acme.example" && x.InScopeBy != nil && x.InScopeBy.EntryID == own.ID().String() {
			overlap = true
		}
	}
	if !apex || !overlap {
		t.Fatalf("exclusions: %+v", pv.Exclusions)
	}
	if pv.MaxTier != "t1" || len(pv.TermsSHA256) != 64 {
		t.Fatalf("tier %s terms %s", pv.MaxTier, pv.TermsSHA256)
	}

	// Without the attestation, or with a stale one, nothing is created.
	if _, _, err := svc.Import(ctx, tenant, user, input()); !errors.Is(err, bp.ErrTermsRequired) {
		t.Fatalf("no attestation: %v", err)
	}
	in := input()
	in.AcceptTermsSHA256 = pv.TermsSHA256
	in.ScopeText += "extra.acme.example\n"
	if _, _, err := svc.Import(ctx, tenant, user, in); !errors.Is(err, bp.ErrTermsChanged) {
		t.Fatalf("changed paste: %v", err)
	}
	in = input()
	in.AcceptTermsSHA256 = pv.TermsSHA256
	if _, _, err := svc.Import(ctx, tenant, shared.ID{}, in); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("a system call must not import: %v", err)
	}
	p, _, err := svc.Import(ctx, tenant, user, in)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := repo.Entries(ctx, tenant, p.ID)
	if len(entries) != 2 {
		t.Fatalf("entries: %d", len(entries))
	}
	for _, e := range entries {
		if !e.IsActive() || !e.IsProgramEntry() || e.MaxTier() != scopedom.TierActive || e.ApprovalsRequired() != 0 {
			t.Fatalf("program entry: active=%v source=%s tier=%v approvals=%d", e.IsActive(), e.AuthorizationSource(), e.MaxTier(), e.ApprovalsRequired())
		}
	}
	if n.n != 1 {
		t.Fatalf("administrators notified %d times", n.n)
	}
	if ok, _ := repo.IsMember(ctx, tenant, p.ID, user); !ok {
		t.Fatal("the importer joins the program's group")
	}
	// The organization's own entry is untouched.
	if !own.IsActive() || own.IsProgramEntry() {
		t.Fatal("an ownership entry must not change")
	}
}

func TestAutomatedScanningForbidden_PassiveOnly(t *testing.T) {
	ctx := context.Background()
	svc := NewService(newFakeRepo(), fullData(true), nil)
	in := input()
	in.Rules.Forbidden = []string{bp.ForbidAutomatedScanning}
	pv, err := svc.Preview(ctx, shared.NewID(), in, nil)
	if err != nil || pv.MaxTier != "t0" {
		t.Fatalf("tier %v %v", pv, err)
	}
}

func TestAccess_MembersAndFullData(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	tenant, owner, member, outsider := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	importer := NewService(repo, fullData(false), nil)
	pv, _ := importer.Preview(ctx, tenant, input(), nil)
	in := input()
	in.AcceptTermsSHA256 = pv.TermsSHA256
	p, _, err := importer.Import(ctx, tenant, member, in)
	if err != nil {
		t.Fatal(err)
	}

	restricted := NewService(repo, fullData(false), nil)
	if _, err := restricted.Get(ctx, tenant, outsider, p.ID); !errors.Is(err, bp.ErrNotFound) {
		t.Fatalf("an outsider must get not found: %v", err)
	}
	if _, err := restricted.Pause(ctx, tenant, outsider, p.ID); !errors.Is(err, bp.ErrNotFound) {
		t.Fatalf("an outsider must not pause: %v", err)
	}
	if l, _ := restricted.List(ctx, tenant, outsider); len(l) != 0 {
		t.Fatalf("an outsider lists nothing: %d", len(l))
	}
	if l, _ := restricted.List(ctx, tenant, member); len(l) != 1 {
		t.Fatalf("a member lists the program: %d", len(l))
	}
	if _, err := restricted.Get(ctx, tenant, member, p.ID); err != nil {
		t.Fatalf("a member reads the program: %v", err)
	}
	full := NewService(repo, fullData(true), nil)
	if _, err := full.Get(ctx, tenant, owner, p.ID); err != nil {
		t.Fatalf("a full-data caller reads every program: %v", err)
	}
	// Another tenant never sees it, even with full data.
	if _, err := full.Get(ctx, shared.NewID(), owner, p.ID); !errors.Is(err, bp.ErrNotFound) {
		t.Fatalf("another tenant: %v", err)
	}
	// Without a full-data checker every caller is restricted (fail closed).
	if l, _ := NewService(repo, nil, nil).List(ctx, tenant, owner); len(l) != 0 {
		t.Fatal("no checker: restricted")
	}
}

func TestLifecycleAndReimport(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	tenant, user := shared.NewID(), shared.NewID()
	svc := NewService(repo, fullData(false), nil)
	pv, _ := svc.Preview(ctx, tenant, input(), nil)
	in := input()
	in.AcceptTermsSHA256 = pv.TermsSHA256
	p, _, err := svc.Import(ctx, tenant, user, in)
	if err != nil {
		t.Fatal(err)
	}
	active := func() int {
		n := 0
		es, _ := repo.Entries(ctx, tenant, p.ID)
		for _, e := range es {
			if e.IsActive() {
				n++
			}
		}
		return n
	}

	if _, err := svc.Pause(ctx, tenant, user, p.ID); err != nil || active() != 0 {
		t.Fatalf("pause: %v active=%d", err, active())
	}
	if _, err := svc.Resume(ctx, tenant, user, p.ID, "deadbeef"); !errors.Is(err, bp.ErrTermsChanged) {
		t.Fatalf("resume needs the current terms: %v", err)
	}
	if _, err := svc.Resume(ctx, tenant, user, p.ID, p.TermsSHA256); err != nil || active() != 2 {
		t.Fatalf("resume: %v active=%d", err, active())
	}

	// Re-import drops shop.other.example and adds api.acme.example.
	re := input()
	re.ScopeText = "*.acme.example\napi.acme.example\n"
	rpv, err := svc.Preview(ctx, tenant, re, p)
	if err != nil {
		t.Fatal(err)
	}
	re.AcceptTermsSHA256 = rpv.TermsSHA256
	if _, _, err := svc.Reimport(ctx, tenant, user, p.ID, re); err != nil {
		t.Fatal(err)
	}
	es, _ := repo.Entries(ctx, tenant, p.ID)
	got := map[string]bool{}
	for _, e := range es {
		got[e.Pattern()] = true
	}
	if len(es) != 2 || !got["*.acme.example"] || !got["api.acme.example"] || got["shop.other.example"] {
		t.Fatalf("after re-import: %v", got)
	}
	// The apex exclusion is gone: api.acme.example is not the apex, but
	// acme.example is still unlisted, so it stays excluded.
	ex, _ := repo.Exclusions(ctx, tenant, &p.ID)
	if len(ex) != 1 || ex[0].Pattern != "acme.example" {
		t.Fatalf("exclusions after re-import: %+v", ex)
	}

	if _, err := svc.End(ctx, tenant, user, p.ID); err != nil || active() != 0 {
		t.Fatalf("end: %v", err)
	}
	if _, _, err := svc.Reimport(ctx, tenant, user, p.ID, re); !errors.Is(err, bp.ErrEnded) {
		t.Fatalf("an ended program cannot be re-imported: %v", err)
	}
	if _, err := svc.Resume(ctx, tenant, user, p.ID, p.TermsSHA256); !errors.Is(err, bp.ErrEnded) {
		t.Fatalf("an ended program cannot be resumed: %v", err)
	}
}

func TestPreview_GuardrailsAndExisting(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	tenant := shared.NewID()
	own, _ := scopedom.NewEntry(tenant, scopedom.TargetTypeDomain, "shop.other.example", "", "o", scopedom.EntryOptions{MaxTier: scopedom.TierActive})
	repo.entries[own.ID()] = own
	svc := NewService(repo, fullData(true), nil)
	in := input()
	in.ScopeText = "*.co.uk\nshop.other.example\n*.amazonaws.com\nok.example.net\n"
	pv, err := svc.Preview(ctx, tenant, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range pv.Entries {
		switch e.Pattern {
		case "*.co.uk", "*.amazonaws.com":
			if e.Status != PlanRefused || e.Code == "" {
				t.Errorf("%s must be refused: %+v", e.Pattern, e)
			}
		case "shop.other.example":
			if e.Status != PlanAlreadyCovered || e.Source != "ownership" {
				t.Errorf("existing entry: %+v", e)
			}
		case "ok.example.net":
			if e.Status != PlanCreate {
				t.Errorf("ok: %+v", e)
			}
		}
	}
	bad := input()
	bad.ProgramURL = "http://acme.example/"
	if _, err := svc.Preview(ctx, tenant, bad, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("http program url: %v", err)
	}
	bad = input()
	bad.Rules.RequiredHeaders = []bp.Header{{Name: "X-A", Value: "v\r\nX-B: c"}}
	if _, err := svc.Preview(ctx, tenant, bad, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("header injection: %v", err)
	}
}

// fakeLedger records what the program paths send to the signer ledger hook.
type fakeLedger struct {
	put, removed int
	refuse       bool
	policy       string
}

func (f *fakeLedger) CommitEntries(_ context.Context, _ shared.ID, _ string, put []*scopedom.Target, removed []shared.ID,
	policy string, save func() error,
) error {
	if f.refuse && len(put) > 0 {
		return errors.New("refused")
	}
	f.put, f.removed, f.policy = f.put+len(put), f.removed+len(removed), policy
	return save()
}

// Every path that puts program entries into effect or takes them out goes
// through the job signer ledger hook (RFC-040 §11.5); a refusal saves
// nothing.
func TestProgramEntriesFeedTheSignerLedger(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	tenant, user := shared.NewID(), shared.NewID()
	svc := NewService(repo, fullData(true), nil)
	l := &fakeLedger{refuse: true}
	svc.SetLedger(l)
	pv, _ := svc.Preview(ctx, tenant, input(), nil)
	in := input()
	in.AcceptTermsSHA256 = pv.TermsSHA256
	if _, _, err := svc.Import(ctx, tenant, user, in); err == nil || len(repo.entries) != 0 {
		t.Fatalf("import with the signer refusing: %v, %d entries", err, len(repo.entries))
	}
	l.refuse = false
	p, _, err := svc.Import(ctx, tenant, user, in)
	if err != nil {
		t.Fatal(err)
	}
	if l.put != 2 || l.policy != programAttestation {
		t.Fatalf("import sent %d entries under %q", l.put, l.policy)
	}
	if _, err := svc.Pause(ctx, tenant, user, p.ID); err != nil {
		t.Fatal(err)
	}
	if l.removed != 2 {
		t.Fatalf("pause removed %d", l.removed)
	}
	if _, err := svc.Resume(ctx, tenant, user, p.ID, p.TermsSHA256); err != nil {
		t.Fatal(err)
	}
	if l.put != 4 {
		t.Fatalf("resume sent %d entries in total", l.put)
	}
}
