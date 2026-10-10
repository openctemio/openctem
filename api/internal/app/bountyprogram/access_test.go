package bountyprogram

import (
	"context"
	"errors"
	"testing"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type ownerKey struct{}

func asOwner(ctx context.Context) context.Context { return context.WithValue(ctx, ownerKey{}, true) }

func ownerCheck(ctx context.Context) bool { v, _ := ctx.Value(ownerKey{}).(bool); return v }

// privateFixture imports a private program as importer, from a Burp file.
func privateFixture(t *testing.T, full bool) (*Service, *fakeRepo, *fakeLedger, shared.ID, shared.ID, *bp.Program) {
	t.Helper()
	ctx := context.Background()
	repo := newFakeRepo()
	l := &fakeLedger{}
	svc := NewService(repo, fullData(full), nil)
	svc.SetOwnerCheck(ownerCheck)
	svc.SetLedger(l)
	tenant, importer := shared.NewID(), shared.NewID()
	in := Input{Name: "Invite-only", Platform: "self", TermsText: "Do not disclose anything about this program.",
		ScopeFile: &bp.ScopeFile{Format: bp.FileFormatBurpJSON,
			Content: `{"target":{"scope":{"include":[{"host":"^.*\\.secret\\.example$"}],"exclude":[{"host":"^vpn\\.secret\\.example$"}]}}}`}}
	pv, err := svc.Preview(ctx, tenant, in, nil)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	in.AcceptTermsSHA256 = pv.TermsSHA256
	p, _, err := svc.Import(ctx, tenant, importer, in)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	return svc, repo, l, tenant, importer, p
}

func TestPrivateProgram_ImportFromFile(t *testing.T) {
	_, repo, l, _, importer, p := privateFixture(t, false)
	if !p.IsPrivate() || p.ScopeSource != bp.ScopeSourceFileImport || p.ProgramURL != "" {
		t.Fatalf("program = %+v", p)
	}
	// The entries went through the signer ledger with the attestation label.
	if l.put == 0 || l.policy != programAttestation {
		t.Fatalf("ledger put %d policy %q", l.put, l.policy)
	}
	// The importer's attestation is recorded.
	if repo.attest[p.ID][importer] != p.TermsSHA256 {
		t.Fatal("importer attestation not recorded")
	}
}

func TestPrivateProgram_Visibility(t *testing.T) {
	ctx := context.Background()
	// Even a full-data caller (an administrator) who is not a member does
	// not see a private program: 404 by id, absent from the list, its
	// entries hidden.
	svc, repo, _, tenant, importer, p := privateFixture(t, true)
	admin := shared.NewID()
	if _, err := svc.Get(ctx, tenant, admin, p.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("non-member admin get: %v", err)
	}
	for _, call := range []func() error{
		func() error { _, err := svc.Pending(ctx, tenant, admin, p.ID); return err },
		func() error { _, err := svc.Sync(ctx, tenant, admin, p.ID); return err },
		func() error { _, err := svc.Pause(ctx, tenant, admin, p.ID); return err },
		func() error { _, err := svc.Attest(ctx, tenant, admin, p.ID, p.TermsSHA256); return err },
	} {
		if err := call(); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("non-member admin: %v", err)
		}
	}
	list, err := svc.List(ctx, tenant, admin)
	if err != nil || len(list) != 0 {
		t.Fatalf("non-member admin list = %d, %v", len(list), err)
	}
	hidden, err := svc.HiddenProgramIDs(ctx, tenant, admin)
	if err != nil || len(hidden) != 1 || !hidden[0].Equals(p.ID) {
		t.Fatalf("hidden = %v, %v", hidden, err)
	}
	// Another tenant never sees it, owner or not.
	other := shared.NewID()
	if _, err := svc.Get(asOwner(ctx), other, importer, p.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if hidden, _ := svc.HiddenProgramIDs(ctx, other, importer); len(hidden) != 0 {
		t.Fatalf("cross-tenant hidden = %v", hidden)
	}
	// The importer (a member who attested) sees everything.
	d, err := svc.Get(ctx, tenant, importer, p.ID)
	if err != nil || d.Locked || len(d.Entries) == 0 {
		t.Fatalf("importer get: locked=%v entries=%d err=%v", d != nil && d.Locked, len(d.Entries), err)
	}
	if hidden, _ := svc.HiddenProgramIDs(ctx, tenant, importer); len(hidden) != 0 {
		t.Fatalf("importer hidden = %v", hidden)
	}

	// A new member sees only the locked summary until they attest.
	member := shared.NewID()
	repo.members[p.ID][member] = true
	d, err = svc.Get(ctx, tenant, member, p.ID)
	if err != nil || !d.Locked || d.Entries != nil || d.Program.ScopeItems != nil || d.Program.TermsText == "" {
		t.Fatalf("member before attest: %+v err=%v", d, err)
	}
	if _, err := svc.Pending(ctx, tenant, member, p.ID); !errors.Is(err, bp.ErrAttestationRequired) {
		t.Fatalf("member pending before attest: %v", err)
	}
	if _, _, err := svc.Reimport(ctx, tenant, member, p.ID, Input{}); !errors.Is(err, bp.ErrAttestationRequired) {
		t.Fatalf("member reimport before attest: %v", err)
	}
	if list, _ := svc.List(ctx, tenant, member); len(list) != 1 || !list[0].Locked || list[0].Program.Rules.UserAgent != "" {
		t.Fatalf("member list before attest: %+v", list)
	}
	if _, err := svc.Attest(ctx, tenant, member, p.ID, "deadbeef"); !errors.Is(err, bp.ErrTermsChanged) {
		t.Fatalf("stale attestation: %v", err)
	}
	if _, err := svc.Attest(ctx, tenant, member, p.ID, p.TermsSHA256); err != nil {
		t.Fatalf("attest: %v", err)
	}
	if d, _ = svc.Get(ctx, tenant, member, p.ID); d.Locked {
		t.Fatal("member still locked after attesting")
	}

	// A change of terms asks everyone again.
	p.TermsSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if d, _ = svc.Get(ctx, tenant, member, p.ID); !d.Locked {
		t.Fatal("changed terms must lock the program again")
	}

	// An owner who is not a member sees it (locked until they attest).
	owner := shared.NewID()
	if d, err = svc.Get(asOwner(ctx), tenant, owner, p.ID); err != nil || !d.Locked {
		t.Fatalf("owner get: %+v %v", d, err)
	}
}

func TestPublicProgram_FullDataSeesWithoutAttestation(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := NewService(repo, fullData(true), nil)
	tenant, user := shared.NewID(), shared.NewID()
	in := input()
	pv, _ := svc.Preview(ctx, tenant, in, nil)
	in.AcceptTermsSHA256 = pv.TermsSHA256
	p, _, err := svc.Import(ctx, tenant, user, in)
	if err != nil {
		t.Fatal(err)
	}
	d, err := svc.Get(ctx, tenant, shared.NewID(), p.ID)
	if err != nil || d.Locked {
		t.Fatalf("public program for a full-data caller: %+v %v", d, err)
	}
}

func TestPreview_RefusesWildcardAbuse(t *testing.T) {
	ctx := context.Background()
	svc := NewService(newFakeRepo(), fullData(false), nil)
	tenant := shared.NewID()
	in := Input{Name: "Abuse", ScopeFile: &bp.ScopeFile{Format: bp.FileFormatText,
		Content: "*.com\n*.co.uk\n8.0.0.0/8\nok.example.org\n"}}
	pv, err := svc.Preview(ctx, tenant, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range pv.Entries {
		if e.Pattern == "ok.example.org" {
			if e.Status != PlanCreate {
				t.Errorf("ok.example.org: %s", e.Status)
			}
			continue
		}
		if e.Status != PlanRefused {
			t.Errorf("%s must be refused by the guardrails, got %s", e.Pattern, e.Status)
		}
	}
	if _, err := svc.Preview(ctx, tenant, Input{Name: "x", Visibility: "everyone", ScopeText: "a.example.org"}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("bad visibility: %v", err)
	}
}
