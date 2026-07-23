package domainverify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/verifieddomain"
)

// ---- test doubles ----------------------------------------------------------

// memRepo is an in-memory verifieddomain.Repository keyed by (tenant, domain).
type memRepo struct {
	rows map[string]*verifieddomain.VerifiedDomain // id -> row
}

func newMemRepo() *memRepo { return &memRepo{rows: map[string]*verifieddomain.VerifiedDomain{}} }

func (m *memRepo) Create(_ context.Context, d *verifieddomain.VerifiedDomain) error {
	for _, r := range m.rows {
		if r.TenantID().Equals(d.TenantID()) && r.Domain() == d.Domain() {
			return verifieddomain.ErrAlreadyExists
		}
	}
	m.rows[d.ID().String()] = d
	return nil
}

func (m *memRepo) Update(_ context.Context, d *verifieddomain.VerifiedDomain) error {
	if _, ok := m.rows[d.ID().String()]; !ok {
		return verifieddomain.ErrNotFound
	}
	m.rows[d.ID().String()] = d
	return nil
}

func (m *memRepo) Delete(_ context.Context, tenantID, id shared.ID) error {
	r, ok := m.rows[id.String()]
	if !ok || !r.TenantID().Equals(tenantID) {
		return verifieddomain.ErrNotFound
	}
	delete(m.rows, id.String())
	return nil
}

func (m *memRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*verifieddomain.VerifiedDomain, error) {
	r, ok := m.rows[id.String()]
	if !ok || !r.TenantID().Equals(tenantID) {
		return nil, verifieddomain.ErrNotFound
	}
	return r, nil
}

func (m *memRepo) GetByTenantAndDomain(_ context.Context, tenantID shared.ID, domain string) (*verifieddomain.VerifiedDomain, error) {
	for _, r := range m.rows {
		if r.TenantID().Equals(tenantID) && r.Domain() == domain {
			return r, nil
		}
	}
	return nil, verifieddomain.ErrNotFound
}

func (m *memRepo) ListByTenant(_ context.Context, tenantID shared.ID) ([]*verifieddomain.VerifiedDomain, error) {
	out := make([]*verifieddomain.VerifiedDomain, 0)
	for _, r := range m.rows {
		if r.TenantID().Equals(tenantID) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memRepo) ListDueForRecheck(_ context.Context, checkedBefore time.Time, limit int) ([]*verifieddomain.VerifiedDomain, error) {
	out := make([]*verifieddomain.VerifiedDomain, 0)
	for _, r := range m.rows {
		if r.Status() != verifieddomain.StatusVerified {
			continue
		}
		lc := r.LastCheckedAt()
		if lc == nil || lc.Before(checkedBefore) {
			out = append(out, r)
		}
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// mockResolver returns scripted TXT records / errors keyed by host.
type mockResolver struct {
	records map[string][]string
	err     error
}

func (m *mockResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.records[name], nil
}

// ---- AddDomain / blocklist -------------------------------------------------

func TestAddDomain_RejectsSharedDomains(t *testing.T) {
	blocked := []string{
		"gmail.com", "GoogleMail.com", "outlook.com", "hotmail.com", "yahoo.com",
		"icloud.com", "proton.me", "protonmail.com", "aol.com", "live.com",
		"msn.com", "microsoft.com", "onmicrosoft.com",
		"contoso.onmicrosoft.com", // *.onmicrosoft.com tenant
		"  YAHOO.COM  ",           // normalization still blocks
	}
	for _, d := range blocked {
		svc := NewService(newMemRepo(), &mockResolver{}, nil)
		if _, _, err := svc.AddDomain(context.Background(), shared.NewID(), d); !errors.Is(err, verifieddomain.ErrBlockedDomain) {
			t.Errorf("domain %q must be blocked, got err=%v", d, err)
		}
	}
}

func TestAddDomain_StoresPendingWithInstructions(t *testing.T) {
	repo := newMemRepo()
	svc := NewService(repo, &mockResolver{}, nil)
	tid := shared.NewID()

	vd, txt, err := svc.AddDomain(context.Background(), tid, "Corp.COM")
	if err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	if vd.Status() != verifieddomain.StatusPending {
		t.Fatalf("new domain must be pending, got %s", vd.Status())
	}
	if vd.Domain() != "corp.com" {
		t.Fatalf("domain must be normalized to lowercase, got %q", vd.Domain())
	}
	if txt.Host != "_openctem-verify.corp.com" {
		t.Fatalf("unexpected TXT host: %q", txt.Host)
	}
	if txt.Type != "TXT" {
		t.Fatalf("unexpected TXT type: %q", txt.Type)
	}
	if txt.Value != "openctem-domain-verification="+vd.VerificationToken() {
		t.Fatalf("unexpected TXT value: %q", txt.Value)
	}
	if vd.VerificationToken() == "" {
		t.Fatal("verification token must be generated")
	}
}

func TestAddDomain_DuplicateRejected(t *testing.T) {
	repo := newMemRepo()
	svc := NewService(repo, &mockResolver{}, nil)
	tid := shared.NewID()
	if _, _, err := svc.AddDomain(context.Background(), tid, "corp.com"); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if _, _, err := svc.AddDomain(context.Background(), tid, "corp.com"); !errors.Is(err, verifieddomain.ErrAlreadyExists) {
		t.Fatalf("duplicate add must conflict, got %v", err)
	}
}

// ---- Verify (mock resolver) ------------------------------------------------

// helper: add a domain and return its (id, token).
func mustAdd(t *testing.T, svc *Service, tid shared.ID, domain string) (shared.ID, string) {
	t.Helper()
	vd, _, err := svc.AddDomain(context.Background(), tid, domain)
	if err != nil {
		t.Fatalf("add %q: %v", domain, err)
	}
	return vd.ID(), vd.VerificationToken()
}

func TestVerify_TokenPresent_Verified(t *testing.T) {
	repo := newMemRepo()
	res := &mockResolver{records: map[string][]string{}}
	svc := NewService(repo, res, nil)
	tid := shared.NewID()
	id, token := mustAdd(t, svc, tid, "corp.com")

	res.records["_openctem-verify.corp.com"] = []string{"unrelated=1", "openctem-domain-verification=" + token}

	vd, err := svc.VerifyByID(context.Background(), tid, id)
	if err != nil {
		t.Fatalf("VerifyByID: %v", err)
	}
	if vd.Status() != verifieddomain.StatusVerified {
		t.Fatalf("token present must verify, got %s", vd.Status())
	}
	if vd.VerifiedAt() == nil {
		t.Fatal("verified_at must be stamped")
	}
	if vd.LastCheckedAt() == nil {
		t.Fatal("last_checked_at must be stamped")
	}
}

func TestVerify_TokenAbsent_StaysPending(t *testing.T) {
	repo := newMemRepo()
	res := &mockResolver{records: map[string][]string{"_openctem-verify.corp.com": {"some-other-record"}}}
	svc := NewService(repo, res, nil)
	tid := shared.NewID()
	id, _ := mustAdd(t, svc, tid, "corp.com")

	vd, err := svc.VerifyByID(context.Background(), tid, id)
	if err != nil {
		t.Fatalf("VerifyByID: %v", err)
	}
	if vd.Status() != verifieddomain.StatusPending {
		t.Fatalf("token absent must NOT verify (stay pending), got %s", vd.Status())
	}
	if vd.VerifiedAt() != nil {
		t.Fatal("verified_at must not be set when token absent")
	}
	if vd.LastCheckedAt() == nil {
		t.Fatal("last_checked_at must still be stamped")
	}
}

func TestVerify_LookupError_NotVerified(t *testing.T) {
	repo := newMemRepo()
	res := &mockResolver{err: errors.New("NXDOMAIN")}
	svc := NewService(repo, res, nil)
	tid := shared.NewID()
	id, _ := mustAdd(t, svc, tid, "corp.com")

	vd, err := svc.VerifyByID(context.Background(), tid, id)
	if err != nil {
		t.Fatalf("VerifyByID: %v", err)
	}
	if vd.Status() == verifieddomain.StatusVerified {
		t.Fatal("a lookup error must never verify (fail-closed)")
	}
	if vd.Status() != verifieddomain.StatusPending {
		t.Fatalf("pending must remain pending on lookup error, got %s", vd.Status())
	}
}

// ---- ReverifyDue downgrade -------------------------------------------------

func TestReverifyDue_DowngradesWhenTXTGone(t *testing.T) {
	repo := newMemRepo()
	res := &mockResolver{records: map[string][]string{}}
	svc := NewService(repo, res, nil)
	tid := shared.NewID()
	id, token := mustAdd(t, svc, tid, "corp.com")

	// First: publish + verify.
	res.records["_openctem-verify.corp.com"] = []string{"openctem-domain-verification=" + token}
	if _, err := svc.VerifyByID(context.Background(), tid, id); err != nil {
		t.Fatalf("initial verify: %v", err)
	}

	// Now the record disappears.
	res.records["_openctem-verify.corp.com"] = nil

	// Staleness 0 → everything is due.
	changed, err := svc.ReverifyDue(context.Background(), 0, 100)
	if err != nil {
		t.Fatalf("ReverifyDue: %v", err)
	}
	if changed != 1 {
		t.Fatalf("expected 1 status change, got %d", changed)
	}
	got, _ := repo.GetByID(context.Background(), tid, id)
	if got.Status() != verifieddomain.StatusFailed {
		t.Fatalf("a verified domain whose TXT vanished must downgrade to failed, got %s", got.Status())
	}
}

func TestReverifyDue_StaysVerifiedWhenTXTPresent(t *testing.T) {
	repo := newMemRepo()
	res := &mockResolver{records: map[string][]string{}}
	svc := NewService(repo, res, nil)
	tid := shared.NewID()
	id, token := mustAdd(t, svc, tid, "corp.com")
	res.records["_openctem-verify.corp.com"] = []string{"openctem-domain-verification=" + token}
	if _, err := svc.VerifyByID(context.Background(), tid, id); err != nil {
		t.Fatalf("initial verify: %v", err)
	}

	changed, err := svc.ReverifyDue(context.Background(), 0, 100)
	if err != nil {
		t.Fatalf("ReverifyDue: %v", err)
	}
	if changed != 0 {
		t.Fatalf("verified domain with intact TXT must not change, got %d changes", changed)
	}
	got, _ := repo.GetByID(context.Background(), tid, id)
	if got.Status() != verifieddomain.StatusVerified {
		t.Fatalf("domain must stay verified, got %s", got.Status())
	}
}

// ---- IsVerifiedDomain tenant scoping ---------------------------------------

func TestIsVerifiedDomain_TenantScoped(t *testing.T) {
	repo := newMemRepo()
	res := &mockResolver{records: map[string][]string{}}
	svc := NewService(repo, res, nil)

	tenantA := shared.NewID()
	tenantB := shared.NewID()

	// Tenant A verifies corp.com.
	idA, token := mustAdd(t, svc, tenantA, "corp.com")
	res.records["_openctem-verify.corp.com"] = []string{"openctem-domain-verification=" + token}
	if _, err := svc.VerifyByID(context.Background(), tenantA, idA); err != nil {
		t.Fatalf("verify A: %v", err)
	}

	// Tenant A sees it verified.
	okA, err := svc.IsVerifiedDomain(context.Background(), tenantA.String(), "corp.com")
	if err != nil || !okA {
		t.Fatalf("tenant A must see corp.com verified, ok=%v err=%v", okA, err)
	}

	// Tenant B must NOT — A's verified domain is not B's.
	okB, err := svc.IsVerifiedDomain(context.Background(), tenantB.String(), "corp.com")
	if err != nil {
		t.Fatalf("IsVerifiedDomain B: %v", err)
	}
	if okB {
		t.Fatal("tenant B must NOT inherit tenant A's verified domain (tenant isolation)")
	}
}

func TestIsVerifiedDomain_PendingIsFalse(t *testing.T) {
	repo := newMemRepo()
	svc := NewService(repo, &mockResolver{}, nil)
	tid := shared.NewID()
	mustAdd(t, svc, tid, "corp.com") // pending, never verified

	ok, err := svc.IsVerifiedDomain(context.Background(), tid.String(), "CORP.com")
	if err != nil {
		t.Fatalf("IsVerifiedDomain: %v", err)
	}
	if ok {
		t.Fatal("a pending domain must not count as verified")
	}
}

func TestIsVerifiedDomain_UnknownDomainFalse(t *testing.T) {
	svc := NewService(newMemRepo(), &mockResolver{}, nil)
	ok, err := svc.IsVerifiedDomain(context.Background(), shared.NewID().String(), "nowhere.com")
	if err != nil {
		t.Fatalf("IsVerifiedDomain: %v", err)
	}
	if ok {
		t.Fatal("an unknown domain must be false (fail-closed)")
	}
}
