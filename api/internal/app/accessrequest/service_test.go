package accessrequest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	ardom "github.com/openctemio/openctem/api/pkg/domain/accessrequest"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type memRepo struct {
	mu   sync.Mutex
	rows map[string]*ardom.Request
}

func newMemRepo() *memRepo { return &memRepo{rows: map[string]*ardom.Request{}} }

func (m *memRepo) Create(_ context.Context, r *ardom.Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *r
	m.rows[r.ID.String()] = &c
	return nil
}

func (m *memRepo) GetByID(_ context.Context, id shared.ID) (*ardom.Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id.String()]
	if !ok {
		return nil, ardom.ErrNotFound
	}
	c := *r
	return &c, nil
}

func (m *memRepo) GetByConfirmHash(_ context.Context, h string) (*ardom.Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if h != "" && r.ConfirmHash == h {
			c := *r
			return &c, nil
		}
	}
	return nil, ardom.ErrNotFound
}

func (m *memRepo) Update(_ context.Context, r *ardom.Request, expected ardom.Status) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.rows[r.ID.String()]
	if !ok || cur.Status != expected {
		return ardom.ErrNotDecidable
	}
	c := *r
	m.rows[r.ID.String()] = &c
	return nil
}

func (m *memRepo) List(_ context.Context, _ ardom.Filter) ([]*ardom.Request, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []*ardom.Request{}
	for _, r := range m.rows {
		out = append(out, r)
	}
	return out, len(out), nil
}

func (m *memRepo) CountByIPSince(_ context.Context, h string, since time.Time) (int, error) {
	n := 0
	for _, r := range m.rows {
		if r.IPHash == h && !r.CreatedAt.Before(since) {
			n++
		}
	}
	return n, nil
}

func (m *memRepo) CountByDomainSince(_ context.Context, d string, since time.Time) (int, error) {
	n := 0
	for _, r := range m.rows {
		if r.Domain == d && !r.CreatedAt.Before(since) {
			n++
		}
	}
	return n, nil
}

func (m *memRepo) Purge(_ context.Context, unconfirmedBefore, decidedBefore time.Time) (int64, error) {
	var n int64
	for id, r := range m.rows {
		if (r.Status == ardom.StatusUnconfirmed && r.CreatedAt.Before(unconfirmedBefore)) ||
			((r.Status == ardom.StatusApproved || r.Status == ardom.StatusRejected) && r.DecidedAt != nil && r.DecidedAt.Before(decidedBefore)) {
			delete(m.rows, id)
			n++
		}
	}
	return n, nil
}

type fakeMailer struct {
	configured bool
	confirm    []string // confirmation URLs
	decisions  []string
}

func (f *fakeMailer) Configured() bool { return f.configured }
func (f *fakeMailer) SendConfirmation(_ context.Context, _, _, url string) error {
	f.confirm = append(f.confirm, url)
	return nil
}
func (f *fakeMailer) SendDecision(_ context.Context, to string, _ bool) error {
	f.decisions = append(f.decisions, to)
	return nil
}

type fakeOrgs struct {
	err   error
	calls []tenantapp.CreateOrganizationInput
}

func (f *fakeOrgs) Create(_ context.Context, in tenantapp.CreateOrganizationInput, _ auditapp.AuditContext) (*tenantapp.CreatedOrganization, error) {
	f.calls = append(f.calls, in)
	if f.err != nil {
		return nil, f.err
	}
	t, _ := tenantdom.NewTenant(in.Name, in.Slug, shared.NewID().String())
	return &tenantapp.CreatedOrganization{Tenant: t}, nil
}

type fakeCaptcha struct{ ok bool }

func (f fakeCaptcha) Verify(context.Context, string, string) (bool, error) { return f.ok, nil }

var openPolicy = signupdom.Static{Mode: signupdom.ModeAdminOnly, RequestAccess: true}

func newSvc(t *testing.T, policy signupdom.PolicySource, mailer *fakeMailer, captcha Captcha) (*Service, *memRepo, *fakeOrgs) {
	t.Helper()
	repo := newMemRepo()
	orgs := &fakeOrgs{}
	var m Mailer
	if mailer != nil {
		m = mailer
	}
	return NewService(repo, policy, orgs, m, captcha, "https://app.example.com/", nil), repo, orgs
}

func superAdmin(t *testing.T) *admin.AdminUser {
	t.Helper()
	a, err := admin.NewAdminUser("ops@op.example", "Ops", admin.AdminRoleOpsAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func submit(svc *Service, email, ip string) error {
	return svc.Submit(context.Background(), SubmitInput{Company: "Acme", Email: email, Note: "Evaluating", IP: ip})
}

func TestSubmit_Refusals(t *testing.T) {
	ctx := context.Background()
	t.Run("closed when request access is off", func(t *testing.T) {
		svc, repo, _ := newSvc(t, signupdom.Static{Mode: signupdom.ModeAdminOnly}, nil, nil)
		if err := submit(svc, "a@acme.com", "203.0.113.1"); !errors.Is(err, ErrClosed) {
			t.Fatalf("expected ErrClosed, got %v", err)
		}
		if len(repo.rows) != 0 {
			t.Fatal("nothing may be stored")
		}
	})
	t.Run("closed in self_service (people sign up instead)", func(t *testing.T) {
		svc, _, _ := newSvc(t, signupdom.Static{Mode: signupdom.ModeSelfService, RequestAccess: true}, nil, nil)
		if err := submit(svc, "a@acme.com", "203.0.113.1"); !errors.Is(err, ErrClosed) {
			t.Fatalf("expected ErrClosed, got %v", err)
		}
	})
	for name, in := range map[string]SubmitInput{
		"no company":       {Email: "a@acme.com"},
		"bad email":        {Company: "Acme", Email: "not-an-email"},
		"two at signs":     {Company: "Acme", Email: "a@b@acme.com"},
		"header injection": {Company: "Acme", Email: "a@acme.com\r\nBcc: x@evil.com"},
		"company too long": {Company: strings.Repeat("x", 201), Email: "a@acme.com"},
		"note too long":    {Company: "Acme", Email: "a@acme.com", Note: strings.Repeat("x", 1001)},
	} {
		t.Run(name, func(t *testing.T) {
			svc, repo, _ := newSvc(t, openPolicy, nil, nil)
			if err := svc.Submit(ctx, in); !errors.Is(err, ardom.ErrInvalid) {
				t.Fatalf("expected ErrInvalid, got %v", err)
			}
			if len(repo.rows) != 0 {
				t.Fatal("nothing may be stored")
			}
		})
	}
	t.Run("captcha failed", func(t *testing.T) {
		svc, repo, _ := newSvc(t, openPolicy, nil, fakeCaptcha{ok: false})
		if err := submit(svc, "a@acme.com", "203.0.113.1"); !errors.Is(err, ErrCaptcha) {
			t.Fatalf("expected ErrCaptcha, got %v", err)
		}
		if len(repo.rows) != 0 {
			t.Fatal("nothing may be stored")
		}
	})
}

// Dropped submissions answer exactly like stored ones (nil), so the form says
// nothing; they store nothing.
func TestSubmit_SilentDrops(t *testing.T) {
	t.Run("disposable address", func(t *testing.T) {
		svc, repo, _ := newSvc(t, openPolicy, nil, nil)
		if err := submit(svc, "x@mailinator.com", "203.0.113.1"); err != nil {
			t.Fatalf("expected the same answer, got %v", err)
		}
		if len(repo.rows) != 0 {
			t.Fatal("a disposable address must not be stored")
		}
	})
	t.Run("per address limit", func(t *testing.T) {
		svc, repo, _ := newSvc(t, openPolicy, nil, nil)
		for i, d := range []string{"a.com", "b.com", "c.com", "d.com"} {
			if err := submit(svc, "p@"+d, "203.0.113.9"); err != nil {
				t.Fatalf("submission %d: %v", i, err)
			}
		}
		if len(repo.rows) != ardom.MaxPerIPPerHour {
			t.Fatalf("expected %d stored, got %d", ardom.MaxPerIPPerHour, len(repo.rows))
		}
	})
	t.Run("per domain limit", func(t *testing.T) {
		svc, repo, _ := newSvc(t, openPolicy, nil, nil)
		for i := 0; i < 7; i++ {
			ip := "198.51.100." + string(rune('1'+i))
			if err := submit(svc, "p@acme.com", ip); err != nil {
				t.Fatal(err)
			}
		}
		if len(repo.rows) != ardom.MaxPerDomainPerDay {
			t.Fatalf("expected %d stored, got %d", ardom.MaxPerDomainPerDay, len(repo.rows))
		}
	})
}

func TestSubmit_StoresNoRawIP(t *testing.T) {
	svc, repo, _ := newSvc(t, openPolicy, nil, nil)
	if err := submit(svc, "a@acme.com", "203.0.113.77"); err != nil {
		t.Fatal(err)
	}
	for _, r := range repo.rows {
		if r.IPHash == "" || strings.Contains(r.IPHash, "203.0.113.77") {
			t.Fatalf("the IP must be kept only as a hash, got %q", r.IPHash)
		}
		if r.Status != ardom.StatusPending {
			t.Fatalf("without email the request waits for an administrator at once, got %s", r.Status)
		}
	}
}

func TestConfirmFlow(t *testing.T) {
	mailer := &fakeMailer{configured: true}
	svc, repo, _ := newSvc(t, openPolicy, mailer, nil)
	ctx := context.Background()
	if err := submit(svc, "a@acme.com", "203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	if len(mailer.confirm) != 1 || !strings.HasPrefix(mailer.confirm[0], "https://app.example.com/request-access/confirm#token=") {
		t.Fatalf("a confirmation link with the token in the fragment must be emailed, got %v", mailer.confirm)
	}
	token := strings.TrimPrefix(mailer.confirm[0], "https://app.example.com/request-access/confirm#token=")
	for _, r := range repo.rows {
		if r.Status != ardom.StatusUnconfirmed || r.ConfirmHash == token {
			t.Fatalf("stored unconfirmed with only the token's hash, got %+v", r)
		}
	}
	if err := svc.Confirm(ctx, "wrong"); !errors.Is(err, ardom.ErrInvalidToken) {
		t.Fatalf("a wrong token is refused, got %v", err)
	}
	if err := svc.Confirm(ctx, token); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if err := svc.Confirm(ctx, token); !errors.Is(err, ardom.ErrInvalidToken) {
		t.Fatalf("a token works once, got %v", err)
	}
	for _, r := range repo.rows {
		if r.Status != ardom.StatusPending || r.ConfirmedAt == nil {
			t.Fatalf("expected pending and confirmed, got %+v", r)
		}
	}
}

func TestConfirm_ExpiredLinkRefused(t *testing.T) {
	mailer := &fakeMailer{configured: true}
	svc, _, _ := newSvc(t, openPolicy, mailer, nil)
	if err := submit(svc, "a@acme.com", "203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	token := mailer.confirm[0][strings.Index(mailer.confirm[0], "#token=")+len("#token="):]
	svc.now = func() time.Time { return time.Now().Add(ardom.UnconfirmedTTL + time.Minute) }
	if err := svc.Confirm(context.Background(), token); !errors.Is(err, ardom.ErrInvalidToken) {
		t.Fatalf("an expired link is refused, got %v", err)
	}
}

func onePending(t *testing.T, repo *memRepo) shared.ID {
	t.Helper()
	for _, r := range repo.rows {
		return r.ID
	}
	t.Fatal("no request")
	return shared.ID{}
}

func TestApprove(t *testing.T) {
	ctx := context.Background()
	svc, repo, orgs := newSvc(t, openPolicy, nil, nil)
	_ = submit(svc, "Owner@Acme.com", "203.0.113.1")
	id := onePending(t, repo)

	req, created, err := svc.Approve(ctx, superAdmin(t), id, ApproveInput{Slug: "acme"}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if len(orgs.calls) != 1 || orgs.calls[0].OwnerEmail != "owner@acme.com" || orgs.calls[0].Name != "Acme" {
		t.Fatalf("the requester owns the new organization, got %+v", orgs.calls)
	}
	if req.Status != ardom.StatusApproved || req.TenantID == nil || *req.TenantID != created.Tenant.ID() || req.DecidedBy == nil {
		t.Fatalf("unexpected request %+v", req)
	}
	// A second approval (another administrator at the same time) is refused
	// and creates nothing.
	if _, _, err := svc.Approve(ctx, superAdmin(t), id, ApproveInput{Slug: "acme2"}, auditapp.AuditContext{}); !errors.Is(err, ardom.ErrNotDecidable) {
		t.Fatalf("expected ErrNotDecidable, got %v", err)
	}
	if len(orgs.calls) != 1 {
		t.Fatal("no second organization may be created")
	}
}

func TestApprove_UnconfirmedRefused(t *testing.T) {
	svc, repo, orgs := newSvc(t, openPolicy, &fakeMailer{configured: true}, nil)
	_ = submit(svc, "a@acme.com", "203.0.113.1")
	if _, _, err := svc.Approve(context.Background(), superAdmin(t), onePending(t, repo), ApproveInput{Slug: "acme"}, auditapp.AuditContext{}); !errors.Is(err, ardom.ErrNotDecidable) {
		t.Fatalf("an unconfirmed request cannot be approved, got %v", err)
	}
	if len(orgs.calls) != 0 {
		t.Fatal("nothing may be created")
	}
}

func TestApprove_FailedCreationReturnsToPending(t *testing.T) {
	svc, repo, orgs := newSvc(t, openPolicy, nil, nil)
	_ = submit(svc, "a@acme.com", "203.0.113.1")
	id := onePending(t, repo)
	orgs.err = errors.New("slug taken")
	if _, _, err := svc.Approve(context.Background(), superAdmin(t), id, ApproveInput{Slug: "acme"}, auditapp.AuditContext{}); err == nil {
		t.Fatal("expected the creation error")
	}
	r, _ := repo.GetByID(context.Background(), id)
	if r.Status != ardom.StatusPending || r.DecidedBy != nil {
		t.Fatalf("a failed approval leaves the request pending, got %+v", r)
	}
}

func TestReject(t *testing.T) {
	ctx := context.Background()
	mailer := &fakeMailer{configured: true}
	svc, repo, _ := newSvc(t, openPolicy, mailer, nil)
	_ = submit(svc, "a@acme.com", "203.0.113.1")
	id := onePending(t, repo)
	// Unconfirmed: rejected without an email (the address was never proven).
	if _, err := svc.Reject(ctx, superAdmin(t), id); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if len(mailer.decisions) != 0 {
		t.Fatal("an unconfirmed requester is not emailed")
	}
	if _, err := svc.Reject(ctx, superAdmin(t), id); !errors.Is(err, ardom.ErrNotDecidable) {
		t.Fatalf("a decided request cannot be rejected again, got %v", err)
	}

	// Confirmed: the requester gets the neutral email.
	svc2, repo2, _ := newSvc(t, openPolicy, nil, nil)
	_ = submit(svc2, "b@acme.com", "203.0.113.2") // no email yet: stored pending
	svc2.mailer = mailer
	if _, err := svc2.Reject(ctx, superAdmin(t), onePending(t, repo2)); err != nil {
		t.Fatal(err)
	}
	if len(mailer.decisions) != 1 || mailer.decisions[0] != "b@acme.com" {
		t.Fatalf("expected the neutral email, got %v", mailer.decisions)
	}
}

func TestPurge(t *testing.T) {
	svc, repo, _ := newSvc(t, openPolicy, nil, nil)
	now := time.Now().UTC()
	old := now.Add(-ardom.DecidedRetention - time.Hour)
	repo.rows["a"] = &ardom.Request{ID: shared.NewID(), Status: ardom.StatusUnconfirmed, CreatedAt: now.Add(-25 * time.Hour)}
	repo.rows["b"] = &ardom.Request{ID: shared.NewID(), Status: ardom.StatusUnconfirmed, CreatedAt: now}
	repo.rows["c"] = &ardom.Request{ID: shared.NewID(), Status: ardom.StatusRejected, CreatedAt: old, DecidedAt: &old}
	repo.rows["d"] = &ardom.Request{ID: shared.NewID(), Status: ardom.StatusPending, CreatedAt: old}
	n, err := svc.Purge(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("expected 2 purged, got %d %v", n, err)
	}
	if _, ok := repo.rows["d"]; !ok {
		t.Fatal("a pending request is kept until decided")
	}
}
