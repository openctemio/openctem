package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/pkg/domain/limits"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/server/pkg/domain/signup"
	"github.com/openctemio/openctem/server/pkg/domain/signupevent"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/server/pkg/domain/user"
	"github.com/openctemio/openctem/server/pkg/domain/verifieddomain"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// fakePersonalOrgs is an in-memory mark store with the repository's rules:
// one organization per mark, members settle it, invitations defer it.
type fakePersonalOrgs struct {
	mu       sync.Mutex
	status   map[shared.ID]tenantdom.PersonalOrgStatus
	members  map[shared.ID]bool
	invited  map[shared.ID]bool
	reserved map[shared.ID]time.Time
	made     []tenantdom.PersonalOrgCreation
	failNext error
}

func newFakePersonalOrgs() *fakePersonalOrgs {
	return &fakePersonalOrgs{status: map[shared.ID]tenantdom.PersonalOrgStatus{}, members: map[shared.ID]bool{}, invited: map[shared.ID]bool{}, reserved: map[shared.ID]time.Time{}}
}

func (f *fakePersonalOrgs) ReservePersonalOrganization(_ context.Context, id shared.ID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.status[id]; !ok {
		f.status[id] = tenantdom.PersonalOrgPending
		f.reserved[id] = at
	}
	return nil
}

func (f *fakePersonalOrgs) PersonalOrganizationPending(_ context.Context, id shared.ID, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.reserved[id]; ok && !r.After(at.Add(-tenantdom.PersonalOrgMarkLifetime)) {
		return false, nil
	}
	return f.status[id] == tenantdom.PersonalOrgPending, nil
}

func (f *fakePersonalOrgs) CreatePersonalOrganization(_ context.Context, c tenantdom.PersonalOrgCreation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failNext; err != nil {
		f.failNext = nil
		return err
	}
	if f.status[c.UserID] != tenantdom.PersonalOrgPending {
		return tenantdom.ErrPersonalOrgNotPending
	}
	if f.members[c.UserID] {
		f.status[c.UserID] = tenantdom.PersonalOrgSkipped
		return tenantdom.ErrPersonalOrgHasMembership
	}
	if f.invited[c.UserID] {
		return tenantdom.ErrPersonalOrgInvited
	}
	f.status[c.UserID] = tenantdom.PersonalOrgCreated
	f.made = append(f.made, c)
	return nil
}

type recordedSignupEvents struct {
	mu     sync.Mutex
	events []signupevent.Event
}

func (r *recordedSignupEvents) Record(_ context.Context, e signupevent.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

type claimedDomain struct{ ep verifieddomain.EmailPolicy }

func (c claimedDomain) SignupPolicyForEmail(context.Context, string) (verifieddomain.EmailPolicy, bool, error) {
	return c.ep, true, nil
}

type capReached struct{}

func (capReached) SelfServiceDefaults(context.Context) (limits.Limits, int, error) {
	return limits.Limits{}, 0, nil
}

func (capReached) CheckOrgsPerUser(context.Context, shared.ID) error {
	return errors.New("limit reached")
}

var (
	personalOn  = signupdom.Static{Mode: signupdom.ModeSelfService, Accounts: signupdom.AccountsOpen, PersonalOrganization: true}
	personalOff = signupdom.Static{Mode: signupdom.ModeSelfService, Accounts: signupdom.AccountsOpen}
)

func verifiedUser(t *testing.T, email, name string) *userdom.User {
	t.Helper()
	u, err := userdom.NewOAuthUser(email, name, "", userdom.AuthProviderGoogle)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestPersonalOrgEnsureMakesOneOrganization(t *testing.T) {
	repo := newFakePersonalOrgs()
	feed := &recordedSignupEvents{}
	p := NewPersonalOrganizations(repo, personalOn, logger.NewNop())
	p.SetSignupRecorder(feed)
	u := verifiedUser(t, "jane@example.com", "Jane Doe")
	p.Reserve(context.Background(), u.ID(), signupdom.OutcomeSelfService)

	got := p.Ensure(context.Background(), u, "203.0.113.7", "test")
	if got == nil {
		t.Fatal("no organization made")
	}
	if got.Name() != "Jane Doe's organization" || !tenantdom.IsValidSlug(got.Slug()) {
		t.Fatalf("name %q slug %q", got.Name(), got.Slug())
	}
	c := repo.made[0]
	if c.Membership.UserID() != u.ID() || c.Membership.TenantID() != got.ID() || c.Membership.Role() != tenantdom.RoleOwner {
		t.Fatal("the person must be the owner of their new organization")
	}
	if c.EmailDomain != "example.com" || c.IPPrefix != "203.0.113.0/24" || c.Rates.PerPrefix == 0 || c.Rates.PerDomain == 0 {
		t.Fatalf("rate inputs: %+v", c)
	}
	if len(feed.events) != 1 || feed.events[0].Source != signupevent.SourcePersonalOrganization ||
		feed.events[0].Kind != signupevent.KindOrganizationCreated || feed.events[0].TenantID != got.ID() {
		t.Fatalf("sign-up feed: %+v", feed.events)
	}
	// A retry (another tab, the next sign-in) makes nothing more.
	if again := p.Ensure(context.Background(), u, "203.0.113.7", "test"); again != nil || len(repo.made) != 1 {
		t.Fatal("a second sign-in made a second organization")
	}
}

func TestPersonalOrgEnsureConcurrentSignInsMakeOne(t *testing.T) {
	repo := newFakePersonalOrgs()
	p := NewPersonalOrganizations(repo, personalOn, logger.NewNop())
	u := verifiedUser(t, "tabs@example.com", "Tabs")
	p.Reserve(context.Background(), u.ID(), signupdom.OutcomeSelfService)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); p.Ensure(context.Background(), u, "", "") }()
	}
	wg.Wait()
	if len(repo.made) != 1 {
		t.Fatalf("made %d organizations, want 1", len(repo.made))
	}
}

func TestPersonalOrgNotMade(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		setup func(p *PersonalOrganizations, repo *fakePersonalOrgs, u *userdom.User)
	}{
		{"switch off", func(p *PersonalOrganizations, _ *fakePersonalOrgs, _ *userdom.User) { p.policy = personalOff }},
		{"organizations admin_only", func(p *PersonalOrganizations, _ *fakePersonalOrgs, _ *userdom.User) {
			p.policy = signupdom.Static{Mode: signupdom.ModeAdminOnly, Accounts: signupdom.AccountsOpen, PersonalOrganization: true}
		}},
		{"address not verified", func(_ *PersonalOrganizations, _ *fakePersonalOrgs, u *userdom.User) { u.MarkEmailUnverified() }},
		{"not marked (invited, SSO, console account)", func(_ *PersonalOrganizations, repo *fakePersonalOrgs, u *userdom.User) {
			delete(repo.status, u.ID())
		}},
		{"pending invitation for the address", func(p *PersonalOrganizations, _ *fakePersonalOrgs, u *userdom.User) {
			p.SetInvitationLookup(fakeInvitations{invited: map[string]bool{u.Email(): true}})
		}},
		{"ownership invitation (checked in the transaction)", func(_ *PersonalOrganizations, repo *fakePersonalOrgs, u *userdom.User) {
			repo.invited[u.ID()] = true
		}},
		{"already a member somewhere", func(_ *PersonalOrganizations, repo *fakePersonalOrgs, u *userdom.User) {
			repo.members[u.ID()] = true
		}},
		{"domain claimed by an organization", func(p *PersonalOrganizations, _ *fakePersonalOrgs, _ *userdom.User) {
			p.SetDomainPolicy(claimedDomain{})
		}},
		{"domain auto-joins", func(p *PersonalOrganizations, _ *fakePersonalOrgs, _ *userdom.User) {
			p.SetDomainPolicy(claimedDomain{ep: verifieddomain.EmailPolicy{Policy: verifieddomain.SignupPolicy{Join: verifieddomain.JoinAuto}}})
		}},
		{"domain requires SSO", func(p *PersonalOrganizations, _ *fakePersonalOrgs, _ *userdom.User) {
			p.SetDomainPolicy(claimedDomain{ep: verifieddomain.EmailPolicy{Policy: verifieddomain.SignupPolicy{SSORequired: true}}})
		}},
		{"rate bound reached", func(_ *PersonalOrganizations, repo *fakePersonalOrgs, _ *userdom.User) {
			repo.failNext = tenantdom.ErrPersonalOrgRateLimited
		}},
		{"per-person organization cap", func(p *PersonalOrganizations, _ *fakePersonalOrgs, _ *userdom.User) {
			p.SetLimits(capReached{})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo := newFakePersonalOrgs()
			p := NewPersonalOrganizations(repo, personalOn, logger.NewNop())
			u := verifiedUser(t, "sam@example.com", "Sam")
			repo.status[u.ID()] = tenantdom.PersonalOrgPending
			c.setup(p, repo, u)
			if got := p.Ensure(ctx, u, "203.0.113.7", ""); got != nil || len(repo.made) != 0 {
				t.Fatal("an organization was made")
			}
		})
	}
}

// After a refusal that can pass (rate bound), the mark stays and the next
// sign-in makes the organization.
func TestPersonalOrgRateBoundIsRetriedLater(t *testing.T) {
	repo := newFakePersonalOrgs()
	p := NewPersonalOrganizations(repo, personalOn, logger.NewNop())
	u := verifiedUser(t, "later@example.com", "Later")
	repo.status[u.ID()] = tenantdom.PersonalOrgPending
	repo.failNext = tenantdom.ErrPersonalOrgRateLimited
	if p.Ensure(context.Background(), u, "", "") != nil {
		t.Fatal("made above the bound")
	}
	if p.Ensure(context.Background(), u, "", "") == nil {
		t.Fatal("not made once under the bound")
	}
}

func TestPersonalOrgSlugTakenIsRetried(t *testing.T) {
	repo := newFakePersonalOrgs()
	p := NewPersonalOrganizations(repo, personalOn, logger.NewNop())
	u := verifiedUser(t, "slug@example.com", "Slug")
	repo.status[u.ID()] = tenantdom.PersonalOrgPending
	repo.failNext = tenantdom.ErrPersonalOrgSlugTaken
	if p.Ensure(context.Background(), u, "", "") == nil {
		t.Fatal("a taken address must be retried with another")
	}
}

func TestPersonalOrgReserveOnlyForSelfService(t *testing.T) {
	ctx := context.Background()
	repo := newFakePersonalOrgs()
	p := NewPersonalOrganizations(repo, personalOn, logger.NewNop())
	for _, o := range []signupdom.Outcome{signupdom.OutcomeAcceptInvitation, signupdom.OutcomeJITMember, signupdom.OutcomeDomainAccount} {
		id := shared.NewID()
		p.Reserve(ctx, id, o)
		if _, ok := repo.status[id]; ok {
			t.Fatalf("%s marked", o)
		}
	}
	off := NewPersonalOrganizations(repo, personalOff, logger.NewNop())
	id := shared.NewID()
	off.Reserve(ctx, id, signupdom.OutcomeSelfService)
	if _, ok := repo.status[id]; ok {
		t.Fatal("marked while the switch is off")
	}
	// A nil service does nothing.
	var none *PersonalOrganizations
	none.Reserve(ctx, id, signupdom.OutcomeSelfService)
	if none.Ensure(ctx, verifiedUser(t, "n@example.com", "N"), "", "") != nil {
		t.Fatal("nil service made an organization")
	}
}

// Social sign-up: a new Google account is marked and gets its organization;
// an invited one is not marked.
func TestOAuthSignupMarksPersonalOrganization(t *testing.T) {
	for _, c := range []struct {
		name     string
		invited  bool
		wantMark bool
	}{{"stranger", false, true}, {"invited", true, false}} {
		t.Run(c.name, func(t *testing.T) {
			users := &fakeUserRepo{}
			repo := newFakePersonalOrgs()
			p := NewPersonalOrganizations(repo, personalOn, logger.NewNop())
			svc := &OAuthService{userRepo: users, logger: logger.NewNop(), authConfig: config.AuthConfig{}}
			svc.SetSignupPolicy(personalOn)
			svc.SetInvitationLookup(fakeInvitations{invited: map[string]bool{"new@example.com": c.invited}})
			svc.SetPersonalOrganizations(p)
			u, err := svc.findOrCreateUser(context.Background(),
				&OAuthUserInfo{Email: "new@example.com", Name: "New", HD: "example.com"}, OAuthProviderGoogle)
			if err != nil || u == nil {
				t.Fatalf("sign-up: %v", err)
			}
			if _, marked := repo.status[u.ID()]; marked != c.wantMark {
				t.Fatalf("marked=%v, want %v", marked, c.wantMark)
			}
			if c.wantMark && p.Ensure(context.Background(), u, "", "") == nil {
				t.Fatal("the provider-verified account did not get its organization")
			}
		})
	}
}

func TestPersonalOrgNameAndSlug(t *testing.T) {
	cases := []struct{ name, email, lang, want string }{
		{"Jane Doe", "j@example.com", "", "Jane Doe's organization"},
		{"  Jane \n Doe ", "j@example.com", "en", "Jane Doe's organization"},
		{"", "sam.lee@example.com", "", "sam.lee's organization"},
		{"Nguyễn An", "a@example.com", "vi", "Tổ chức của Nguyễn An"},
	}
	for _, c := range cases {
		if got := tenantdom.PersonalOrgName(c.name, c.email, c.lang); got != c.want {
			t.Errorf("PersonalOrgName(%q) = %q, want %q", c.name, got, c.want)
		}
	}
	for _, in := range []string{"Nguyễn Đức An", "", "李小龍", "---"} {
		s, err := tenantdom.PersonalOrgSlug(in, "x@example.com")
		if err != nil || !tenantdom.IsValidSlug(s) {
			t.Errorf("PersonalOrgSlug(%q) = %q %v", in, s, err)
		}
	}
	a, _ := tenantdom.PersonalOrgSlug("Same", "s@example.com")
	b, _ := tenantdom.PersonalOrgSlug("Same", "s@example.com")
	if a == b {
		t.Error("two slugs for the same name must differ (random suffix)")
	}
}

// L3: a pending mark is honored only within its lifetime of the sign-up.
func TestPersonalOrgMarkExpires(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name string
		age  time.Duration
		want bool
	}{{"29 days old", 29 * 24 * time.Hour, true}, {"31 days old", 31 * 24 * time.Hour, false}} {
		t.Run(c.name, func(t *testing.T) {
			repo := newFakePersonalOrgs()
			p := NewPersonalOrganizations(repo, personalOn, logger.NewNop())
			u := verifiedUser(t, "old@example.com", "Old")
			if err := repo.ReservePersonalOrganization(ctx, u.ID(), time.Now().Add(-c.age)); err != nil {
				t.Fatal(err)
			}
			if got := p.Ensure(ctx, u, "", "") != nil; got != c.want {
				t.Fatalf("made=%v, want %v", got, c.want)
			}
		})
	}
}

// L2: the per-domain bound does not apply to consumer mail domains; the
// per-network bound does.
func TestPersonalOrgRatesForConsumerDomain(t *testing.T) {
	p := NewPersonalOrganizations(newFakePersonalOrgs(), personalOn, logger.NewNop())
	if r := p.ratesFor("gmail.com"); r.PerDomain != 0 || r.PerPrefix != personalOrgPerPrefixPerHour {
		t.Fatalf("gmail.com: %+v", r)
	}
	if r := p.ratesFor("example.com"); r.PerDomain != personalOrgPerDomainPerHour {
		t.Fatalf("example.com: %+v", r)
	}
}
