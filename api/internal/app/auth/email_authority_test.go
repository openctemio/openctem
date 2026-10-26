package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestEmailAuthoritative(t *testing.T) {
	cases := []struct {
		name     string
		provider OAuthProvider
		info     OAuthUserInfo
		want     bool
	}{
		{"gmail.com", OAuthProviderGoogle, OAuthUserInfo{Email: "a@gmail.com"}, true},
		{"googlemail.com", OAuthProviderGoogle, OAuthUserInfo{Email: "a@GoogleMail.com"}, true},
		{"workspace hd equals domain", OAuthProviderGoogle, OAuthUserInfo{Email: "a@corp.example", HD: "corp.example"}, true},
		{"consumer account on a company address", OAuthProviderGoogle, OAuthUserInfo{Email: "a@corp.example"}, false},
		{"hd of another domain", OAuthProviderGoogle, OAuthUserInfo{Email: "a@corp.example", HD: "other.example"}, false},
		{"github never", OAuthProviderGitHub, OAuthUserInfo{Email: "a@corp.example"}, false},
		{"github on gmail never", OAuthProviderGitHub, OAuthUserInfo{Email: "a@gmail.com"}, false},
		{"microsoft", OAuthProviderMicrosoft, OAuthUserInfo{Email: "a@corp.example"}, true},
		{"unknown provider", OAuthProvider("x"), OAuthUserInfo{Email: "a@gmail.com"}, false},
		{"no domain", OAuthProviderGoogle, OAuthUserInfo{Email: "nodomain"}, false},
	}
	for _, c := range cases {
		if got := emailAuthoritative(c.provider, &c.info); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// joinableDomain says every address's domain is claimed by an organization
// that lets verified holders join automatically.
type joinableDomain struct{}

func (joinableDomain) SignupPolicyForEmail(context.Context, string) (verifieddomain.EmailPolicy, bool, error) {
	return verifieddomain.EmailPolicy{Policy: verifieddomain.SignupPolicy{Join: verifieddomain.JoinAuto}}, true, nil
}

func newSocialSvc(repo *fakeUserRepo, mode signupdom.Policy) *OAuthService {
	s := &OAuthService{userRepo: repo, identities: newMemIdentities(), logger: logger.NewNop()}
	s.SetSignupPolicy(signupdom.Static(mode))
	s.SetSignupDomainPolicy(joinableDomain{})
	s.SetInvitationLookup(fakeInvitations{invited: map[string]bool{"bob@corp.example": true}})
	return s
}

var domainPolicy = signupdom.Policy{Mode: signupdom.ModeAdminOnly, Accounts: signupdom.AccountsDomain}
var openPolicy = signupdom.Policy{Mode: signupdom.ModeSelfService, Accounts: signupdom.AccountsOpen}

// A personal Google account on a company address cannot join the company by
// its domain policy, and cannot claim an invitation for the address.
func TestSocialLogin_NonAuthoritativeEmailCannotJoinOrClaim(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider OAuthProvider
		info     OAuthUserInfo
	}{
		{"personal google on a company address", OAuthProviderGoogle, OAuthUserInfo{Email: "bob@corp.example", Issuer: googleIssuer, Subject: "g-1"}},
		{"github on a company address", OAuthProviderGitHub, OAuthUserInfo{Email: "bob@corp.example", Issuer: githubIssuer, Subject: "42"}},
	} {
		t.Run(tc.name+": domain join refused", func(t *testing.T) {
			repo := &fakeUserRepo{}
			info := tc.info
			info.Email = "carol@corp.example" // no invitation
			_, err := newSocialSvc(repo, domainPolicy).findOrCreateUser(context.Background(), &info, tc.provider)
			if !errors.Is(err, ErrSignupNotAvailable) || repo.created != nil {
				t.Fatalf("a domain join must be refused and write nothing: err=%v created=%v", err, repo.created)
			}
		})
		t.Run(tc.name+": invitation claim refused", func(t *testing.T) {
			repo := &fakeUserRepo{}
			info := tc.info
			_, err := newSocialSvc(repo, domainPolicy).findOrCreateUser(context.Background(), &info, tc.provider)
			if !errors.Is(err, ErrSignupNotAvailable) || repo.created != nil {
				t.Fatalf("an invitation claim must be refused and write nothing: err=%v created=%v", err, repo.created)
			}
		})
		t.Run(tc.name+": open sign-up gives an unverified fresh account", func(t *testing.T) {
			repo := &fakeUserRepo{}
			info := tc.info
			u, err := newSocialSvc(repo, openPolicy).findOrCreateUser(context.Background(), &info, tc.provider)
			if err != nil || u == nil || repo.created == nil {
				t.Fatalf("open sign-up still admits a fresh account: %v", err)
			}
			if u.EmailVerified() {
				t.Fatal("the address was not proved: the account must stay unverified (no invitation or domain join)")
			}
		})
	}
}

func TestSocialLogin_AuthoritativeEmailKeepsItsPrivileges(t *testing.T) {
	repo := &fakeUserRepo{}
	u, err := newSocialSvc(repo, domainPolicy).findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "carol@corp.example", HD: "corp.example", Issuer: googleIssuer, Subject: "g-2"}, OAuthProviderGoogle)
	if err != nil || u == nil || !u.EmailVerified() {
		t.Fatalf("a Workspace account of the domain joins by domain policy and is verified: %v", err)
	}
	repo = &fakeUserRepo{}
	u, err = newSocialSvc(repo, domainPolicy).findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "bob@corp.example", HD: "corp.example", Issuer: googleIssuer, Subject: "g-3"}, OAuthProviderGoogle)
	if err != nil || u == nil {
		t.Fatalf("a Workspace account claims its invitation: %v", err)
	}
	repo = &fakeUserRepo{}
	s := newSocialSvc(repo, openPolicy)
	if u, err = s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "me@gmail.com", Issuer: googleIssuer, Subject: "g-4"}, OAuthProviderGoogle); err != nil || !u.EmailVerified() {
		t.Fatalf("gmail.com is unaffected: %v", err)
	}
}

// An account already bound to the identity signs in whatever the address says.
func TestSocialLogin_BoundIdentitySignsInOnNonAuthoritativeEmail(t *testing.T) {
	u, _ := userdom.NewOAuthUser("bob@corp.example", "Bob", "", userdom.AuthProviderGoogle)
	repo := &emailUsers{all: []*userdom.User{u}}
	ids := newMemIdentities()
	ids.bindTo(u, googleIssuer, "g-1")
	s := &OAuthService{userRepo: repo, identities: ids, logger: logger.NewNop()}
	got, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "bob@corp.example", Issuer: googleIssuer, Subject: "g-1"}, OAuthProviderGoogle)
	if err != nil || got == nil || got.ID() != u.ID() {
		t.Fatalf("bound identity must sign in: %v", err)
	}
}

// A same-provider account with no bound identity is bound only when the
// provider is authoritative for the address (GitHub: sign-in only).
func TestSocialLogin_LegacyAccountBinding(t *testing.T) {
	run := func(provider OAuthProvider, ap userdom.AuthProvider, info OAuthUserInfo) (error, int) {
		u, _ := userdom.NewOAuthUser(info.Email, "U", "", ap)
		ids := newMemIdentities()
		s := &OAuthService{userRepo: &emailUsers{all: []*userdom.User{u}}, identities: ids, logger: logger.NewNop()}
		_, err := s.findOrCreateUser(context.Background(), &info, provider)
		return err, len(ids.keysOf(u.ID()))
	}
	if err, n := run(OAuthProviderGoogle, userdom.AuthProviderGoogle, OAuthUserInfo{Email: "bob@corp.example", Issuer: googleIssuer, Subject: "g-1"}); !errors.Is(err, ErrEmailNotAuthoritative) || n != 0 {
		t.Fatalf("consumer Google on a company address must not bind a legacy account: err=%v bound=%d", err, n)
	}
	if err, n := run(OAuthProviderGoogle, userdom.AuthProviderGoogle, OAuthUserInfo{Email: "bob@corp.example", HD: "corp.example", Issuer: googleIssuer, Subject: "g-1"}); err != nil || n != 1 {
		t.Fatalf("Workspace account binds: err=%v bound=%d", err, n)
	}
	if err, n := run(OAuthProviderGoogle, userdom.AuthProviderGoogle, OAuthUserInfo{Email: "bob@gmail.com", Issuer: googleIssuer, Subject: "g-1"}); err != nil || n != 1 {
		t.Fatalf("gmail binds: err=%v bound=%d", err, n)
	}
	if err, n := run(OAuthProviderGitHub, userdom.AuthProviderGitHub, OAuthUserInfo{Email: "bob@corp.example", Issuer: githubIssuer, Subject: "42"}); err != nil || n != 1 {
		t.Fatalf("GitHub primary verified email binds an account of its own provider: err=%v bound=%d", err, n)
	}
}

// A passwordless account (provisioned by an organization) is not claimed by an
// email the provider does not vouch for.
func TestSocialLogin_NonAuthoritativeEmailCannotClaimSeat(t *testing.T) {
	seat, _ := userdom.New("bob@corp.example", "Bob")
	s, _ := newOAuthSvcWithUser(seat)
	s.identities = newMemIdentities()
	s.SetClaimGuard(claimMembers{ms: nil}, claimDomains{})
	_, err := s.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "bob@corp.example", Issuer: googleIssuer, Subject: "g-9"}, OAuthProviderGoogle)
	if !errors.Is(err, ErrEmailNotAuthoritative) {
		t.Fatalf("a seat must not be claimed by a non-authoritative email: %v", err)
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGitHubEmail_OnlyPrimaryVerified(t *testing.T) {
	get := func(body string) (string, error) {
		s := &OAuthService{httpClient: &http.Client{Transport: rtFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(body))}, nil
		})}}
		return s.getGitHubPrimaryEmail(context.Background(), "tok")
	}
	if e, err := get(`[{"email":"x@corp.example","primary":false,"verified":true},{"email":"me@example.com","primary":true,"verified":true}]`); err != nil || e != "me@example.com" {
		t.Fatalf("primary verified wins: %q %v", e, err)
	}
	if e, err := get(`[{"email":"x@corp.example","primary":false,"verified":true},{"email":"me@example.com","primary":true,"verified":false}]`); err == nil {
		t.Fatalf("a verified non-primary address must not be used, got %q", e)
	}
}
