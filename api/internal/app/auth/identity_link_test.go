package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// --- fakes ------------------------------------------------------------------

type fakeRevoker struct {
	revoked []string
	except  []string
}

func (f *fakeRevoker) RevokeAllSessions(_ context.Context, userID, except string) error {
	f.revoked = append(f.revoked, userID)
	f.except = append(f.except, except)
	return nil
}

type fakeNotifier struct {
	linked, unlinked []string
}

func (f *fakeNotifier) NotifyIdentityLinked(_ context.Context, email, _, _, provider string) {
	f.linked = append(f.linked, email+"|"+provider)
}

func (f *fakeNotifier) NotifyIdentityUnlinked(_ context.Context, email, _, _, provider string) {
	f.unlinked = append(f.unlinked, email+"|"+provider)
}

// fakeGate answers a fixed challenge and records the accounts it was asked
// about.
type fakeGate struct {
	challenge *MFAChallengeInfo
	asked     []shared.ID
}

func (g *fakeGate) LinkedSignInChallenge(_ context.Context, u *userdom.User, _, _ string) (*MFAChallengeInfo, error) {
	g.asked = append(g.asked, u.ID())
	return g.challenge, nil
}

type nopSessions struct {
	sessiondom.Repository
	created int
}

func (r *nopSessions) Create(context.Context, *sessiondom.Session) error { r.created++; return nil }

type nopRefresh struct {
	sessiondom.RefreshTokenRepository
}

func (nopRefresh) Create(context.Context, *sessiondom.RefreshToken) error { return nil }

type linkFixture struct {
	svc      *OAuthService
	users    *fakeUserRepo
	idents   *memIdentities
	revoker  *fakeRevoker
	notifier *fakeNotifier
	sessions *nopSessions
	proof    *fakeLinkProof
}

// fakeLinkProof stands in for AuthService.VerifyLinkProof (tested in
// tests/unit/auth_link_proof_test.go): goodProof passes, an empty proof is
// missing, anything else is wrong.
type fakeLinkProof struct {
	purposes []string
	method   StepUpMethod
}

// goodProof is the proof fakeLinkProof accepts.
var goodProof = StepUpProof{TOTP: "135790"}

func (f *fakeLinkProof) LinkProofMethod(context.Context, string) (StepUpMethod, error) {
	return f.method, nil
}

func (f *fakeLinkProof) VerifyLinkProof(_ context.Context, _ auditapp.AuditContext, _, sessionID string, p StepUpProof, purpose string) (StepUpMethod, error) {
	f.purposes = append(f.purposes, purpose)
	switch {
	case sessionID == "":
		return "", ErrLinkProofUnavailable
	case p == StepUpProof{}:
		return f.method, ErrLinkProofRequired
	case p != goodProof:
		return f.method, ErrLinkProofFailed
	}
	return f.method, nil
}

func newLinkFixture(t *testing.T, existing *userdom.User) *linkFixture {
	t.Helper()
	f := &linkFixture{
		users:    &fakeUserRepo{byEmail: existing},
		idents:   newMemIdentities(),
		revoker:  &fakeRevoker{},
		notifier: &fakeNotifier{},
		sessions: &nopSessions{},
		proof:    &fakeLinkProof{method: StepUpTOTP},
	}
	f.svc = NewOAuthService(f.users, f.sessions, nopRefresh{},
		config.OAuthConfig{Enabled: true, Google: config.OAuthProviderConfig{Enabled: true, ClientID: "c", ClientSecret: "s"}},
		config.AuthConfig{JWTSecret: "test-secret-test-secret-test-secret!", AccessTokenDuration: time.Minute,
			RefreshTokenDuration: time.Hour, SessionDuration: time.Hour},
		logger.NewNop())
	f.svc.SetIdentityRepo(f.idents)
	f.svc.SetSessionRevoker(f.revoker)
	f.svc.SetIdentityNotifier(f.notifier)
	f.svc.SetLinkProofVerifier(f.proof)
	return f
}

// verifiedPasswordAccount is a local account with a password whose address
// was proved, with a pending password reset link.
func verifiedPasswordAccount(t *testing.T, email string) *userdom.User {
	t.Helper()
	u, err := userdom.NewLocalUser(email, "Person", "$2a$10$hash")
	if err != nil {
		t.Fatal(err)
	}
	u.VerifyEmail()
	u.SetPasswordResetToken("pending-reset", time.Now().Add(time.Hour))
	return u
}

func googleInfo(email, sub, hd string) *OAuthUserInfo {
	return &OAuthUserInfo{Email: email, Issuer: googleIssuer, Subject: sub, HD: hd}
}

// --- a collision never links ---------------------------------------------------

// A sign-in whose address belongs to a verified password account never links
// itself, whatever the provider vouches for: Gmail, a Workspace domain,
// Microsoft. There is no setting that turns it on. The answer is the pending
// link, and nothing is written: no identity, no revoked session, no mail, no
// new account, the pending reset link stays.
func TestCollision_NeverLinksAPasswordAccount(t *testing.T) {
	cases := map[string]struct {
		email    string
		info     *OAuthUserInfo
		provider OAuthProvider
	}{
		"gmail":        {"person@gmail.com", googleInfo("person@gmail.com", "g-1", ""), OAuthProviderGoogle},
		"workspace hd": {"a@acme.example", googleInfo("a@acme.example", "g-2", "acme.example"), OAuthProviderGoogle},
		"microsoft": {"a@contoso.example", &OAuthUserInfo{Email: "a@contoso.example",
			Issuer: "https://login.microsoftonline.com/tid-1/v2.0", Subject: "oid-1"}, OAuthProviderMicrosoft},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			acct := verifiedPasswordAccount(t, tc.email)
			f := newLinkFixture(t, acct)
			collide(t, f, tc.info, tc.provider)
			if n := len(f.idents.keysOf(acct.ID())); n != 0 {
				t.Fatalf("identity linked without a proof: %d", n)
			}
			if len(f.revoker.revoked) != 0 || len(f.notifier.linked) != 0 || f.users.created != nil {
				t.Fatal("a collision revoked sessions, sent mail or created an account")
			}
			if acct.PasswordResetToken() == nil {
				t.Fatal("a collision changed the account")
			}
		})
	}
}

// A provider linked to a password account never rewrites the account's
// address, even when the provider now sends another one.
func TestLinkedIdentity_DoesNotMoveThePasswordAccountAddress(t *testing.T) {
	acct := verifiedPasswordAccount(t, "p@gmail.com")
	f := newLinkFixture(t, acct)
	f.idents.bindTo(acct, googleIssuer, "g-1")
	f.users.byEmail, f.users.created = nil, acct // the new address belongs to no one
	got, err := f.svc.findOrCreateUser(context.Background(), googleInfo("renamed@gmail.com", "g-1", ""), OAuthProviderGoogle)
	if err != nil || got.ID() != acct.ID() {
		t.Fatalf("linked sign-in failed: %v", err)
	}
	if acct.Email() != "p@gmail.com" {
		t.Fatalf("password account address moved to %q", acct.Email())
	}
}

// --- second factor after the provider ---------------------------------------

// A password account signed into through a linked provider gets the second
// step of its password sign-in, and no session, when a factor is needed.
func TestSignIn_LinkedPasswordAccountStillNeedsSecondFactor(t *testing.T) {
	acct := verifiedPasswordAccount(t, "p@gmail.com")
	f := newLinkFixture(t, acct)
	f.idents.bindTo(acct, googleIssuer, "g-1")
	gate := &fakeGate{challenge: &MFAChallengeInfo{Token: "challenge", Purpose: mfa.PurposeVerify, ExpiresAt: time.Now().Add(time.Minute)}}
	f.svc.SetSecondFactorGate(gate)

	res, err := f.svc.signIn(context.Background(), googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle, "/")
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if res.MFAChallenge == nil || res.MFAChallenge.Token != "challenge" {
		t.Fatalf("no second step: %+v", res)
	}
	if res.AccessToken != "" || res.RefreshToken != "" || f.sessions.created != 0 {
		t.Fatal("a session was issued before the second factor")
	}
	if len(gate.asked) != 1 || gate.asked[0] != acct.ID() {
		t.Fatalf("gate asked about %v", gate.asked)
	}
}

// Without the gate a password account is never signed in through a provider.
func TestSignIn_PasswordAccountWithoutGateIsRefused(t *testing.T) {
	acct := verifiedPasswordAccount(t, "p@gmail.com")
	f := newLinkFixture(t, acct)
	f.idents.bindTo(acct, googleIssuer, "g-1")
	if _, err := f.svc.signIn(context.Background(), googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle, "/"); !errors.Is(err, ErrOAuthAccountExists) {
		t.Fatalf("want refusal, got %v", err)
	}
	if f.sessions.created != 0 {
		t.Fatal("session issued")
	}
}

// No factor needed: the session is issued; an account of the provider itself
// (no password) never consults the gate.
func TestSignIn_NoSecondFactorNeeded(t *testing.T) {
	t.Run("linked password account without a factor", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f := newLinkFixture(t, acct)
		f.idents.bindTo(acct, googleIssuer, "g-1")
		f.svc.SetSecondFactorGate(&fakeGate{})
		res, err := f.svc.signIn(context.Background(), googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle, "/")
		if err != nil || res.AccessToken == "" || f.sessions.created != 1 {
			t.Fatalf("no session: %+v %v", res, err)
		}
	})
	t.Run("provider account", func(t *testing.T) {
		acct, _ := userdom.NewOAuthUser("g@gmail.com", "G", "", userdom.AuthProviderGoogle)
		f := newLinkFixture(t, acct)
		f.idents.bindTo(acct, googleIssuer, "g-9")
		gate := &fakeGate{challenge: &MFAChallengeInfo{Token: "x"}}
		f.svc.SetSecondFactorGate(gate)
		res, err := f.svc.signIn(context.Background(), googleInfo("g@gmail.com", "g-9", ""), OAuthProviderGoogle, "/")
		if err != nil || res.AccessToken == "" || len(gate.asked) != 0 {
			t.Fatalf("provider account: %+v %v asked=%v", res, err, gate.asked)
		}
	})
}

// --- explicit linking --------------------------------------------------------

// A link state is accepted only by CompleteLink for the account and session
// that started it, and never signs anybody in.
func TestLinkState_BoundToAccountAndSession(t *testing.T) {
	f := newLinkFixture(t, nil)
	state, _, err := f.svc.generateState(OAuthProviderGoogle, "", &linkBinding{UserID: "u-1", SessionID: "s-1"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := f.svc.validateState(state, OAuthProviderGoogle)
	if err != nil || claims.Purpose != statePurposeLink || claims.UserID != "u-1" || claims.SessionID != "s-1" {
		t.Fatalf("claims %+v %v", claims, err)
	}
	ctx := context.Background()
	for name, in := range map[string]LinkCompleteInput{
		"other account": {UserID: "u-2", SessionID: "s-1"},
		"other session": {UserID: "u-1", SessionID: "s-2"},
	} {
		in.Provider, in.State, in.Code = OAuthProviderGoogle, state, "code"
		if _, err := f.svc.CompleteLink(ctx, in); !errors.Is(err, ErrInvalidState) {
			t.Errorf("%s: want ErrInvalidState, got %v", name, err)
		}
	}
	// A sign-in state is not a link state.
	login, _, _ := f.svc.generateState(OAuthProviderGoogle, "/", nil)
	if _, err := f.svc.CompleteLink(ctx, LinkCompleteInput{UserID: "u-1", SessionID: "s-1", Provider: OAuthProviderGoogle, State: login, Code: "c"}); !errors.Is(err, ErrInvalidState) {
		t.Errorf("sign-in state accepted by the link: %v", err)
	}
	// A link state does not sign in.
	if _, err := f.svc.HandleCallback(ctx, CallbackInput{Provider: OAuthProviderGoogle, State: state, Code: "c"}); !errors.Is(err, ErrInvalidState) {
		t.Errorf("link state signed in: %v", err)
	}
}

func TestLinkIdentity(t *testing.T) {
	ctx := context.Background()
	t.Run("links a provider account with another address", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@acme.example")
		f := newLinkFixture(t, acct)
		m, err := f.svc.linkIdentity(ctx, acct.ID().String(), &OAuthUserInfo{Email: "someone@gmail.com", Issuer: googleIssuer, Subject: "g-1"}, OAuthProviderGoogle, linkHowManual, StepUpTOTP)
		if err != nil || m.Provider != "google" {
			t.Fatalf("link: %+v %v", m, err)
		}
		if len(f.notifier.linked) != 1 {
			t.Fatal("manual link not told")
		}
		if len(f.revoker.revoked) != 0 {
			t.Fatal("a manual link must not sign the person out")
		}
	})
	t.Run("provider account linked to another account", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@acme.example")
		other := verifiedPasswordAccount(t, "o@acme.example")
		f := newLinkFixture(t, acct)
		f.users.created = other // GetByID finds both
		f.idents.bindTo(other, googleIssuer, "g-1")
		if _, err := f.svc.linkIdentity(ctx, acct.ID().String(), googleInfo("x@gmail.com", "g-1", ""), OAuthProviderGoogle, linkHowManual, StepUpTOTP); !errors.Is(err, ErrIdentityLinkedElsewhere) {
			t.Fatalf("want ErrIdentityLinkedElsewhere, got %v", err)
		}
		if len(f.idents.keysOf(acct.ID())) != 0 {
			t.Fatal("bound anyway")
		}
	})
	t.Run("second account of the same provider", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@acme.example")
		f := newLinkFixture(t, acct)
		f.idents.bindTo(acct, "https://login.microsoftonline.com/tid-a/v2.0", "oid-a")
		info := &OAuthUserInfo{Email: "p@acme.example", Issuer: "https://login.microsoftonline.com/tid-b/v2.0", Subject: "oid-b"}
		if _, err := f.svc.linkIdentity(ctx, acct.ID().String(), info, OAuthProviderMicrosoft, linkHowManual, StepUpTOTP); !errors.Is(err, ErrProviderAlreadyLinked) {
			t.Fatalf("want ErrProviderAlreadyLinked, got %v", err)
		}
	})
	t.Run("relinking the same identity is a no-op", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@acme.example")
		f := newLinkFixture(t, acct)
		f.idents.bindTo(acct, googleIssuer, "g-1")
		if _, err := f.svc.linkIdentity(ctx, acct.ID().String(), googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle, linkHowManual, StepUpTOTP); err != nil {
			t.Fatalf("relink: %v", err)
		}
		if len(f.idents.keysOf(acct.ID())) != 1 {
			t.Fatal("duplicate identity")
		}
	})
}

// --- unlinking ---------------------------------------------------------------

func TestUnlink(t *testing.T) {
	ctx := context.Background()
	idOf := func(f *linkFixture, u *userdom.User, issuer string) string {
		list, _ := f.idents.ListByUser(ctx, u.ID())
		for _, i := range list {
			if i.Key.Issuer == issuer {
				return i.ID.String()
			}
		}
		t.Fatalf("no identity %s", issuer)
		return ""
	}
	t.Run("password account unlinks its only provider", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f := newLinkFixture(t, acct)
		f.idents.bindTo(acct, googleIssuer, "g-1")
		if err := f.svc.Unlink(ctx, UnlinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), IdentityID: idOf(f, acct, googleIssuer), Proof: goodProof}); err != nil {
			t.Fatalf("unlink: %v", err)
		}
		if len(f.idents.keysOf(acct.ID())) != 0 || len(f.notifier.unlinked) != 1 {
			t.Fatal("not unlinked or not told")
		}
	})
	t.Run("the last sign-in method stays", func(t *testing.T) {
		acct, _ := userdom.NewOAuthUser("g@gmail.com", "G", "", userdom.AuthProviderGoogle)
		f := newLinkFixture(t, acct)
		f.idents.bindTo(acct, googleIssuer, "g-1")
		if err := f.svc.Unlink(ctx, UnlinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), IdentityID: idOf(f, acct, googleIssuer), Proof: goodProof}); !errors.Is(err, ErrLastSignInMethod) {
			t.Fatalf("want ErrLastSignInMethod, got %v", err)
		}
		if len(f.idents.keysOf(acct.ID())) != 1 {
			t.Fatal("last method removed")
		}
	})
	t.Run("a provider account with two providers may drop one", func(t *testing.T) {
		acct, _ := userdom.NewOAuthUser("g@gmail.com", "G", "", userdom.AuthProviderGoogle)
		f := newLinkFixture(t, acct)
		f.idents.bindTo(acct, googleIssuer, "g-1")
		f.idents.bindTo(acct, githubIssuer, "42")
		if err := f.svc.Unlink(ctx, UnlinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), IdentityID: idOf(f, acct, googleIssuer), Proof: goodProof}); err != nil {
			t.Fatalf("unlink: %v", err)
		}
	})
	t.Run("another account's identity is not found", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		other := verifiedPasswordAccount(t, "o@gmail.com")
		f := newLinkFixture(t, acct)
		f.users.created = other
		f.idents.bindTo(other, googleIssuer, "g-o")
		if err := f.svc.Unlink(ctx, UnlinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), IdentityID: idOf(f, other, googleIssuer), Proof: goodProof}); !errors.Is(err, ErrIdentityNotFound) {
			t.Fatalf("want ErrIdentityNotFound, got %v", err)
		}
		if len(f.idents.keysOf(other.ID())) != 1 {
			t.Fatal("another account's identity was removed")
		}
	})
	t.Run("an organization's identity is managed there", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@acme.example")
		f := newLinkFixture(t, acct)
		f.idents.bindTo(acct, "https://idp.acme.example", "sub")
		if err := f.svc.Unlink(ctx, UnlinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), IdentityID: idOf(f, acct, "https://idp.acme.example"), Proof: goodProof}); !errors.Is(err, ErrIdentityNotUnlinkable) {
			t.Fatalf("want ErrIdentityNotUnlinkable, got %v", err)
		}
	})
}

func TestListSignInMethods(t *testing.T) {
	acct, _ := userdom.NewOAuthUser("g@gmail.com", "G", "", userdom.AuthProviderGoogle)
	f := newLinkFixture(t, acct)
	f.idents.bindTo(acct, googleIssuer, "g-1")
	scope := shared.NewID()
	ident, _ := useridentity.New(acct.ID(), useridentity.Key{Issuer: "https://saml.acme.example", Subject: "s", ScopeTenantID: &scope})
	_ = f.idents.Create(context.Background(), ident)

	got, err := f.svc.ListSignInMethods(context.Background(), acct.ID().String())
	if err != nil {
		t.Fatal(err)
	}
	if got.Password || len(got.Identities) != 2 {
		t.Fatalf("methods %+v", got)
	}
	for _, m := range got.Identities {
		switch m.Provider {
		case "google":
			if !m.Unlinkable {
				t.Error("google should be unlinkable: the organization identity remains")
			}
		case "organization":
			if m.Unlinkable {
				t.Error("organization identity must not be unlinkable here")
			}
		default:
			t.Errorf("provider %q", m.Provider)
		}
	}
	if len(got.Available) != 1 || got.Available[0] != "google" {
		t.Fatalf("available %v", got.Available)
	}
}

// Unlinking needs the proof typed for it; a refused proof removes nothing and
// sends no notice.
func TestUnlink_NeedsProof(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		sid   string
		proof StepUpProof
		nilV  bool
		want  error
	}{
		"no proof (a fresh sign-in alone)": {newSessionID(), StepUpProof{}, false, ErrLinkProofRequired},
		"wrong proof":                      {newSessionID(), StepUpProof{TOTP: "000000"}, false, ErrLinkProofFailed},
		"no session":                       {"", goodProof, false, ErrLinkProofUnavailable},
		"no verifier wired (fail closed)":  {newSessionID(), goodProof, true, ErrLinkProofUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			acct := verifiedPasswordAccount(t, "p@gmail.com")
			f := newLinkFixture(t, acct)
			if tc.nilV {
				f.svc.SetLinkProofVerifier(nil)
			}
			f.idents.bindTo(acct, googleIssuer, "g-1")
			list, _ := f.idents.ListByUser(ctx, acct.ID())
			err := f.svc.Unlink(ctx, UnlinkInput{UserID: acct.ID().String(), SessionID: tc.sid, IdentityID: list[0].ID.String(), Proof: tc.proof})
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if len(f.idents.keysOf(acct.ID())) != 1 || len(f.notifier.unlinked) != 0 {
				t.Fatal("unlinked without a proof")
			}
		})
	}
	t.Run("proof is checked for unlink", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f := newLinkFixture(t, acct)
		f.idents.bindTo(acct, googleIssuer, "g-1")
		list, _ := f.idents.ListByUser(ctx, acct.ID())
		if err := f.svc.Unlink(ctx, UnlinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), IdentityID: list[0].ID.String(), Proof: goodProof}); err != nil {
			t.Fatal(err)
		}
		if got := f.proof.purposes; len(got) != 1 || got[0] != LinkProofUnlink {
			t.Fatalf("purposes %v", got)
		}
	})
}
