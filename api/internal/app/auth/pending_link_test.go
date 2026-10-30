package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

// authAtSessions answers when a session last proved the person.
type authAtSessions struct {
	nopSessions
	at  time.Time
	err error
}

func (s *authAtSessions) RecentAuthAt(context.Context, shared.ID, shared.ID) (time.Time, error) {
	return s.at, s.err
}

func (s *authAtSessions) MarkStepUp(context.Context, shared.ID, shared.ID, time.Time) (bool, error) {
	return true, nil
}

// newPendingFixture is a link fixture with the platform default policy
// (automatic linking off) and a session that signed in now.
func newPendingFixture(t *testing.T, acct *userdom.User) (*linkFixture, *authAtSessions) {
	t.Helper()
	f := newLinkFixture(t, acct)
	f.svc.SetSignupPolicy(signupdom.Static{Mode: signupdom.ModeAdminOnly})
	sess := &authAtSessions{at: time.Now().Add(time.Second)}
	f.svc.sessionRepo = sess
	return f, sess
}

// collide runs the social sign-in and returns the pending link it left.
func collide(t *testing.T, f *linkFixture, info *OAuthUserInfo, p OAuthProvider) *PendingLinkError {
	t.Helper()
	_, err := f.svc.findOrCreateUser(context.Background(), info, p)
	var pending *PendingLinkError
	if !errors.As(err, &pending) || !errors.Is(err, ErrOAuthAccountExists) {
		t.Fatalf("want a pending link wrapping ErrOAuthAccountExists, got %v", err)
	}
	if pending.Token == "" || pending.Provider != p {
		t.Fatalf("pending link incomplete: %+v", pending)
	}
	return pending
}

// suspendedCopy is u as an operator suspended it (users.status).
func suspendedCopy(u *userdom.User) *userdom.User {
	return userdom.Reconstitute(u.ID(), nil, u.Email(), u.Name(), "", "", userdom.StatusSuspended,
		userdom.Preferences{}, nil, time.Now(), time.Now(), u.AuthProvider(), u.PasswordHash(), u.EmailVerified(),
		nil, nil, nil, nil, 0, nil)
}

func newSessionID() string { return shared.NewID().String() }

// The default: a Google sign-in on the address of a verified password account
// links nothing and signs nobody in. It leaves a pending link only.
func TestSocialSignIn_DefaultNeverLinksAutomatically(t *testing.T) {
	acct := verifiedPasswordAccount(t, "person@gmail.com")
	f, _ := newPendingFixture(t, acct)
	collide(t, f, googleInfo("person@gmail.com", "g-1", ""), OAuthProviderGoogle)
	if n := len(f.idents.keysOf(acct.ID())); n != 0 {
		t.Fatalf("identity linked without the person's consent: %d", n)
	}
	if len(f.revoker.revoked) != 0 || len(f.notifier.linked) != 0 || f.users.created != nil {
		t.Fatal("a refused sign-in revoked sessions, sent mail or created an account")
	}
	if acct.PasswordResetToken() == nil {
		t.Fatal("a refused sign-in changed the account")
	}
}

// With automatic linking turned on, an account that has no password (made by
// another provider) is never linked automatically: it gets the pending link.
func TestAutoLink_OnlyPasswordAccounts(t *testing.T) {
	acct, err := userdom.NewOAuthUser("a@acme.example", "A", "", userdom.AuthProviderGoogle)
	if err != nil {
		t.Fatal(err)
	}
	f := newLinkFixture(t, acct) // automatic linking on
	info := &OAuthUserInfo{Email: "a@acme.example", Issuer: "https://login.microsoftonline.com/tid-1/v2.0", Subject: "oid-1"}
	collide(t, f, info, OAuthProviderMicrosoft)
	if n := len(f.idents.keysOf(acct.ID())); n != 0 {
		t.Fatalf("provider account linked automatically: %d", n)
	}
}

// The whole flow: refused sign-in, sign-in to the account, confirm. The
// identity is linked, the account's other sessions are revoked (not the one
// that confirmed), the mailbox is told, and the pending link is spent.
func TestPendingLink_ConfirmAfterSignIn(t *testing.T) {
	for name, tc := range map[string]struct {
		info     *OAuthUserInfo
		provider OAuthProvider
	}{
		"google":                  {googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle},
		"github (proved by both)": {&OAuthUserInfo{Email: "p@gmail.com", Issuer: githubIssuer, Subject: "42"}, OAuthProviderGitHub},
	} {
		t.Run(name, func(t *testing.T) {
			acct := verifiedPasswordAccount(t, "p@gmail.com")
			f, _ := newPendingFixture(t, acct)
			pending := collide(t, f, tc.info, tc.provider)
			ctx := context.Background()

			got, err := f.svc.DescribePendingLink(ctx, acct.ID().String(), pending.Token)
			if err != nil || got.Provider != string(tc.provider) || got.Email != "p@gmail.com" {
				t.Fatalf("describe: %+v %v", got, err)
			}
			sid := newSessionID()
			m, err := f.svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: acct.ID().String(), SessionID: sid, Token: pending.Token})
			if err != nil || m.Provider != string(tc.provider) {
				t.Fatalf("confirm: %+v %v", m, err)
			}
			keys := f.idents.keysOf(acct.ID())
			if len(keys) != 1 || keys[0].Subject != tc.info.Subject {
				t.Fatalf("identity not linked: %+v", keys)
			}
			if len(f.revoker.revoked) != 1 || f.revoker.except[0] != sid {
				t.Fatalf("other sessions not revoked (keeping this one): %v %v", f.revoker.revoked, f.revoker.except)
			}
			if len(f.notifier.linked) != 1 || f.notifier.automatic[0] {
				t.Fatalf("mailbox not told of a confirmed link: %v %v", f.notifier.linked, f.notifier.automatic)
			}
			if _, err := f.svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: acct.ID().String(), SessionID: sid, Token: pending.Token}); !errors.Is(err, ErrPendingLinkInvalid) {
				t.Fatalf("a pending link must be single use, got %v", err)
			}
		})
	}
}

// Every refusal links nothing.
func TestPendingLink_Refusals(t *testing.T) {
	ctx := context.Background()
	t.Run("another account presents it (and spends it)", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f, _ := newPendingFixture(t, acct)
		pending := collide(t, f, googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle)
		other := shared.NewID().String()
		if _, err := f.svc.DescribePendingLink(ctx, other, pending.Token); !errors.Is(err, ErrPendingLinkInvalid) {
			t.Fatalf("describe by another account: %v", err)
		}
		if _, err := f.svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), Token: pending.Token}); !errors.Is(err, ErrPendingLinkInvalid) {
			t.Fatalf("a pending link shown to another account must be spent, got %v", err)
		}
		if n := len(f.idents.keysOf(acct.ID())); n != 0 {
			t.Fatal("linked")
		}
	})
	t.Run("confirm by another account", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f, _ := newPendingFixture(t, acct)
		pending := collide(t, f, googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle)
		if _, err := f.svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: shared.NewID().String(), SessionID: newSessionID(), Token: pending.Token}); !errors.Is(err, ErrPendingLinkInvalid) {
			t.Fatalf("got %v", err)
		}
		if len(f.idents.keysOf(acct.ID())) != 0 || len(f.revoker.revoked) != 0 {
			t.Fatal("linked or revoked")
		}
	})
	t.Run("session authenticated before the pending link", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f, sess := newPendingFixture(t, acct)
		sess.at = time.Now().Add(-time.Hour)
		pending := collide(t, f, googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle)
		if _, err := f.svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), Token: pending.Token}); !errors.Is(err, ErrPendingLinkNeedsSignIn) {
			t.Fatalf("got %v", err)
		}
		if len(f.idents.keysOf(acct.ID())) != 0 {
			t.Fatal("linked")
		}
	})
	t.Run("session record unreadable (fail closed)", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f, sess := newPendingFixture(t, acct)
		sess.err = errors.New("db down")
		pending := collide(t, f, googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle)
		if _, err := f.svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), Token: pending.Token}); !errors.Is(err, ErrPendingLinkNeedsSignIn) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("session store without auth times (fail closed)", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f, _ := newPendingFixture(t, acct)
		f.svc.sessionRepo = &nopSessions{}
		pending := collide(t, f, googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle)
		if _, err := f.svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), Token: pending.Token}); !errors.Is(err, ErrPendingLinkNeedsSignIn) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("account address changed since", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f, _ := newPendingFixture(t, acct)
		pending := collide(t, f, googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle)
		_ = acct.UpdateEmail("moved@example.com")
		if _, err := f.svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), Token: pending.Token}); !errors.Is(err, ErrPendingLinkInvalid) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("account suspended since", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f, _ := newPendingFixture(t, acct)
		pending := collide(t, f, googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle)
		f.users.byEmail = suspendedCopy(acct)
		if _, err := f.svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), Token: pending.Token}); !errors.Is(err, ErrAccountSuspended) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("provider account linked elsewhere meanwhile", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f, _ := newPendingFixture(t, acct)
		pending := collide(t, f, googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle)
		someone, _ := userdom.NewLocalUser("someone@example.com", "S", "$2a$10$hash")
		f.idents.bindTo(someone, googleIssuer, "g-1")
		f.users.created = someone
		if _, err := f.svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), Token: pending.Token}); !errors.Is(err, ErrIdentityLinkedElsewhere) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f, _ := newPendingFixture(t, acct)
		pending := collide(t, f, googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle)
		f.svc.CancelPendingLink(ctx, acct.ID().String(), pending.Token)
		if _, err := f.svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), Token: pending.Token}); !errors.Is(err, ErrPendingLinkInvalid) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("forged, empty and oversized secrets", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f, _ := newPendingFixture(t, acct)
		collide(t, f, googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle)
		long := make([]byte, maxPendingLinkToken+1)
		for i := range long {
			long[i] = 'a'
		}
		for _, tok := range []string{"", "forged", string(long)} {
			if _, err := f.svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), Token: tok}); !errors.Is(err, ErrPendingLinkInvalid) {
				t.Fatalf("%q: got %v", tok, err)
			}
		}
	})
	t.Run("expired", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f, _ := newPendingFixture(t, acct)
		store := NewMemoryPKCEStore()
		f.svc.SetPKCEStore(store)
		pending := collide(t, f, googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle)
		store.mu.Lock()
		for k, e := range store.entries {
			e.expires = time.Now().Add(-time.Second)
			store.entries[k] = e
		}
		store.mu.Unlock()
		if _, err := f.svc.ConfirmPendingLink(ctx, ConfirmPendingLinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), Token: pending.Token}); !errors.Is(err, ErrPendingLinkInvalid) {
			t.Fatalf("got %v", err)
		}
	})
}

// No pending link where linking could never succeed: another identity of the
// provider is already on the account, or the account is suspended.
func TestPendingLink_NotOfferedWhenUnlinkable(t *testing.T) {
	t.Run("provider already linked", func(t *testing.T) {
		acct := verifiedPasswordAccount(t, "p@gmail.com")
		f, _ := newPendingFixture(t, acct)
		f.idents.bindTo(acct, googleIssuer, "g-old")
		_, err := f.svc.findOrCreateUser(context.Background(), googleInfo("p@gmail.com", "g-new", ""), OAuthProviderGoogle)
		var pending *PendingLinkError
		if !errors.Is(err, ErrOAuthAccountExists) || errors.As(err, &pending) {
			t.Fatalf("want a plain ErrOAuthAccountExists, got %v", err)
		}
	})
	t.Run("suspended account", func(t *testing.T) {
		acct := suspendedCopy(verifiedPasswordAccount(t, "p@gmail.com"))
		f, _ := newPendingFixture(t, acct)
		_, err := f.svc.findOrCreateUser(context.Background(), googleInfo("p@gmail.com", "g-1", ""), OAuthProviderGoogle)
		var pending *PendingLinkError
		if !errors.Is(err, ErrOAuthAccountExists) || errors.As(err, &pending) {
			t.Fatalf("want a plain ErrOAuthAccountExists, got %v", err)
		}
	})
}

// A provider's new address counts as verified only where the provider runs
// the mailbox: a GitHub account that switches its primary address keeps the
// account, but the new address is unverified.
func TestProviderEmailChange_VerifiedOnlyWhenAuthoritative(t *testing.T) {
	for name, tc := range map[string]struct {
		provider OAuthProvider
		auth     userdom.AuthProvider
		issuer   string
		hd       string
		want     bool
	}{
		"github":           {OAuthProviderGitHub, userdom.AuthProviderGitHub, githubIssuer, "", false},
		"google workspace": {OAuthProviderGoogle, userdom.AuthProviderGoogle, googleIssuer, "new.example", true},
		"google consumer":  {OAuthProviderGoogle, userdom.AuthProviderGoogle, googleIssuer, "", false},
	} {
		t.Run(name, func(t *testing.T) {
			acct, err := userdom.NewOAuthUser("old@old.example", "A", "", tc.auth)
			if err != nil {
				t.Fatal(err)
			}
			f, _ := newPendingFixture(t, acct)
			f.idents.bindTo(acct, tc.issuer, "s-1")
			f.users.byEmail, f.users.created = nil, acct
			got, err := f.svc.findOrCreateUser(context.Background(),
				&OAuthUserInfo{Email: "a@new.example", Issuer: tc.issuer, Subject: "s-1", HD: tc.hd}, tc.provider)
			if err != nil || got.ID() != acct.ID() || acct.Email() != "a@new.example" {
				t.Fatalf("sign-in: %v %q", err, acct.Email())
			}
			if acct.EmailVerified() != tc.want {
				t.Fatalf("verified = %v, want %v", acct.EmailVerified(), tc.want)
			}
		})
	}
}
