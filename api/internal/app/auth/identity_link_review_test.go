package auth

// Linking review findings: addresses in another case, sessions that outlive
// an unlink or a link, organization sign-on identities shown and unlinked as
// social ones, and a social sign-in through an organization's identity.

import (
	"context"
	"errors"
	"testing"

	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const entraIssuer = "https://login.microsoftonline.com/0b8e2c4a-1111-4222-8333-944455556666/v2.0"

// caseSensitiveUsers holds one account and finds it only by its exact stored
// address, as users.email did before lookups compared lower(email).
type caseSensitiveUsers struct {
	*fakeUserRepo
}

func (r caseSensitiveUsers) GetByEmail(_ context.Context, email string) (*userdom.User, error) {
	if r.byEmail != nil && r.byEmail.Email() == email {
		return r.byEmail, nil
	}
	return nil, userdom.NotFoundByEmailError(email)
}

// failingRevoker fails every revoke.
type failingRevoker struct{ calls int }

func (f *failingRevoker) RevokeAllSessions(context.Context, string, string) error {
	f.calls++
	return errors.New("session store down")
}

// A provider spelling an existing account's address in another case reaches
// that account (its pending link), never a second account.
func TestSocialSignIn_AddressInAnotherCaseFindsTheAccount(t *testing.T) {
	for name, tc := range map[string]struct {
		info     *OAuthUserInfo
		provider OAuthProvider
	}{
		"github": {&OAuthUserInfo{Email: " Alice@Corp.Example ", Issuer: githubIssuer, Subject: "4242", Login: "alice"}, OAuthProviderGitHub},
		"microsoft": {&OAuthUserInfo{Email: "ALICE@corp.example", Issuer: entraIssuer, Subject: "oid-alice"},
			OAuthProviderMicrosoft},
	} {
		t.Run(name, func(t *testing.T) {
			acct := verifiedPasswordAccount(t, "alice@corp.example")
			f := newLinkFixture(t, acct)
			f.svc.userRepo = caseSensitiveUsers{f.users}
			pending := collide(t, f, tc.info, tc.provider)
			if f.users.created != nil {
				t.Fatal("a second account was created for the same mailbox")
			}
			if n := len(f.idents.keysOf(acct.ID())); n != 0 {
				t.Fatalf("identity linked without confirmation: %d", n)
			}
			got, err := f.svc.DescribePendingLink(context.Background(), acct.ID().String(), pending.Token)
			if err != nil || got.Email != "alice@corp.example" {
				t.Fatalf("pending link %+v / %v", got, err)
			}
		})
	}
}

// The confirm dialog shows which provider account is being linked; a picture
// off the known avatar hosts is dropped.
func TestPendingLink_DescribesTheProviderAccount(t *testing.T) {
	acct := verifiedPasswordAccount(t, "p@corp.example")
	f := newLinkFixture(t, acct)
	pending := collide(t, f, &OAuthUserInfo{Email: "p@corp.example", Issuer: githubIssuer, Subject: "77",
		Login: "octo", Name: "Octo Cat", AvatarURL: "https://avatars.githubusercontent.com/u/77"}, OAuthProviderGitHub)
	got, err := f.svc.DescribePendingLink(context.Background(), acct.ID().String(), pending.Token)
	if err != nil {
		t.Fatal(err)
	}
	if got.Login != "octo" || got.Name != "Octo Cat" || got.AvatarURL != "https://avatars.githubusercontent.com/u/77" {
		t.Fatalf("pending link info %+v", got)
	}

	acct2 := verifiedPasswordAccount(t, "q@corp.example")
	f2 := newLinkFixture(t, acct2)
	pending2 := collide(t, f2, &OAuthUserInfo{Email: "q@corp.example", Issuer: githubIssuer, Subject: "78",
		Login: "q", AvatarURL: "https://tracker.example/pixel.png"}, OAuthProviderGitHub)
	got2, err := f2.svc.DescribePendingLink(context.Background(), acct2.ID().String(), pending2.Token)
	if err != nil || got2.AvatarURL != "" {
		t.Fatalf("an off-list picture must be dropped: %+v / %v", got2, err)
	}
}

// Unlinking ends the account's other sessions, keeping the one that proved
// the unlink.
func TestUnlink_RevokesOtherSessions(t *testing.T) {
	ctx := context.Background()
	acct := verifiedPasswordAccount(t, "p@gmail.com")
	f := newLinkFixture(t, acct)
	f.idents.bindTo(acct, googleIssuer, "g-1")
	list, _ := f.idents.ListByUser(ctx, acct.ID())
	sid := newSessionID()
	if err := f.svc.Unlink(ctx, UnlinkInput{UserID: acct.ID().String(), SessionID: sid, IdentityID: list[0].ID.String(), Proof: goodProof}); err != nil {
		t.Fatal(err)
	}
	if len(f.revoker.revoked) != 1 || f.revoker.revoked[0] != acct.ID().String() || f.revoker.except[0] != sid {
		t.Fatalf("revoked %v except %v", f.revoker.revoked, f.revoker.except)
	}
}

// When the other sessions cannot be ended, nothing is unlinked (fail closed),
// and the same when no revoker is wired.
func TestUnlink_RevokeFailureUnlinksNothing(t *testing.T) {
	ctx := context.Background()
	for name, r := range map[string]SessionRevoker{"revoke fails": &failingRevoker{}, "no revoker": nil} {
		t.Run(name, func(t *testing.T) {
			acct := verifiedPasswordAccount(t, "p@gmail.com")
			f := newLinkFixture(t, acct)
			f.svc.SetSessionRevoker(r)
			f.idents.bindTo(acct, googleIssuer, "g-1")
			list, _ := f.idents.ListByUser(ctx, acct.ID())
			err := f.svc.Unlink(ctx, UnlinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), IdentityID: list[0].ID.String(), Proof: goodProof})
			if err == nil {
				t.Fatal("unlinked although the other sessions were not revoked")
			}
			if len(f.idents.keysOf(acct.ID())) != 1 || len(f.notifier.unlinked) != 0 {
				t.Fatal("identity removed or notice sent after a failed revoke")
			}
		})
	}
}

// A completed explicit link ends the account's other sessions first.
func TestCompleteLink_RevokesOtherSessions(t *testing.T) {
	f := newLinkBindingFixture(t)
	state, binding := f.start(t)
	if _, err := f.complete(state, binding, "code"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if len(f.revoker.revoked) != 1 || f.revoker.except[0] != "s-1" {
		t.Fatalf("revoked %v except %v", f.revoker.revoked, f.revoker.except)
	}
}

// When the other sessions cannot be ended, nothing is linked.
func TestCompleteLink_RevokeFailureLinksNothing(t *testing.T) {
	f := newLinkBindingFixture(t)
	fr := &failingRevoker{}
	f.svc.SetSessionRevoker(fr)
	state, binding := f.start(t)
	if _, err := f.complete(state, binding, "code"); err == nil {
		t.Fatal("linked although the other sessions were not revoked")
	}
	if fr.calls != 1 {
		t.Fatalf("revoke calls %d", fr.calls)
	}
	f.assertNotLinked(t)
}

// An organization's Entra ID sign-on stores the same unscoped issuer as the
// social Microsoft button. Its identity is managed by the organization: shown
// as such, never unlinkable here, and it does not count as the account's
// Microsoft link.
func TestOrganizationSignOnIdentity_IsNotSocial(t *testing.T) {
	ctx := context.Background()
	acct := verifiedPasswordAccount(t, "p@contoso.example")
	f := newLinkFixture(t, acct)
	f.idents.bindSSO(acct, entraIssuer, "oid-p")

	got, err := f.svc.ListSignInMethods(ctx, acct.ID().String())
	if err != nil || len(got.Identities) != 1 {
		t.Fatalf("methods %+v / %v", got, err)
	}
	if m := got.Identities[0]; m.Provider != "organization" || m.Unlinkable {
		t.Fatalf("organization sign-on shown as %+v", m)
	}

	list, _ := f.idents.ListByUser(ctx, acct.ID())
	err = f.svc.Unlink(ctx, UnlinkInput{UserID: acct.ID().String(), SessionID: newSessionID(), IdentityID: list[0].ID.String(), Proof: goodProof})
	if !errors.Is(err, ErrIdentityNotUnlinkable) {
		t.Fatalf("want ErrIdentityNotUnlinkable, got %v", err)
	}
	if len(f.idents.keysOf(acct.ID())) != 1 || len(f.revoker.revoked) != 0 || len(f.notifier.unlinked) != 0 {
		t.Fatal("organization identity removed, sessions revoked or notice sent")
	}

	// A personal Microsoft account may still be linked beside it.
	personal := &OAuthUserInfo{Email: "p@outlook.example", Issuer: "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0", Subject: "msa-p"}
	if _, err := f.svc.linkIdentity(ctx, acct.ID().String(), personal, OAuthProviderMicrosoft, linkHowManual, StepUpTOTP); err != nil {
		t.Fatalf("personal Microsoft link refused beside the organization identity: %v", err)
	}
}

// A social Microsoft sign-in through an identity an organization's sign-on
// manages signs in to that account but never moves its address: the
// organization changes it only for a domain it proved.
func TestSocialSignIn_ThroughOrganizationIdentityKeepsTheAddress(t *testing.T) {
	acct, err := userdom.NewFederatedUser("p@contoso.example", "P", "", userdom.AuthProviderMicrosoft)
	if err != nil {
		t.Fatal(err)
	}
	f := newLinkFixture(t, acct)
	f.users.byEmail, f.users.created = nil, acct
	f.idents.bindSSO(acct, entraIssuer, "oid-p")
	got, err := f.svc.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "p@unproved.example", Issuer: entraIssuer, Subject: "oid-p"}, OAuthProviderMicrosoft)
	if err != nil || got.ID() != acct.ID() {
		t.Fatalf("sign-in: %v", err)
	}
	if acct.Email() != "p@contoso.example" {
		t.Fatalf("address moved to %q through the social button", acct.Email())
	}

	// A social identity still follows the provider's address.
	social, _ := userdom.NewOAuthUser("s@outlook.example", "S", "", userdom.AuthProviderMicrosoft)
	f2 := newLinkFixture(t, social)
	f2.users.byEmail, f2.users.created = nil, social
	f2.idents.bindTo(social, entraIssuer, "oid-s")
	if _, err := f2.svc.findOrCreateUser(context.Background(),
		&OAuthUserInfo{Email: "s2@outlook.example", Issuer: entraIssuer, Subject: "oid-s"}, OAuthProviderMicrosoft); err != nil {
		t.Fatal(err)
	}
	if social.Email() != "s2@outlook.example" {
		t.Fatalf("social identity address %q", social.Email())
	}
}

// The organization's sign-on marks an identity it asserts as its own, so an
// identity first bound by the social button is managed by the organization
// once its sign-on uses it. The social path never marks.
func TestOrganizationSignOn_MarksTheIdentity(t *testing.T) {
	ctx := context.Background()
	acct := verifiedPasswordAccount(t, "p@contoso.example")
	idents := newMemIdentities()
	idents.bindTo(acct, entraIssuer, "oid-p")
	key := useridentity.Key{Issuer: entraIssuer, Subject: "oid-p"}

	social := federatedAccounts{identities: idents, logger: logger.NewNop(), source: useridentity.SourceSocial}
	ident, _ := idents.GetByKey(ctx, key)
	social.markUsed(ctx, ident)
	if got, _ := idents.GetByKey(ctx, key); got.Source != useridentity.SourceSocial {
		t.Fatalf("social sign-in marked the identity %q", got.Source)
	}

	sso := federatedAccounts{identities: idents, logger: logger.NewNop(), source: useridentity.SourceSSO}
	sso.markUsed(ctx, ident)
	if got, _ := idents.GetByKey(ctx, key); got.Source != useridentity.SourceSSO {
		t.Fatalf("organization sign-on left the identity %q", got.Source)
	}

	// A new binding by the organization's sign-on is its own from the start.
	other := verifiedPasswordAccount(t, "o@contoso.example")
	if err := sso.bind(ctx, other, useridentity.Key{Issuer: entraIssuer, Subject: "oid-o"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := idents.GetByKey(ctx, useridentity.Key{Issuer: entraIssuer, Subject: "oid-o"}); got.Source != useridentity.SourceSSO {
		t.Fatalf("new organization binding %q", got.Source)
	}
}
