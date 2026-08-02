package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/config"
	identityproviderdom "github.com/openctemio/api/pkg/domain/identityprovider"
	userdom "github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Proof-before-link — a federated (SSO/OAuth) login must never gain control of
// a PRE-EXISTING account it hasn't proven it owns. Matching an email is never,
// on its own, enough to bind a federated identity.
//
// Four cases (GitLab-style): 4 returning user (allow), 3 different IdP (reject),
// 1 real password account (refuse — sign in first), 2 claimable passwordless
// seat (claim ONLY with IdP-verified email AND a DNS-verified tenant domain).
// =============================================================================

// proofSvc builds an SSOService with a scriptable domain verifier for the Case 2
// gate. verifiedDomains==nil leaves the verifier UNWIRED (fail-closed path).
func proofSvc(existing *userdom.User, verifiedDomains map[string]bool) (*SSOService, *ssoFakeUserRepo) {
	repo := &ssoFakeUserRepo{byEmail: existing}
	svc := &SSOService{userRepo: repo, logger: logger.NewNop(), authConfig: regEnabled()}
	if verifiedDomains != nil {
		svc.domainVerifier = &fakeDomainVerifier{verified: verifiedDomains}
	}
	return svc, repo
}

// -----------------------------------------------------------------------------
// Case 4 — the returning user (same iss+sub already bound) still logs in.
// -----------------------------------------------------------------------------
func TestProofBeforeLink_Case4_ReturningUser_Allowed(t *testing.T) {
	const entraIss = "https://login.microsoftonline.com/dir-1/v2.0"
	u, _ := userdom.NewOAuthUser("user@corp.com", "User", "", userdom.AuthProviderMicrosoft)
	u.BindFederatedIdentity(entraIss, "entra-sub")
	svc, repo := proofSvc(u, map[string]bool{"corp.com": true})

	got, err := svc.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "user@corp.com", Issuer: entraIss, Subject: "entra-sub", EmailVerified: true},
		identityproviderdom.ProviderEntraID)
	if err != nil {
		t.Fatalf("returning user (same iss+sub) must log in, got %v", err)
	}
	if got == nil {
		t.Fatal("expected the returning user back")
	}
	if repo.updated == nil {
		t.Fatal("returning login should stamp last-login via Update")
	}
}

// -----------------------------------------------------------------------------
// Case 3 — a DIFFERENT federated provider bound to the email is rejected.
// -----------------------------------------------------------------------------
func TestProofBeforeLink_Case3_DifferentProvider_Rejected(t *testing.T) {
	// Account created via Google; login attempted via Microsoft/Entra.
	u, _ := userdom.NewOAuthUser("user@corp.com", "User", "", userdom.AuthProviderGoogle)
	svc, repo := proofSvc(u, map[string]bool{"corp.com": true})

	got, err := svc.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "user@corp.com", Issuer: "https://login.microsoftonline.com/x/v2.0", Subject: "s", EmailVerified: true},
		identityproviderdom.ProviderEntraID)
	if err == nil {
		t.Fatal("a different federated provider must be rejected (cross-IdP)")
	}
	if got != nil || repo.updated != nil || repo.created != nil {
		t.Fatal("rejected cross-IdP login must not return a user or persist anything")
	}
}

// Case 3 variant — same provider enum, DIFFERENT verified issuer is rejected
// even with a verified domain (a verified domain must never override the pin).
func TestProofBeforeLink_Case3_SameProviderDifferentIssuer_Rejected(t *testing.T) {
	victim, _ := userdom.NewFromKeycloak("kc", "victim@corp.com", "Victim") // OIDC
	victim.BindFederatedIdentity(corpOkta, "corp-sub")
	svc, repo := proofSvc(victim, map[string]bool{"corp.com": true})

	got, err := svc.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "victim@corp.com", Issuer: evilOkta, Subject: "evil", EmailVerified: true},
		identityproviderdom.ProviderOkta)
	if err == nil {
		t.Fatal("a different verified issuer must be rejected even when the domain is verified")
	}
	if got != nil {
		t.Fatalf("rejected login must not return a user, got %v", got)
	}
	if repo.updated != nil {
		t.Fatal("rejected login must not persist a binding")
	}
	if iss := victim.FederatedIssuer(); iss == nil || *iss != corpOkta {
		t.Fatalf("victim issuer must stay %q, got %v", corpOkta, iss)
	}
}

// -----------------------------------------------------------------------------
// Case 1 — a real PASSWORD account is never silently linked; the user must sign
// in with their existing password first. Even a verified domain does NOT unlock
// silent linking of a password account.
// -----------------------------------------------------------------------------
func TestProofBeforeLink_Case1_PasswordAccount_RefusedNotLinked(t *testing.T) {
	pw, _ := userdom.NewLocalUser("owner@corp.com", "Owner", "argon2-hash")
	svc, repo := proofSvc(pw, map[string]bool{"corp.com": true}) // domain IS verified

	got, err := svc.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "owner@corp.com", Issuer: "https://login.microsoftonline.com/d/v2.0", Subject: "s", EmailVerified: true},
		identityproviderdom.ProviderEntraID)
	if !errors.Is(err, ErrAccountLinkRequiresVerification) {
		t.Fatalf("password account must be refused with ErrAccountLinkRequiresVerification, got %v", err)
	}
	if got != nil {
		t.Fatalf("refused login must not return a user, got %v", got)
	}
	if repo.updated != nil || repo.created != nil {
		t.Fatal("refused login must not persist a login or a federated binding")
	}
	// The account must remain purely local — no federated identity was bound.
	if pw.FederatedIssuer() != nil {
		t.Fatal("a password account must not gain a federated binding from a refused login")
	}
}

// -----------------------------------------------------------------------------
// Case 2 — a claimable passwordless seat is claimed ONLY with proof of ownership.
// -----------------------------------------------------------------------------

// Verified email + DNS-verified tenant domain ⇒ the seat is claimed and bound.
func TestProofBeforeLink_Case2_VerifiedEmailAndDomain_ClaimedAndBound(t *testing.T) {
	const iss = "https://login.microsoftonline.com/dir-1/v2.0"
	invited, _ := userdom.New("invited@corp.com", "Invited") // local, no password
	if invited.PasswordHash() != nil {
		t.Skip("userdom.New unexpectedly set a password")
	}
	svc, repo := proofSvc(invited, map[string]bool{"corp.com": true})

	got, err := svc.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "invited@corp.com", Issuer: iss, Subject: "sub-1", EmailVerified: true},
		identityproviderdom.ProviderEntraID)
	if err != nil {
		t.Fatalf("verified email + verified domain must claim the seat, got %v", err)
	}
	if got == nil {
		t.Fatal("expected the claimed account back")
	}
	if bound := got.FederatedIssuer(); bound == nil || *bound != iss {
		t.Fatalf("the claimed seat must be bound to the IdP issuer %q, got %v", iss, bound)
	}
	if repo.updated == nil {
		t.Fatal("the claim + binding must be persisted via Update")
	}
}

// Verified email but the domain is NOT DNS-verified for the tenant ⇒ refused.
func TestProofBeforeLink_Case2_UnverifiedDomain_Refused(t *testing.T) {
	invited, _ := userdom.New("invited@corp.com", "Invited")
	svc, repo := proofSvc(invited, map[string]bool{}) // verifier wired, nothing verified

	got, err := svc.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "invited@corp.com", Issuer: "iss", Subject: "sub", EmailVerified: true},
		identityproviderdom.ProviderEntraID)
	if !errors.Is(err, ErrAccountLinkRequiresVerification) {
		t.Fatalf("unverified domain must refuse the claim, got %v", err)
	}
	if got != nil || repo.updated != nil {
		t.Fatal("refused claim must not return a user or persist a binding")
	}
	if invited.FederatedIssuer() != nil {
		t.Fatal("refused claim must not bind a federated identity")
	}
}

// DNS-verified domain but the IdP did NOT verify the email ⇒ refused.
func TestProofBeforeLink_Case2_UnverifiedEmail_Refused(t *testing.T) {
	invited, _ := userdom.New("invited@corp.com", "Invited")
	svc, repo := proofSvc(invited, map[string]bool{"corp.com": true})

	got, err := svc.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "invited@corp.com", Issuer: "iss", Subject: "sub", EmailVerified: false},
		identityproviderdom.ProviderEntraID)
	if !errors.Is(err, ErrAccountLinkRequiresVerification) {
		t.Fatalf("unverified email must refuse the claim even with a verified domain, got %v", err)
	}
	if got != nil || repo.updated != nil {
		t.Fatal("refused claim must not return a user or persist a binding")
	}
}

// Domain verifier UNWIRED ⇒ cannot prove ownership ⇒ refused (fail-closed).
func TestProofBeforeLink_Case2_NoVerifier_Refused(t *testing.T) {
	invited, _ := userdom.New("invited@corp.com", "Invited")
	svc, repo := proofSvc(invited, nil) // verifier NOT wired

	got, err := svc.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "invited@corp.com", Issuer: "iss", Subject: "sub", EmailVerified: true},
		identityproviderdom.ProviderEntraID)
	if !errors.Is(err, ErrAccountLinkRequiresVerification) {
		t.Fatalf("no domain verifier must fail closed, got %v", err)
	}
	if got != nil || repo.updated != nil {
		t.Fatal("fail-closed refusal must not return a user or persist a binding")
	}
}

// Domain verifier ERROR ⇒ refused (fail-closed, never claim on error).
func TestProofBeforeLink_Case2_VerifierError_Refused(t *testing.T) {
	invited, _ := userdom.New("invited@corp.com", "Invited")
	repo := &ssoFakeUserRepo{byEmail: invited}
	svc := &SSOService{
		userRepo:       repo,
		logger:         logger.NewNop(),
		authConfig:     regEnabled(),
		domainVerifier: &fakeDomainVerifier{err: errors.New("dns backend down")},
	}

	got, err := svc.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "invited@corp.com", Issuer: "iss", Subject: "sub", EmailVerified: true},
		identityproviderdom.ProviderEntraID)
	if !errors.Is(err, ErrAccountLinkRequiresVerification) {
		t.Fatalf("verifier error must fail closed, got %v", err)
	}
	if got != nil || repo.updated != nil {
		t.Fatal("verifier error refusal must not return a user or persist a binding")
	}
}

// nil tenant context ⇒ refused (fail-closed; a claim needs a tenant to prove
// domain ownership against).
func TestProofBeforeLink_Case2_NilTenant_Refused(t *testing.T) {
	invited, _ := userdom.New("invited@corp.com", "Invited")
	svc, _ := proofSvc(invited, map[string]bool{"corp.com": true})

	got, err := svc.findOrCreateUser(context.Background(), nil,
		&SSOUserInfo{Email: "invited@corp.com", Issuer: "iss", Subject: "sub", EmailVerified: true},
		identityproviderdom.ProviderEntraID)
	if !errors.Is(err, ErrAccountLinkRequiresVerification) {
		t.Fatalf("nil tenant must fail closed, got %v", err)
	}
	if got != nil {
		t.Fatalf("nil-tenant refusal must not return a user, got %v", got)
	}
}

// -----------------------------------------------------------------------------
// New user (no pre-existing account) — normal JIT create, unaffected.
// -----------------------------------------------------------------------------
func TestProofBeforeLink_NewUser_CreatedNormally(t *testing.T) {
	const iss = "https://login.microsoftonline.com/dir-1/v2.0"
	svc, repo := proofSvc(nil, nil) // no existing user; verifier irrelevant to create path

	got, err := svc.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "brand-new@corp.com", Name: "New", Issuer: iss, Subject: "sub", EmailVerified: true},
		identityproviderdom.ProviderEntraID)
	if err != nil {
		t.Fatalf("a brand-new user must be created (JIT), got %v", err)
	}
	if got == nil || repo.created == nil {
		t.Fatal("expected a newly created user")
	}
	if bound := repo.created.FederatedIssuer(); bound == nil || *bound != iss {
		t.Fatalf("new user must be bound to %q, got %v", iss, bound)
	}
}

// Registration disabled + no account ⇒ refused (no self-provisioning). Confirms
// the proof-before-link change did not weaken the FIX 4 registration gate.
func TestProofBeforeLink_NewUser_RegistrationDisabled_Refused(t *testing.T) {
	repo := &ssoFakeUserRepo{byEmail: nil}
	svc := &SSOService{userRepo: repo, logger: logger.NewNop(), authConfig: config.AuthConfig{AllowRegistration: false}}

	_, err := svc.findOrCreateUser(context.Background(), ssoTn(t),
		&SSOUserInfo{Email: "nobody@corp.com", Issuer: "iss", Subject: "sub", EmailVerified: true},
		identityproviderdom.ProviderEntraID)
	if !errors.Is(err, ErrSSORegistrationDisabled) {
		t.Fatalf("registration disabled + no account must refuse, got %v", err)
	}
	if repo.created != nil {
		t.Fatal("must not create a user when registration is disabled")
	}
}
