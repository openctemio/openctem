package auth

import (
	"context"
	"errors"
	"testing"
)

// fakeDomainVerifier is a scriptable DomainVerifier for the JIT gate tests.
type fakeDomainVerifier struct {
	verified map[string]bool // emailDomain -> verified
	err      error
	gotTID   string
}

func (f *fakeDomainVerifier) IsVerifiedDomain(_ context.Context, tenantID, emailDomain string) (bool, error) {
	f.gotTID = tenantID
	if f.err != nil {
		return false, f.err
	}
	return f.verified[emailDomain], nil
}

// =============================================================================
// SSO P1 — verified-domain membership is the PRIMARY JIT gate
// =============================================================================

// A DNS-verified domain provisions a non-member (no AllowedDomains configured).
func TestP1_JIT_VerifiedDomain_Provisioned(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	svc.domainVerifier = &fakeDomainVerifier{verified: map[string]bool{"corp.com": true}}
	// No AllowedDomains at all — under P0 this would be refused; P1 verified-domain supersedes it.
	rp := &resolvedProvider{autoProvision: true, allowedDomains: nil, defaultRole: "member"}

	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); err != nil {
		t.Fatalf("verified domain must provision, got %v", err)
	}
	if mr.created == nil {
		t.Fatal("verified domain must create a membership")
	}
	if svc.domainVerifier.(*fakeDomainVerifier).gotTID != tenant.ID().String() {
		t.Fatal("verifier must be queried with the target tenant id (tenant-scoped)")
	}
}

// An UNVERIFIED domain is refused even when auto-provision is on (fail-closed).
func TestP1_JIT_UnverifiedDomain_Refused(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	svc.domainVerifier = &fakeDomainVerifier{verified: map[string]bool{}} // nothing verified
	rp := &resolvedProvider{autoProvision: true, allowedDomains: nil, defaultRole: "member"}

	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("unverified domain must refuse JIT, got %v", err)
	}
	if mr.created != nil {
		t.Fatal("refused JIT must NOT create a membership")
	}
}

// Verified-but-not-in-AllowedDomains is refused when the provider ALSO narrows
// via a non-empty AllowedDomains allow-list (both gates required).
func TestP1_JIT_VerifiedButNotInAllowedDomains_Refused(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	svc.domainVerifier = &fakeDomainVerifier{verified: map[string]bool{"corp.com": true}}
	// Domain is verified, but the admin further narrowed to a DIFFERENT domain.
	rp := &resolvedProvider{autoProvision: true, allowedDomains: []string{"other.com"}, defaultRole: "member"}

	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("verified but not in AllowedDomains must refuse, got %v", err)
	}
	if mr.created != nil {
		t.Fatal("refused JIT must NOT create a membership")
	}
}

// Verified AND in AllowedDomains ⇒ provisioned (both gates satisfied).
func TestP1_JIT_VerifiedAndInAllowedDomains_Provisioned(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	svc.domainVerifier = &fakeDomainVerifier{verified: map[string]bool{"corp.com": true}}
	rp := &resolvedProvider{autoProvision: true, allowedDomains: []string{"corp.com"}, defaultRole: "member"}

	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); err != nil {
		t.Fatalf("verified + allowed must provision, got %v", err)
	}
	if mr.created == nil {
		t.Fatal("verified + allowed must create a membership")
	}
}

// A verifier error fails closed (refuse) rather than provisioning.
func TestP1_JIT_VerifierError_FailsClosed(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	svc.domainVerifier = &fakeDomainVerifier{err: errors.New("db down")}
	rp := &resolvedProvider{autoProvision: true, allowedDomains: nil, defaultRole: "member"}

	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("verifier error must fail closed, got %v", err)
	}
	if mr.created != nil {
		t.Fatal("verifier error must NOT create a membership")
	}
}

// autoProvision off ⇒ refused even for a verified domain.
func TestP1_JIT_AutoProvisionOff_Refused(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	svc.domainVerifier = &fakeDomainVerifier{verified: map[string]bool{"corp.com": true}}
	rp := &resolvedProvider{autoProvision: false, allowedDomains: nil, defaultRole: "member"}

	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("auto-provision off must refuse, got %v", err)
	}
	if mr.created != nil {
		t.Fatal("auto-provision off must NOT create a membership")
	}
}

// Nil verifier (pre-wiring) falls back to the P0 AllowedDomains gate:
// empty AllowedDomains ⇒ refused.
func TestP1_JIT_NilVerifier_FallsBackToP0_EmptyRefused(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	svc.domainVerifier = nil // not wired
	rp := &resolvedProvider{autoProvision: true, allowedDomains: nil, defaultRole: "member"}

	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); !errors.Is(err, ErrSSONotAMember) {
		t.Fatalf("nil verifier + empty AllowedDomains must refuse (P0), got %v", err)
	}
	if mr.created != nil {
		t.Fatal("P0 fallback with empty AllowedDomains must NOT create a membership")
	}
}

// Nil verifier falls back to P0: a matching AllowedDomains still provisions,
// so pre-wiring behavior is unchanged.
func TestP1_JIT_NilVerifier_FallsBackToP0_MatchProvisioned(t *testing.T) {
	svc, u, tenant, mr := memberTestFixtures(t)
	svc.domainVerifier = nil
	rp := &resolvedProvider{autoProvision: true, allowedDomains: []string{"corp.com"}, defaultRole: "member"}

	if err := svc.ensureTenantMembership(context.Background(), u, tenant, rp, "jit@corp.com"); err != nil {
		t.Fatalf("nil verifier + matching AllowedDomains must provision (P0), got %v", err)
	}
	if mr.created == nil {
		t.Fatal("P0 fallback with matching AllowedDomains must create a membership")
	}
}
