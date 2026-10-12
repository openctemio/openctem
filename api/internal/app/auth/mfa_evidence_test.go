package auth

import (
	"testing"

	"github.com/crewjam/saml"

	"github.com/openctemio/openctem/api/pkg/oidc"
)

func TestOIDCMFAEvidence(t *testing.T) {
	for _, tc := range []struct {
		amr  []string
		want bool
	}{
		{[]string{"pwd", "mfa"}, true},
		{[]string{"MFA"}, true},
		{[]string{"pwd"}, false},
		{[]string{"otp"}, false},
		{nil, false},
	} {
		if got := oidcMFAEvidence(&oidc.Claims{AMR: tc.amr}); got != tc.want {
			t.Errorf("amr=%v: got %v, want %v", tc.amr, got, tc.want)
		}
	}
	if oidcMFAEvidence(nil) {
		t.Error("no claims, no evidence")
	}
}

func TestSAMLMFAEvidence(t *testing.T) {
	mk := func(ref string) *saml.Assertion {
		return &saml.Assertion{AuthnStatements: []saml.AuthnStatement{{
			AuthnContext: saml.AuthnContext{AuthnContextClassRef: &saml.AuthnContextClassRef{Value: ref}},
		}}}
	}
	if !samlMFAEvidence(mk("http://schemas.microsoft.com/claims/multipleauthn")) {
		t.Error("multipleauthn is MFA")
	}
	if samlMFAEvidence(mk("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")) {
		t.Error("password transport is not MFA")
	}
	if samlMFAEvidence(&saml.Assertion{}) || samlMFAEvidence(nil) {
		t.Error("no statement, no evidence")
	}
}
