package auth

import (
	"strings"

	"github.com/crewjam/saml"

	"github.com/openctemio/openctem/api/pkg/oidc"
)

// Second-factor evidence from an identity provider (RFC-058): a host
// organization that requires MFA may accept a trusted home organization's
// sign-in only when the provider proved a second factor. Evidence comes only
// from the signature-verified id_token or assertion, never from userinfo.

// oidcMFAEvidence reports whether a verified id_token says the user completed
// multi-factor authentication: amr carries "mfa" (RFC 8176: multiple-factor
// authentication). Single factors (pwd, otp alone) are not evidence.
func oidcMFAEvidence(c *oidc.Claims) bool {
	if c == nil {
		return false
	}
	for _, m := range c.AMR {
		if strings.EqualFold(strings.TrimSpace(m), "mfa") {
			return true
		}
	}
	return false
}

// samlMultiFactorContexts are AuthnContextClassRef values that state a
// multi-factor authentication.
var samlMultiFactorContexts = map[string]bool{
	"http://schemas.microsoft.com/claims/multipleauthn":                        true,
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract":           true,
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered":       true,
	"urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken":                     true,
	"https://refeds.org/profile/mfa":                                           true,
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication":         true,
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MultifactorAuthenticationContract": true,
}

// samlMFAEvidence reports whether a validated assertion's authentication
// statement states a multi-factor authentication context.
func samlMFAEvidence(a *saml.Assertion) bool {
	if a == nil {
		return false
	}
	for _, st := range a.AuthnStatements {
		if st.AuthnContext.AuthnContextClassRef != nil &&
			samlMultiFactorContexts[strings.TrimSpace(st.AuthnContext.AuthnContextClassRef.Value)] {
			return true
		}
	}
	return false
}
