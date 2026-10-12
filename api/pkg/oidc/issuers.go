package oidc

import (
	"errors"
	"strings"
)

// Issuer rules for providers whose id_token issuer is not one fixed string
// configured with the provider (Expectations.IssuerRule).

var (
	errIssuerMismatch = errors.New("issuer mismatch")
	errTenantMismatch = errors.New("tenant mismatch")
)

// EntraIssuer is the issuer rule for Microsoft Entra ID. The v2 issuer is
// https://login.microsoftonline.com/{tid}/v2.0 where {tid} is the token's
// directory id, so iss and tid must agree. A configured directory pins the
// token to it; the multi-tenant authorities (empty, common, organizations,
// consumers) accept any directory, and the caller's email-domain rules then
// decide who may sign in.
func EntraIssuer(configuredTenant string) func(*Claims) error {
	return func(c *Claims) error {
		if c.TID == "" {
			return errors.New("tid claim is missing")
		}
		if !strings.EqualFold(c.Issuer, "https://login.microsoftonline.com/"+c.TID+"/v2.0") {
			return errIssuerMismatch
		}
		if IsMultiTenantEntraAuthority(configuredTenant) {
			return nil
		}
		if !strings.EqualFold(c.TID, strings.TrimSpace(configuredTenant)) {
			return errTenantMismatch
		}
		return nil
	}
}

// IsMultiTenantEntraAuthority reports whether an Entra tenant setting names
// no single directory ("", common, organizations, consumers): any Microsoft
// account can complete such a flow.
func IsMultiTenantEntraAuthority(tenant string) bool {
	switch strings.ToLower(strings.TrimSpace(tenant)) {
	case "", "common", "organizations", "consumers":
		return true
	}
	return false
}

// OktaIssuer pins the issuer to the configured Okta org's default
// authorization server, the one whose endpoints the flow uses.
func OktaIssuer(orgURL string) func(*Claims) error {
	expected := strings.TrimRight(strings.TrimSpace(orgURL), "/") + "/oauth2/default"
	return func(c *Claims) error {
		if !strings.EqualFold(strings.TrimRight(c.Issuer, "/"), expected) {
			return errIssuerMismatch
		}
		return nil
	}
}

// GoogleIssuer accepts the two issuer spellings Google documents for its
// id_tokens.
func GoogleIssuer(c *Claims) error {
	switch c.Issuer {
	case "https://accounts.google.com", "accounts.google.com":
		return nil
	}
	return errIssuerMismatch
}
