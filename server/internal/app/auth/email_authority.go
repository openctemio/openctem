package auth

import "strings"

// emailAuthoritative reports whether the provider vouches that the signed-in
// person owns the mailbox of info.Email, in the sense account creation on a
// claimed domain, a domain join, an invitation claim and a seat claim need:
//
//   - Google: the address is on gmail.com or googlemail.com (Google runs the
//     mailbox), or the id_token's hosted-domain claim equals the address's
//     domain (a Workspace account of that domain). A consumer Google account
//     can be made on any address, including a company's, and outlives the
//     person's time there.
//   - GitHub: never. A verified address is verified once and never re-proved,
//     and a GitHub account says nothing about the domain's mailbox.
//   - Microsoft: yes. The sign-in requires the domain-owner-verified claim.
//
// An unknown provider is not authoritative (fail closed).
func emailAuthoritative(provider OAuthProvider, info *OAuthUserInfo) bool {
	switch provider {
	case OAuthProviderMicrosoft:
		return true
	case OAuthProviderGoogle:
		domain := emailDomain(info.Email)
		if domain == "" {
			return false
		}
		if domain == "gmail.com" || domain == "googlemail.com" {
			return true
		}
		return info.HD != "" && strings.EqualFold(info.HD, domain)
	}
	return false
}

// mayBindLegacyAccount reports whether an existing account of this same
// provider that has no bound identity yet may be bound on this sign-in: the
// email is authoritative, or the provider is GitHub (whose address is always
// the primary, verified one and is used for sign-in only).
func mayBindLegacyAccount(provider OAuthProvider, info *OAuthUserInfo) bool {
	return provider == OAuthProviderGitHub || emailAuthoritative(provider, info)
}

func emailDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(email[at+1:]))
}
