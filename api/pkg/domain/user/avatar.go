package user

import (
	"net/url"
	"strings"
)

// A profile picture is shown to the person's teammates. An arbitrary URL
// would let anyone who sets one (an API client, an identity provider's
// picture claim) log every viewer's IP address and browser, so a picture is
// kept only when it is an https URL on a known avatar host. The web keeps
// the same list (web/src/lib/safe-href.ts, safeAvatarSrc) for values stored
// before this rule.
var avatarHosts = map[string]bool{
	"avatars.githubusercontent.com": true,
	"secure.gravatar.com":           true,
	"www.gravatar.com":              true,
	"gitlab.com":                    true,
}

// avatarHostSuffixes are host suffixes of providers that shard their
// picture CDN (Google: lh3…lh6.googleusercontent.com).
var avatarHostSuffixes = []string{".googleusercontent.com"}

// maxAvatarURLLength matches the profile API's limit.
const maxAvatarURLLength = 500

// AllowedAvatarURL reports whether raw may be stored and shown as a profile
// picture: empty (no picture), or an https URL without credentials or a
// port on a known avatar host.
func AllowedAvatarURL(raw string) bool {
	if raw == "" {
		return true
	}
	if len(raw) > maxAvatarURLLength {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Opaque != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if avatarHosts[host] {
		return true
	}
	for _, s := range avatarHostSuffixes {
		if strings.HasSuffix(host, s) && len(host) > len(s) {
			return true
		}
	}
	return false
}

// SanitizeAvatarURL returns raw when it is allowed, otherwise "" (no
// picture). Used for pictures taken from an identity provider, where a
// refused picture must not fail the sign-in.
func SanitizeAvatarURL(raw string) string {
	if AllowedAvatarURL(raw) {
		return raw
	}
	return ""
}
