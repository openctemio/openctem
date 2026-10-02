package tenant

import (
	"net"
	"strings"
)

// EmailDomainAllowed reports whether email may join this organization under
// Security.AllowedDomains. An empty list means no restriction. The match is on
// the exact domain after the last "@" (case-insensitive): "corp.com" does not
// admit "eu.corp.com" or "evilcorp.com". It is enforced when a user is invited,
// created by an administrator, accepts an invitation, or is admitted by SSO
// just-in-time provisioning.
func (s SecuritySettings) EmailDomainAllowed(email string) bool {
	if len(s.AllowedDomains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	for _, d := range s.AllowedDomains {
		if strings.ToLower(strings.TrimSpace(d)) == domain {
			return true
		}
	}
	return false
}

// IPAllowlistActive reports whether the organization restricts user sessions
// to Security.IPWhitelist.
func (s SecuritySettings) IPAllowlistActive() bool {
	return len(s.IPWhitelist) > 0
}

// IPAllowed reports whether a client IP may reach this organization's routes
// under Security.IPWhitelist (single addresses or CIDR ranges). An empty list
// means no restriction. An unparseable IP is refused when the list is active,
// and invalid list entries never match (fail closed).
func (s SecuritySettings) IPAllowed(ip string) bool {
	if !s.IPAllowlistActive() {
		return true
	}
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return false
	}
	if v4 := addr.To4(); v4 != nil {
		addr = v4
	}
	for _, entry := range s.IPWhitelist {
		entry = strings.TrimSpace(entry)
		if strings.Contains(entry, "/") {
			if _, network, err := net.ParseCIDR(entry); err == nil && network.Contains(addr) {
				return true
			}
			continue
		}
		if allowed := net.ParseIP(entry); allowed != nil && allowed.Equal(addr) {
			return true
		}
	}
	return false
}
