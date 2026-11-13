// Package emaildomain classifies email and organization domains that no
// single organization can own: public suffixes (from the Public Suffix List,
// both its ICANN and private sections), free consumer mailbox providers and
// disposable-address services.
//
// The lists are embedded at build time, so a check never makes a network call.
// consumer.txt is maintained by hand. disposable.txt is the public-domain
// (CC0) disposable-email-domains blocklist, refreshed with
// scripts/update-disposable-domains.sh.
package emaildomain

import (
	_ "embed"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
)

//go:embed consumer.txt
var consumerList string

//go:embed disposable.txt
var disposableList string

var (
	loadOnce   sync.Once
	consumer   map[string]struct{}
	disposable map[string]struct{}
)

func parseList(raw string) map[string]struct{} {
	set := make(map[string]struct{}, strings.Count(raw, "\n")+1)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[line] = struct{}{}
	}
	return set
}

func load() {
	loadOnce.Do(func() {
		consumer = parseList(consumerList)
		disposable = parseList(disposableList)
	})
}

// normalize lower-cases a domain and strips a leading "@" and a trailing dot.
func normalize(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimPrefix(d, "@")
	return strings.TrimSuffix(d, ".")
}

// inSet reports whether domain or one of its parent domains is in set, so a
// listed provider also covers its subdomains (mail.yahoo.com, x.mailinator.com).
func inSet(set map[string]struct{}, domain string) bool {
	d := normalize(domain)
	for d != "" {
		if _, ok := set[d]; ok {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return false
		}
		d = d[i+1:]
	}
	return false
}

// IsConsumer reports whether domain belongs to a free consumer mailbox
// provider (or a shared platform domain such as onmicrosoft.com).
func IsConsumer(domain string) bool {
	load()
	return inSet(consumer, domain)
}

// IsDisposable reports whether domain belongs to a disposable-address service.
func IsDisposable(domain string) bool {
	load()
	return inSet(disposable, domain)
}

// IsPublicSuffixOrShared reports whether domain cannot be owned by one
// organization because of the Public Suffix List: it is itself a public
// suffix (com, co.uk, github.io), or it sits under a suffix of the list's
// private section (alice.github.io, x.vercel.app), where every name belongs to
// a different customer of that platform.
func IsPublicSuffixOrShared(domain string) bool {
	d := normalize(domain)
	if d == "" {
		return true
	}
	suffix, icann := publicsuffix.PublicSuffix(d)
	if suffix == d {
		return true
	}
	// An unlisted TLD falls back to the default rule "*" (one label, not
	// ICANN); only a multi-label private-section suffix marks a shared
	// platform.
	return !icann && strings.Contains(suffix, ".")
}

// Reason names why a domain cannot be claimed by an organization.
type Reason string

const (
	// ReasonNone: the domain may be claimed (subject to DNS proof).
	ReasonNone Reason = ""
	// ReasonPublicSuffix: a public suffix or a name under a shared platform suffix.
	ReasonPublicSuffix Reason = "public_suffix"
	// ReasonConsumer: a free consumer mailbox provider.
	ReasonConsumer Reason = "consumer"
	// ReasonDisposable: a disposable-address service.
	ReasonDisposable Reason = "disposable"
)

// ClaimRefusal returns why no organization may claim domain, or ReasonNone.
func ClaimRefusal(domain string) Reason {
	switch {
	case IsPublicSuffixOrShared(domain):
		return ReasonPublicSuffix
	case IsConsumer(domain):
		return ReasonConsumer
	case IsDisposable(domain):
		return ReasonDisposable
	}
	return ReasonNone
}
