package assetgroup

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A pasted list holds one name, address, range or URL per line. Parsing is
// strict: the list is untrusted text, so a line is either a value of one
// kind or it is reported as rejected with the reason; nothing is guessed.

// Kinds of a pasted value.
const (
	PasteDomain = "domain"
	PasteIP     = "ip"
	PasteCIDR   = "cidr"
	PasteURL    = "url"
)

// maxPasteValueLen bounds one line.
const maxPasteValueLen = 2048

// PasteItem is one accepted line.
type PasteItem struct {
	Line  int    `json:"line"`
	Kind  string `json:"kind"`
	Value string `json:"value"` // normalised: what is matched and created
}

// PasteRejected is one line that is not a value of any kind.
type PasteRejected struct {
	Line   int    `json:"line"`
	Value  string `json:"value"` // shortened, control characters removed
	Reason string `json:"reason"`
}

// ParsePaste reads a pasted list. It returns the accepted items (duplicates
// folded into the first), the rejected lines, and an error when the list has
// more than MaxPasteLines lines. Blank lines and lines starting with # are
// skipped.
func ParsePaste(text string) (items []PasteItem, rejected []PasteRejected, err error) {
	lines := strings.Split(text, "\n")
	if len(lines) > MaxPasteLines {
		return nil, nil, fmt.Errorf("%w: a pasted list has at most %d lines", shared.ErrValidation, MaxPasteLines)
	}
	seen := make(map[string]struct{}, len(lines))
	for i, raw := range lines {
		line := i + 1
		raw = strings.TrimRight(raw, "\r")
		v := strings.TrimSpace(raw)
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		kind, norm, reason := classifyPaste(v)
		if reason != "" {
			rejected = append(rejected, PasteRejected{Line: line, Value: shortText(v), Reason: reason})
			continue
		}
		key := kind + "\x00" + norm
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, PasteItem{Line: line, Kind: kind, Value: norm})
	}
	return items, rejected, nil
}

// Reasons a line is rejected (codes the web app translates).
const (
	ReasonTooLong       = "too_long"
	ReasonControlChars  = "control_characters"
	ReasonScheme        = "unsupported_scheme"
	ReasonUserInfo      = "credentials_in_url"
	ReasonNotAValue     = "not_a_name_address_or_url"
	ReasonBadRange      = "invalid_range"
	ReasonBroadRange    = "range_too_broad"
	ReasonBadHost       = "invalid_host"
	ReasonSpacesInValue = "spaces_in_value"
)

// minCIDRBits1 / minCIDRBits6 bound how wide a pasted range may be: a /8 or
// /32 prefix of IPv6 would expand to more addresses than any group may hold.
const (
	minCIDRBits4 = 8
	minCIDRBits6 = 32
)

func classifyPaste(v string) (kind, norm, reason string) {
	if len(v) > maxPasteValueLen {
		return "", "", ReasonTooLong
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return "", "", ReasonControlChars
		}
	}
	if strings.ContainsAny(v, " \t") {
		return "", "", ReasonSpacesInValue
	}
	if i := strings.Index(v, "://"); i > 0 {
		return classifyURL(v)
	}
	if strings.Contains(v, ":") && !strings.Contains(v, "/") {
		if a, err := netip.ParseAddr(v); err == nil {
			return PasteIP, a.Unmap().String(), ""
		}
	}
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			// A scheme-less URL (host/path) is not accepted: the value
			// would be ambiguous. Say the range is wrong only for
			// something that looks like one.
			if isAddrish(v) {
				return "", "", ReasonBadRange
			}
			return "", "", ReasonNotAValue
		}
		p = p.Masked()
		if p.Addr().Is4() && p.Bits() < minCIDRBits4 || p.Addr().Is6() && p.Bits() < minCIDRBits6 {
			return "", "", ReasonBroadRange
		}
		return PasteCIDR, p.String(), ""
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return PasteIP, a.Unmap().String(), ""
	}
	if strings.ContainsAny(v, ":") {
		return "", "", ReasonNotAValue
	}
	name, wildcard, err := NormalizeDomain(v)
	if err != nil || wildcard {
		return "", "", ReasonNotAValue
	}
	return PasteDomain, name, ""
}

func isAddrish(v string) bool {
	head, _, _ := strings.Cut(v, "/")
	_, err := netip.ParseAddr(head)
	return err == nil
}

func classifyURL(v string) (kind, norm, reason string) {
	u, err := url.Parse(v)
	if err != nil {
		return "", "", ReasonNotAValue
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", ReasonScheme
	}
	if u.User != nil {
		return "", "", ReasonUserInfo
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", "", ReasonBadHost
	}
	if a, aerr := netip.ParseAddr(host); aerr == nil {
		host = a.Unmap().String()
		if a.Is6() {
			host = "[" + host + "]"
		}
	} else {
		n, wildcard, derr := NormalizeDomain(host)
		if derr != nil || wildcard {
			return "", "", ReasonBadHost
		}
		host = n
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	out := scheme + "://" + host
	if port != "" {
		out += ":" + port
	}
	path := u.EscapedPath()
	if path != "" && path != "/" {
		out += path
	}
	return PasteURL, out, ""
}
