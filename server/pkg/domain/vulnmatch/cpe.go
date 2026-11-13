// Package vulnmatch decides whether a product version an asset runs falls in
// a vulnerability's affected range. It is pure: no I/O, no clock.
//
// Design: docs/rfcs/RFC-066-inventory-vulnerability-matching.md.
package vulnmatch

import (
	"errors"
	"strings"
)

// Limits on input taken from feeds and scan output. A longer value is
// refused, never truncated, so a crafted string cannot turn into a different
// identity.
const (
	MaxCPELen       = 512
	MaxCPEFieldLen  = 128
	MaxVersionLen   = 64
	maxVersionParts = 16
)

// ErrInvalidCPE is returned for a string that is not a CPE 2.3 formatted
// string or a CPE 2.2 URI.
var ErrInvalidCPE = errors.New("invalid CPE name")

// CPE is the part of a CPE name the matcher uses. Values are lower case
// with escapes removed; "*" means any value and "-" means not applicable.
type CPE struct {
	Part      string // a (application), o (operating system), h (hardware)
	Vendor    string
	Product   string
	Version   string
	Update    string
	SWEdition string // e.g. "community" vs "enterprise"
	TargetSW  string // platform the product is built for, e.g. "wordpress"
}

// Any and NA are the CPE logical values.
const (
	Any = "*"
	NA  = "-"
)

// ParseCPE parses a CPE 2.3 formatted string
// ("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*") or a CPE 2.2 URI
// ("cpe:/a:nginx:nginx:1.18.0"). Missing trailing fields are "*".
func ParseCPE(s string) (CPE, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxCPELen {
		return CPE{}, ErrInvalidCPE
	}
	lower := strings.ToLower(s)
	var fields []string
	switch {
	case strings.HasPrefix(lower, "cpe:2.3:"):
		fields = splitEscaped(lower[len("cpe:2.3:"):])
	case strings.HasPrefix(lower, "cpe:/"):
		fields = strings.Split(lower[len("cpe:/"):], ":")
		for i, f := range fields {
			fields[i] = uriDecode(f)
			if fields[i] == "" {
				fields[i] = Any
			}
		}
	default:
		return CPE{}, ErrInvalidCPE
	}
	if len(fields) < 3 || len(fields) > 11 {
		return CPE{}, ErrInvalidCPE
	}
	get := func(i int) string {
		if i < len(fields) {
			return fields[i]
		}
		return Any
	}
	c := CPE{
		Part:      get(0),
		Vendor:    get(1),
		Product:   get(2),
		Version:   get(3),
		Update:    get(4),
		SWEdition: get(7),
		TargetSW:  get(8),
	}
	switch c.Part {
	case "a", "o", "h":
	default:
		return CPE{}, ErrInvalidCPE
	}
	for _, v := range []string{c.Vendor, c.Product, c.Version, c.Update, c.SWEdition, c.TargetSW} {
		if v == "" || len(v) > MaxCPEFieldLen || hasControl(v) {
			return CPE{}, ErrInvalidCPE
		}
	}
	// A name must say whose product it is: "any vendor" or "any product"
	// would match every asset.
	if !isConcrete(c.Vendor) || !isConcrete(c.Product) {
		return CPE{}, ErrInvalidCPE
	}
	return c, nil
}

// Key is the identity the matcher joins on: part, vendor and product.
func (c CPE) Key() string { return MatchKey(c.Part, c.Vendor, c.Product) }

// MatchKey builds the join key "cpe:<part>:<vendor>:<product>".
func MatchKey(part, vendor, product string) string {
	return "cpe:" + strings.ToLower(part) + ":" + strings.ToLower(vendor) + ":" + strings.ToLower(product)
}

// ValidMatchKey reports whether k is a key MatchKey could have built from a
// concrete part, vendor and product.
func ValidMatchKey(k string) bool {
	if len(k) > MaxCPELen || !strings.HasPrefix(k, "cpe:") {
		return false
	}
	parts := strings.SplitN(k[len("cpe:"):], ":", 3)
	if len(parts) != 3 {
		return false
	}
	switch parts[0] {
	case "a", "o", "h":
	default:
		return false
	}
	return isConcrete(parts[1]) && isConcrete(parts[2]) && !strings.Contains(parts[2], ":") &&
		!hasControl(parts[1]) && !hasControl(parts[2]) && strings.ToLower(k) == k
}

func isConcrete(v string) bool {
	return v != "" && v != Any && v != NA && !strings.ContainsAny(v, "*?")
}

// splitEscaped splits a CPE 2.3 formatted string on unescaped colons and
// removes the escapes ("\:" → ":", "\." → ".").
func splitEscaped(s string) []string {
	var out []string
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		if ch == ':' {
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(ch)
	}
	return append(out, b.String())
}

// uriDecode decodes the percent escapes a CPE 2.2 URI uses for punctuation.
func uriDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, ok := hexByte(s[i+1], s[i+2]); ok {
				b.WriteByte(v)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexByte(a, b byte) (byte, bool) {
	h, ok1 := hexVal(a)
	l, ok2 := hexVal(b)
	return h<<4 | l, ok1 && ok2
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
