package email

import (
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"strings"
	"time"
)

// Locale codes the e-mail catalog has. Anything else renders in DefaultLocale.
const (
	LocaleEN      = "en"
	LocaleVI      = "vi"
	DefaultLocale = LocaleEN
)

//go:embed locales/*.json
var localeFS embed.FS

// catalog holds the strings of every locale, keyed by locale then key. It is
// trusted content compiled into the binary: the only markup in it is the
// inline <strong>/<span>/<a> a value is meant to carry, and user values are
// never part of it (they are placeholders {0}, {1}, ... filled in at render).
var catalog = mustLoadCatalog()

func mustLoadCatalog() map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, l := range []string{LocaleEN, LocaleVI} {
		raw, err := localeFS.ReadFile("locales/" + l + ".json")
		if err != nil {
			panic(fmt.Sprintf("email: read locale %s: %v", l, err))
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			panic(fmt.Sprintf("email: parse locale %s: %v", l, err))
		}
		out[l] = m
	}
	return out
}

// ParseLocale maps a stored language value (for example "vi", "vi-VN", "VI")
// to a supported locale; ok is false for an empty or unsupported value.
func ParseLocale(s string) (locale string, ok bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexAny(s, "-_"); i >= 0 {
		s = s[:i]
	}
	_, ok = catalog[s]
	return s, ok
}

// NormalizeLocale is ParseLocale with DefaultLocale for anything unsupported.
func NormalizeLocale(s string) string {
	if l, ok := ParseLocale(s); ok {
		return l
	}
	return DefaultLocale
}

// Lang carries the language an e-mail renders in. Every template data struct
// embeds it; an empty value renders in DefaultLocale.
type Lang struct {
	Locale string
}

// LocaleCode returns the normalized locale.
func (l Lang) LocaleCode() string { return NormalizeLocale(l.Locale) }

// localeCarrier is implemented by every template data struct through Lang.
type localeCarrier interface{ LocaleCode() string }

// lookup returns the catalog string for key in locale, falling back to the
// default locale, then to the key itself (a missing key is a bug the catalog
// test catches).
func lookup(locale, key string) string {
	if s, ok := catalog[NormalizeLocale(locale)][key]; ok {
		return s
	}
	if s, ok := catalog[DefaultLocale][key]; ok {
		return s
	}
	return key
}

// fill replaces {0}, {1}, ... in one pass, so a value that itself contains a
// placeholder is never expanded again.
func fill(s string, args []string) string {
	if len(args) == 0 {
		return s
	}
	pairs := make([]string, 0, len(args)*2)
	for i, a := range args {
		pairs = append(pairs, fmt.Sprintf("{%d}", i), a)
	}
	return strings.NewReplacer(pairs...).Replace(s)
}

func stringArgs(args []any) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = fmt.Sprint(a)
	}
	return out
}

// Text renders a plain-text catalog string (subjects, notice messages). The
// values are inserted verbatim; callers that put the result in HTML must
// escape it (the template engine does).
func Text(locale, key string, args ...any) string {
	return fill(lookup(locale, key), stringArgs(args))
}

// TextHTML renders a catalog string that carries inline markup. The catalog
// part is trusted; every value is HTML-escaped.
func TextHTML(locale, key string, args ...any) template.HTML {
	esc := stringArgs(args)
	for i := range esc {
		esc[i] = html.EscapeString(esc[i])
	}
	return template.HTML(fill(lookup(locale, key), esc)) // #nosec G203 -- catalog is trusted, values escaped above
}

// FormatDuration renders a validity period ("2 days", "24 giờ").
func FormatDuration(locale string, d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		days := int(d.Hours() / 24)
		if days == 1 {
			return Text(locale, "duration.day")
		}
		return Text(locale, "duration.days", days)
	case d >= time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return Text(locale, "duration.hour")
		}
		return Text(locale, "duration.hours", h)
	case d >= time.Minute:
		m := int(d.Minutes())
		if m == 1 {
			return Text(locale, "duration.minute")
		}
		return Text(locale, "duration.minutes", m)
	}
	return d.String()
}

// FormatTime renders a moment with its zone in the locale's usual order.
func FormatTime(locale string, t time.Time) string {
	if NormalizeLocale(locale) == LocaleVI {
		return t.Format("15:04, 02/01/2006 MST")
	}
	return t.Format("January 2, 2006 at 3:04 PM MST")
}

// FormatDate renders a calendar date in the locale's usual order.
func FormatDate(locale string, t time.Time) string {
	if NormalizeLocale(locale) == LocaleVI {
		return t.Format("02/01/2006")
	}
	return t.Format("January 2, 2006")
}

// FooterHTMLFor is Branding.FooterHTML with the "Powered by" credit in the
// locale.
func (b Branding) FooterHTMLFor(locale string) template.HTML {
	return b.footer(locale)
}

// templateFuncs are available to every body template.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"lang": NormalizeLocale,
		"t":    Text,
		"th":   TextHTML,
		"footer": func(locale string, b Branding) template.HTML {
			return b.footer(locale)
		},
	}
}
