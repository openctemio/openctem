// Package notifymsg is the message model of channel notifications (Slack,
// Teams, Telegram, e-mail, webhook, Splunk): one Card per delivery, built
// from an event and the channel's detail level, optionally laid out by the
// channel's template, then rendered by each provider client.
//
// Design: docs/architecture/notification-system.md, "Channel messages".
package notifymsg

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Locales the catalog has. Anything else renders in DefaultLocale.
const (
	LocaleEN      = "en"
	LocaleVI      = "vi"
	DefaultLocale = LocaleEN
)

//go:embed locales/*.json
var localeFS embed.FS

// catalog is trusted text compiled into the binary, keyed by locale then
// key. Values carry no markup: every renderer escapes them like any value.
var catalog = mustLoadCatalog()

func mustLoadCatalog() map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, l := range Locales() {
		raw, err := localeFS.ReadFile("locales/" + l + ".json")
		if err != nil {
			panic(fmt.Sprintf("notifymsg: read locale %s: %v", l, err))
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			panic(fmt.Sprintf("notifymsg: parse locale %s: %v", l, err))
		}
		out[l] = m
	}
	return out
}

// Locales lists the supported locales.
func Locales() []string { return []string{LocaleEN, LocaleVI} }

// NormalizeLocale maps a stored language value ("vi", "vi-VN", "VI") to a
// supported locale, DefaultLocale for anything else.
func NormalizeLocale(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexAny(s, "-_"); i >= 0 {
		s = s[:i]
	}
	if _, ok := catalog[s]; ok {
		return s
	}
	return DefaultLocale
}

// text returns the catalog string of key in locale, falling back to the
// default locale; ok is false when neither has it.
func text(locale, key string) (string, bool) {
	if v, ok := catalog[NormalizeLocale(locale)][key]; ok {
		return v, true
	}
	v, ok := catalog[DefaultLocale][key]
	return v, ok
}

// T is text with the key itself as the last fallback, and {0}, {1}, ...
// replaced by args in one pass: an argument (an asset name) is never scanned
// for placeholders itself.
func T(locale, key string, arg ...string) string {
	v, ok := text(locale, key)
	if !ok {
		v = key
	}
	if len(arg) == 0 {
		return v
	}
	return placeholderRE.ReplaceAllStringFunc(v, func(m string) string {
		i, err := strconv.Atoi(m[1 : len(m)-1])
		if err != nil || i >= len(arg) {
			return m
		}
		return arg[i]
	})
}

var placeholderRE = regexp.MustCompile(`\{[0-9]\}`)

// SeverityWord is the localized name of a severity ("High", "Cao").
func SeverityWord(locale, severity string) string {
	if v, ok := text(locale, "severity."+strings.ToLower(severity)); ok {
		return v
	}
	return T(locale, "severity.info")
}

// Headline is the localized name of an event type ("New exposure"); an
// unknown type is humanized ("some_event" becomes "Some event").
func Headline(locale, eventType string) string {
	if v, ok := text(locale, "event."+eventType); ok {
		return v
	}
	return humanize(eventType)
}

// ClassLabel is the localized name of an exposure class; unknown classes
// are humanized.
func ClassLabel(locale, class string) string {
	if class == "" {
		return ""
	}
	if v, ok := text(locale, "class."+class); ok {
		return v
	}
	return strings.ToLower(humanize(class))
}

func humanize(s string) string {
	s = strings.NewReplacer("_", " ", ".", " ").Replace(strings.TrimSpace(s))
	if s == "" {
		return "Notification"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
