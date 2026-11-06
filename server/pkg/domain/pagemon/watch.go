// Package pagemon is web page monitoring: what a watched page loads (its
// scripts) and, optionally, what it says (its visible text), what each of its
// own scripts contains, and what changed between two fetches.
// Design: docs/rfcs/RFC-138-web-page-monitoring.md.
//
// Everything a fetch returns is hostile input: the target chose it. Nothing
// here executes or renders it. HTML is read with a tokenizer, patterns are
// RE2 (linear time), every list and string is capped, and stored text is
// masked like finding evidence.
package pagemon

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Capability is the stage capability that fetches watched URLs.
const Capability = "monitor.web_content"

// Mode is what a watch keeps of a page.
type Mode string

// Modes.
const (
	// ModeJS keeps the scripts a page loads (default).
	ModeJS Mode = "js"
	// ModeFull also keeps the page's normalized visible text.
	ModeFull Mode = "full"
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool { return m == ModeJS || m == ModeFull }

// Source is how a watch was added.
type Source string

// Sources.
const (
	SourceManual    Source = "manual"
	SourceSuggested Source = "suggested"
	// SourceDerived: a first-party script of a JS-mode page, added and
	// removed by the platform.
	SourceDerived Source = "derived"
)

// Valid reports whether s is a source a person may set.
func (s Source) Valid() bool { return s == SourceManual || s == SourceSuggested }

// State is a watch's last outcome.
type State string

// States.
const (
	StatePending State = "pending"
	StateOK      State = "ok"
	StateFailed  State = "failed"
	StateBlocked State = "blocked"
	// StateWaiting: no sensor can run the capability yet.
	StateWaiting State = "waiting"
)

// Limits.
const (
	MaxWatchesPerTenant   = 200
	MaxDerivedPerPage     = 25
	MaxURLBytes           = 2048
	MaxIgnorePatterns     = 10
	MaxIgnorePatternBytes = 200
	MinCadenceHours       = 6
	MaxCadenceHours       = 168
	DefaultCadenceHours   = 24
	// DynamicAfter consecutive changed fetches mark a watch dynamic.
	DynamicAfter = 3
	// SnapshotsKept per watch.
	SnapshotsKept = 5
	// ChangeRetention is how long change rows are kept.
	ChangeRetention = 180 * 24 * time.Hour
	// BlockedRetry is when a URL the gate refused is tried again.
	BlockedRetry = 6 * time.Hour
	// WaitingRetry is when a watch waiting for the capability is tried again.
	WaitingRetry = time.Hour
)

// Watch is one monitored URL.
type Watch struct {
	ID             shared.ID  `json:"id"`
	TenantID       shared.ID  `json:"-"`
	AssetID        shared.ID  `json:"asset_id"`
	AssetName      string     `json:"asset_name,omitempty"`
	ParentID       *shared.ID `json:"parent_id,omitempty"`
	URL            string     `json:"url"`
	Mode           Mode       `json:"mode"`
	Source         Source     `json:"source"`
	Enabled        bool       `json:"enabled"`
	CadenceHours   int        `json:"cadence_hours"`
	IgnorePatterns []string   `json:"ignore_patterns"`
	Dynamic        bool       `json:"dynamic"`
	ChangeStreak   int        `json:"-"`
	State          State      `json:"state"`
	LastError      string     `json:"last_error,omitempty"`
	NextDueAt      time.Time  `json:"next_due_at"`
	LastFetchedAt  *time.Time `json:"last_fetched_at,omitempty"`
	LastStatus     int        `json:"last_status,omitempty"`
	LastChangedAt  *time.Time `json:"last_changed_at,omitempty"`
	Changes        int        `json:"changes"`
	Scripts        int        `json:"scripts"`
	CreatedBy      *shared.ID `json:"-"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// NormalizeURL validates a URL to watch and returns its canonical form:
// http or https, a host, no user info, no fragment, lowercase scheme and
// host, no default port, "/" for an empty path.
func NormalizeURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > MaxURLBytes || !utf8.ValidString(s) {
		return "", fmt.Errorf("%w: a URL of at most %d bytes is required", shared.ErrValidation, MaxURLBytes)
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return "", fmt.Errorf("%w: not an absolute URL", shared.ErrValidation)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if !webScheme(u.Scheme) {
		return "", fmt.Errorf("%w: only http and https URLs can be watched", shared.ErrValidation)
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: a watched URL cannot carry user info", shared.ErrValidation)
	}
	if strings.ContainsAny(u.Host, " \t\r\n") {
		return "", fmt.Errorf("%w: invalid host", shared.ErrValidation)
	}
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "https" && strings.HasSuffix(u.Host, ":443")) || (u.Scheme == "http" && strings.HasSuffix(u.Host, ":80")) {
		u.Host = u.Host[:strings.LastIndex(u.Host, ":")]
	}
	u.Fragment, u.RawFragment = "", ""
	if u.Path == "" {
		u.Path = "/"
	}
	out := u.String()
	if len(out) > MaxURLBytes {
		return "", fmt.Errorf("%w: a URL of at most %d bytes is required", shared.ErrValidation, MaxURLBytes)
	}
	return out, nil
}

// OriginName is the stored name of the http_service asset that serves a
// normalized URL.
func OriginName(normalized string) string {
	u, err := url.Parse(normalized)
	if err != nil {
		return ""
	}
	return asset.NormalizeName(u.Scheme+"://"+u.Host, asset.AssetTypeService, "http")
}

// NormalizeCadence returns the cadence in hours (0 = the default).
func NormalizeCadence(h int) (int, error) {
	if h == 0 {
		return DefaultCadenceHours, nil
	}
	if h < MinCadenceHours || h > MaxCadenceHours {
		return 0, fmt.Errorf("%w: cadence must be %d to %d hours", shared.ErrValidation, MinCadenceHours, MaxCadenceHours)
	}
	return h, nil
}

// NormalizeIgnorePatterns validates ignore patterns (RE2, bounded) and
// returns them trimmed and deduplicated.
func NormalizeIgnorePatterns(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		if len(p) > MaxIgnorePatternBytes || !utf8.ValidString(p) {
			return nil, fmt.Errorf("%w: an ignore pattern is at most %d bytes", shared.ErrValidation, MaxIgnorePatternBytes)
		}
		if _, err := regexp.Compile(p); err != nil {
			return nil, fmt.Errorf("%w: an ignore pattern is not a valid regular expression", shared.ErrValidation)
		}
		seen[p] = true
		out = append(out, p)
	}
	if len(out) > MaxIgnorePatterns {
		return nil, fmt.Errorf("%w: at most %d ignore patterns", shared.ErrValidation, MaxIgnorePatterns)
	}
	return out, nil
}

// compilePatterns compiles stored patterns; one that no longer compiles is
// skipped (they are validated on save).
func compilePatterns(in []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(in))
	for _, p := range in {
		if re, err := regexp.Compile(p); err == nil {
			out = append(out, re)
		}
	}
	return out
}

func ignored(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}
