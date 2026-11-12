package pagemon

import (
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Kind is what a fetched URL is.
type Kind string

// Kinds.
const (
	KindHTML   Kind = "html"
	KindScript Kind = "script"
	KindOther  Kind = "other"
)

// Snapshot is the normalized form of one fetch that changed something.
type Snapshot struct {
	ID          shared.ID   `json:"id"`
	FetchedAt   time.Time   `json:"fetched_at"`
	StatusCode  int         `json:"status_code"`
	ContentType string      `json:"content_type,omitempty"`
	FinalURL    string      `json:"final_url,omitempty"`
	Size        int64       `json:"size"`
	BodySHA256  string      `json:"body_sha256,omitempty"`
	ContentHash string      `json:"content_hash"`
	Kind        Kind        `json:"kind"`
	Truncated   bool        `json:"truncated,omitempty"`
	Scripts     []ScriptRef `json:"scripts"`
	URLs        []string    `json:"urls"`
	Text        []string    `json:"-"`
	Tool        string      `json:"tool,omitempty"`
}

// KindOf classifies a capture by content type, then by path.
func KindOf(contentType, rawURL string) Kind {
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript"):
		return KindScript
	case strings.Contains(ct, "html"):
		return KindHTML
	}
	if u, err := url.Parse(rawURL); err == nil {
		p := strings.ToLower(u.Path)
		if strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs") {
			return KindScript
		}
		if ct == "" && (strings.HasSuffix(p, "/") || strings.HasSuffix(p, ".html") || strings.HasSuffix(p, ".htm")) {
			return KindHTML
		}
	}
	return KindOther
}

// FirstParty decides whether a script host is the organization's: the page
// host, a host of the same registrable domain, or a host known reports true for.
func FirstParty(pageHost, host string, known func(string) bool) bool {
	pageHost, host = strings.ToLower(pageHost), strings.ToLower(host)
	if host == pageHost {
		return true
	}
	a, err1 := publicsuffix.EffectiveTLDPlusOne(pageHost)
	b, err2 := publicsuffix.EffectiveTLDPlusOne(host)
	if err1 == nil && err2 == nil && a == b {
		return true
	}
	return known != nil && known(host)
}

// ScriptHosts returns the hosts of a page body's external scripts (for the
// known-host lookup before Build).
func ScriptHosts(c Capture) []string {
	if KindOf(c.ContentType, c.URL) != KindHTML {
		return nil
	}
	page, err := url.Parse(c.URL)
	if err != nil {
		return nil
	}
	scripts, _ := ParseHTML(c.Body, page, false)
	set := map[string]bool{}
	for _, s := range scripts {
		if s.Host != "" {
			set[s.Host] = true
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	slices.Sort(out)
	return out
}

// Build normalizes a successful capture for a watch. known reports hosts the
// organization owns (domain and subdomain assets).
func Build(c Capture, w Watch, known func(string) bool) Snapshot {
	s := Snapshot{
		FetchedAt: c.FetchedAt, StatusCode: c.StatusCode, ContentType: c.ContentType, FinalURL: c.FinalURL,
		Size: c.Size, BodySHA256: c.SHA256, Truncated: c.Truncated || c.BodyTruncated, Tool: c.Tool,
		Kind: KindOf(c.ContentType, c.URL), Scripts: []ScriptRef{}, URLs: []string{},
	}
	if s.BodySHA256 == "" && c.Body != "" {
		s.BodySHA256 = sha(c.Body)
	}
	if s.Size == 0 {
		s.Size = int64(len(c.Body))
	}
	res := compilePatterns(w.IgnorePatterns)
	switch s.Kind {
	case KindHTML:
		base := c.URL
		if c.FinalURL != "" {
			base = c.FinalURL
		}
		page, err := url.Parse(base)
		if err != nil {
			break
		}
		scripts, lines := ParseHTML(c.Body, page, w.Mode == ModeFull)
		for _, sc := range scripts {
			if ignored(res, sc.ID) || (sc.Src != "" && ignored(res, sc.Src)) {
				continue
			}
			if !sc.Inline {
				sc.ThirdParty = !FirstParty(page.Hostname(), sc.Host, known)
			}
			s.Scripts = append(s.Scripts, sc)
		}
		for _, l := range lines {
			if !ignored(res, l) {
				s.Text = append(s.Text, evidence.RedactText(l))
			}
		}
	case KindScript:
		for _, u := range ExtractURLs(c.Body) {
			if !ignored(res, u) {
				s.URLs = append(s.URLs, u)
			}
		}
	}
	s.ContentHash = s.hash()
	return s
}

// hash is the content hash diffs compare.
func (s Snapshot) hash() string {
	switch s.Kind {
	case KindHTML:
		parts := make([]string, 0, len(s.Scripts)+len(s.Text))
		for _, sc := range s.Scripts {
			parts = append(parts, "script "+sc.ID)
		}
		slices.Sort(parts)
		parts = append(parts, s.Text...)
		return sha("html\n" + strings.Join(parts, "\n"))
	default:
		return sha(string(s.Kind) + "\n" + s.BodySHA256)
	}
}

// Severity of a change.
type Severity string

// Severities, lowest first.
const (
	SeverityInfo   Severity = "info"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

func (s Severity) rank() int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	}
	return 0
}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { return s == SeverityInfo || s.rank() > 0 }

// AtLeast reports whether s ranks at least as high as o.
func (s Severity) AtLeast(o Severity) bool { return s.rank() >= o.rank() }

func maxSev(a, b Severity) Severity {
	if b.rank() > a.rank() {
		return b
	}
	return a
}

// Diff caps.
const (
	MaxDiffItems = 100
	MaxDiffLines = 200
)

// Diff is what changed between two snapshots of one watch.
type Diff struct {
	Kind           Kind        `json:"kind"`
	ScriptsAdded   []ScriptRef `json:"scripts_added,omitempty"`
	ScriptsRemoved []ScriptRef `json:"scripts_removed,omitempty"`
	// NewThirdPartyHosts are third-party script hosts the page did not
	// load before.
	NewThirdPartyHosts  []string `json:"new_third_party_hosts,omitempty"`
	GoneThirdPartyHosts []string `json:"gone_third_party_hosts,omitempty"`
	HashFrom            string   `json:"hash_from,omitempty"`
	HashTo              string   `json:"hash_to,omitempty"`
	SizeFrom            int64    `json:"size_from"`
	SizeTo              int64    `json:"size_to"`
	StatusFrom          int      `json:"status_from,omitempty"`
	StatusTo            int      `json:"status_to,omitempty"`
	URLsAdded           []string `json:"urls_added,omitempty"`
	URLsRemoved         []string `json:"urls_removed,omitempty"`
	LinesAdded          []string `json:"lines_added,omitempty"`
	LinesRemoved        []string `json:"lines_removed,omitempty"`
	// Truncated: a list above was cut at its cap.
	Truncated bool `json:"truncated,omitempty"`
}

// Summary is the change's counts (list views).
type Summary struct {
	ScriptsAdded       int  `json:"scripts_added"`
	ScriptsRemoved     int  `json:"scripts_removed"`
	ThirdPartyAdded    int  `json:"third_party_added"`
	NewThirdPartyHosts int  `json:"new_third_party_hosts"`
	ContentChanged     bool `json:"content_changed"`
	URLsAdded          int  `json:"urls_added"`
	URLsRemoved        int  `json:"urls_removed"`
	LinesAdded         int  `json:"lines_added"`
	LinesRemoved       int  `json:"lines_removed"`
}

// Compare diffs two snapshots of a watch and rates the change (see the
// severity rules of the design).
func Compare(prev, next Snapshot) (Diff, Summary, Severity) {
	d := Diff{Kind: next.Kind, SizeFrom: prev.Size, SizeTo: next.Size, StatusFrom: prev.StatusCode, StatusTo: next.StatusCode}
	var sum Summary
	sev := SeverityInfo
	if prev.Kind != KindHTML || next.Kind != KindHTML {
		if prev.BodySHA256 != next.BodySHA256 {
			d.HashFrom, d.HashTo = prev.BodySHA256, next.BodySHA256
			sum.ContentChanged = true
			if next.Kind == KindScript {
				sev = maxSev(sev, SeverityLow)
			}
		}
	}
	// Scripts (pages).
	prevIDs := map[string]ScriptRef{}
	prevHosts := map[string]bool{}
	for _, sc := range prev.Scripts {
		prevIDs[sc.ID] = sc
		if sc.ThirdParty {
			prevHosts[sc.Host] = true
		}
	}
	nextIDs := map[string]bool{}
	nextHosts := map[string]bool{}
	newHosts := map[string]bool{}
	for _, sc := range next.Scripts {
		nextIDs[sc.ID] = true
		if sc.ThirdParty {
			nextHosts[sc.Host] = true
		}
		if _, ok := prevIDs[sc.ID]; ok {
			continue
		}
		sum.ScriptsAdded++
		switch {
		case sc.ThirdParty && !prevHosts[sc.Host]:
			sum.ThirdPartyAdded++
			newHosts[sc.Host] = true
			sev = maxSev(sev, SeverityHigh)
		case sc.ThirdParty:
			sum.ThirdPartyAdded++
			sev = maxSev(sev, SeverityMedium)
		}
		if len(d.ScriptsAdded) < MaxDiffItems {
			d.ScriptsAdded = append(d.ScriptsAdded, sc)
		} else {
			d.Truncated = true
		}
	}
	for _, sc := range prev.Scripts {
		if nextIDs[sc.ID] {
			continue
		}
		sum.ScriptsRemoved++
		if len(d.ScriptsRemoved) < MaxDiffItems {
			d.ScriptsRemoved = append(d.ScriptsRemoved, sc)
		} else {
			d.Truncated = true
		}
	}
	for h := range prevHosts {
		if !nextHosts[h] {
			d.GoneThirdPartyHosts = append(d.GoneThirdPartyHosts, h)
		}
	}
	for h := range newHosts {
		d.NewThirdPartyHosts = append(d.NewThirdPartyHosts, h)
	}
	slices.Sort(d.NewThirdPartyHosts)
	slices.Sort(d.GoneThirdPartyHosts)
	sum.NewThirdPartyHosts = len(d.NewThirdPartyHosts)
	// URLs (scripts).
	var cut bool
	d.URLsAdded, sum.URLsAdded, cut = setDiff(next.URLs, prev.URLs, MaxDiffItems)
	d.Truncated = d.Truncated || cut
	d.URLsRemoved, sum.URLsRemoved, cut = setDiff(prev.URLs, next.URLs, MaxDiffItems)
	d.Truncated = d.Truncated || cut
	if sum.URLsAdded > 0 {
		sev = maxSev(sev, SeverityLow)
	}
	// Text (full mode).
	d.LinesAdded, sum.LinesAdded, cut = setDiff(next.Text, prev.Text, MaxDiffLines)
	d.Truncated = d.Truncated || cut
	d.LinesRemoved, sum.LinesRemoved, cut = setDiff(prev.Text, next.Text, MaxDiffLines)
	d.Truncated = d.Truncated || cut
	return d, sum, sev
}

// setDiff returns the items of a not in b (in a's order, as a multiset so a
// repeated line counts), at most limit of them, the full count, and whether
// it was cut.
func setDiff(a, b []string, limit int) ([]string, int, bool) {
	inB := make(map[string]int, len(b))
	for _, s := range b {
		inB[s]++
	}
	var out []string
	n := 0
	for _, s := range a {
		if inB[s] > 0 {
			inB[s]--
			continue
		}
		n++
		if len(out) < limit {
			out = append(out, s)
		}
	}
	return out, n, n > len(out)
}

// DerivedScripts returns the first-party external scripts of a page
// snapshot, at most MaxDerivedPerPage, by identity.
func DerivedScripts(s Snapshot) []ScriptRef {
	out := make([]ScriptRef, 0, MaxDerivedPerPage)
	for _, sc := range s.Scripts {
		if sc.Inline || sc.ThirdParty || sc.Src == "" {
			continue
		}
		if len(out) == MaxDerivedPerPage {
			break
		}
		out = append(out, sc)
	}
	return out
}
