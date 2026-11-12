package contentrule

import (
	"bytes"
	"context"
	"crypto/sha256"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Scopes of a rule's origin.
const (
	ScopePlatform     = "platform"
	ScopeOrganization = "organization"
)

// OrgRulePrefix opens the id of an organization rule wherever it is shown,
// so it never collides with a platform rule id.
const OrgRulePrefix = "org."

// Origin is where a rule came from: a platform pack (name, version, digest)
// or the organization's own rules.
type Origin struct {
	Scope   string
	Pack    string
	Version string
	Digest  string
}

// Source is the technology source name of a rule-derived detection.
func (o Origin) Source() string {
	if o.Scope == ScopeOrganization {
		return "rules:organization"
	}
	return "rules:" + o.Pack + "@" + o.Version
}

// RuleSet is a set of rules of one kind from one origin.
type RuleSet struct {
	Kind   Kind
	Origin Origin
	Rules  []Rule
}

// Document caps. Bytes past a cap are not read.
const (
	MaxBodyBytes    = 1 << 20
	MaxScriptsBytes = 64 << 10
	MaxScripts      = 200
	MaxFieldBytes   = 2048
	MaxCookies      = 20
	MaxHeaders      = 32
	// windowRadius is how far around a keyword hit a body pattern reads.
	windowRadius = 256
	// maxHitsPerKeyword bounds the hits of one keyword in one document.
	maxHitsPerKeyword = 64
)

// Budget bounds the work of one document scan.
type Budget struct {
	MaxRegexRuns int
	MaxMatches   int
	Timeout      time.Duration
}

// DefaultBudget is the budget of one document.
var DefaultBudget = Budget{MaxRegexRuns: 2000, MaxMatches: 50, Timeout: 100 * time.Millisecond} //nolint:gochecknoglobals // read-only defaults

// Document is one web response, as the platform received it. Header names
// are lower case. Every field is hostile input; Scan caps each.
type Document struct {
	URL      string
	Title    string
	Headers  map[string]string
	Cookies  []string
	Favicon  string
	Body     []byte
	Scripts  []string
	FinalURL string
}

// TechMatch is a technology a fingerprint rule detected.
type TechMatch struct {
	RuleID     string
	Origin     Origin
	Name       string
	Version    string
	Category   string
	CPE        string
	Confidence int
}

// SecretMatch is a secret a secret rule found, masked: the value itself
// never leaves Scan.
type SecretMatch struct {
	RuleID   string
	RuleName string
	Origin   Origin
	Category string
	Severity string
	// Field is the location read ("body", "header:x-debug", ...).
	Field string
	// Line and Column (1-based, bytes) locate the value in the field.
	Line   int
	Column int
	// Fingerprint is a keyed hash of the value ("" without a key).
	Fingerprint string
	// Preview shows at most 4 characters at each end.
	Preview string
	Length  int
}

// Result is what one scan found.
type Result struct {
	Technologies []TechMatch
	Secrets      []SecretMatch
	// Truncated: a field was longer than its cap and only its start was read.
	Truncated bool
	// Stopped names the budget that stopped the scan ("" = finished).
	Stopped string
}

// Fingerprinter turns a secret value into its keyed fingerprint; nil or ""
// means no fingerprint is kept.
type Fingerprinter func(value string) string

type compiledRule struct {
	kind       Kind
	id         string
	name       string
	origin     Origin
	all        bool
	tech       *Technology
	confidence int
	secret     *Secret
	matchers   []*compiledMatcher
}

type compiledMatcher struct {
	rule     *compiledRule
	index    int
	loc      Location
	header   string
	keywords []string
	re       *regexp.Regexp
	version  int
	secret   int
	hashes   map[string]bool
}

// Engine is a compiled set of rules. It is safe for concurrent use.
type Engine struct {
	rules  []*compiledRule
	byLoc  map[Location][]*compiledMatcher
	bodyIx *keywordIndex
	scrIx  *keywordIndex
	sets   []RuleSet
}

// Compile validates and compiles rule sets into one engine. A rule that
// fails validation is skipped and reported; one bad rule never disables
// the others.
func Compile(sets []RuleSet) (*Engine, []error) {
	e := &Engine{byLoc: map[Location][]*compiledMatcher{}, sets: sets}
	var errs []error
	seen := map[string]bool{}
	for _, set := range sets {
		for i := range set.Rules {
			r := set.Rules[i]
			if err := r.Validate(set.Kind); err != nil {
				errs = append(errs, err)
				continue
			}
			id := r.ID
			if set.Origin.Scope == ScopeOrganization {
				id = OrgRulePrefix + id
			}
			key := string(set.Kind) + "\x00" + id
			if seen[key] {
				continue // the first set that names a rule id wins
			}
			seen[key] = true
			cr := &compiledRule{
				kind: set.Kind, id: id, name: r.Name, origin: set.Origin, all: r.Condition == ConditionAll,
				tech: r.Technology, confidence: r.Confidence, secret: r.Secret,
			}
			if cr.confidence == 0 {
				cr.confidence = DefaultConfidence
			}
			for j := range r.Matchers {
				cr.matchers = append(cr.matchers, compileMatcher(cr, j, &r.Matchers[j]))
			}
			e.rules = append(e.rules, cr)
			for _, m := range cr.matchers {
				e.byLoc[m.loc] = append(e.byLoc[m.loc], m)
			}
		}
	}
	e.bodyIx = newKeywordIndex(e.byLoc[LocBody])
	e.scrIx = newKeywordIndex(e.byLoc[LocScript])
	return e, errs
}

func compileMatcher(r *compiledRule, i int, m *Matcher) *compiledMatcher {
	cm := &compiledMatcher{rule: r, index: i, loc: m.Location, header: m.Header, version: -1, secret: -1}
	for _, k := range m.Keywords {
		cm.keywords = append(cm.keywords, strings.ToLower(k))
	}
	if m.Pattern != "" {
		cm.re = regexp.MustCompile(m.Pattern) // checked by Validate
		cm.version = cm.re.SubexpIndex(GroupVersion)
		cm.secret = cm.re.SubexpIndex(GroupSecret)
	}
	if len(m.Hashes) > 0 {
		cm.hashes = map[string]bool{}
		for _, h := range m.Hashes {
			cm.hashes[h] = true
		}
	}
	return cm
}

// Rules is the number of compiled rules.
func (e *Engine) Rules() int {
	if e == nil {
		return 0
	}
	return len(e.rules)
}

// Sets are the rule sets the engine was compiled from.
func (e *Engine) Sets() []RuleSet {
	if e == nil {
		return nil
	}
	return e.sets
}

// HasKind reports whether the engine holds a rule of kind k.
func (e *Engine) HasKind(k Kind) bool {
	if e == nil {
		return false
	}
	for _, r := range e.rules {
		if r.kind == k {
			return true
		}
	}
	return false
}

// scan is the state of one document scan.
type scan struct {
	ctx      context.Context
	budget   Budget
	deadline time.Time
	runs     int
	fp       Fingerprinter
	res      *Result
	// fingerprint rules: matched matchers and the version found.
	hit     map[*compiledRule]map[int]bool
	version map[*compiledRule]string
	// secret dedup by rule and value hash (kept in memory only).
	secretSeen map[string]bool
	matches    int
}

func (s *scan) stop(reason string) bool {
	if s.res.Stopped == "" {
		s.res.Stopped = reason
	}
	return true
}

// over reports whether a budget is spent.
func (s *scan) over() bool {
	if s.res.Stopped != "" {
		return true
	}
	if s.ctx.Err() != nil {
		return s.stop("canceled")
	}
	if s.runs >= s.budget.MaxRegexRuns {
		return s.stop("regex_runs")
	}
	if s.matches >= s.budget.MaxMatches {
		return s.stop("matches")
	}
	if time.Now().After(s.deadline) {
		return s.stop("time")
	}
	return false
}

// Scan runs the engine on one document. fp keys secret fingerprints (nil:
// no fingerprint). The returned secrets hold no value.
func (e *Engine) Scan(ctx context.Context, doc Document, budget Budget, fp Fingerprinter) Result {
	res := Result{}
	if e == nil || len(e.rules) == 0 {
		return res
	}
	if budget.MaxRegexRuns <= 0 {
		budget = DefaultBudget
	}
	s := &scan{
		ctx: ctx, budget: budget, deadline: time.Now().Add(budget.Timeout), fp: fp, res: &res,
		hit: map[*compiledRule]map[int]bool{}, version: map[*compiledRule]string{}, secretSeen: map[string]bool{},
	}
	body := doc.Body
	if len(body) > MaxBodyBytes {
		body, res.Truncated = body[:MaxBodyBytes], true
	}
	s.fields(e, doc)
	if len(body) > 0 {
		s.text(e.bodyIx, body, "body")
	}
	if scripts := joinScripts(doc.Scripts, &res.Truncated); len(scripts) > 0 {
		s.text(e.scrIx, scripts, "script")
	}
	s.finishTechnologies(e)
	return res
}

// fields scans the short fields: url, title, headers, cookies, favicon.
func (s *scan) fields(e *Engine, doc Document) {
	for _, u := range []string{doc.URL, doc.FinalURL} {
		if u != "" {
			s.field(e.byLoc[LocURL], capField(u, &s.res.Truncated), "url")
		}
		if doc.FinalURL == doc.URL {
			break
		}
	}
	if doc.Title != "" {
		s.field(e.byLoc[LocTitle], capField(doc.Title, &s.res.Truncated), "title")
	}
	if len(doc.Headers) > 0 {
		byHeader := map[string][]*compiledMatcher{}
		for _, m := range e.byLoc[LocHeader] {
			byHeader[m.header] = append(byHeader[m.header], m)
		}
		names := make([]string, 0, len(doc.Headers))
		for n := range doc.Headers {
			names = append(names, n)
		}
		sort.Strings(names)
		for i, n := range names {
			if i >= MaxHeaders {
				s.res.Truncated = true
				break
			}
			if ms := byHeader[strings.ToLower(n)]; len(ms) > 0 {
				s.field(ms, capField(doc.Headers[n], &s.res.Truncated), "header:"+strings.ToLower(n))
			}
		}
	}
	for i, c := range doc.Cookies {
		if i >= MaxCookies {
			s.res.Truncated = true
			break
		}
		s.field(e.byLoc[LocCookie], capField(c, &s.res.Truncated), "cookie")
	}
	if f := strings.TrimSpace(doc.Favicon); f != "" {
		for _, m := range e.byLoc[LocFavicon] {
			if m.hashes[f] {
				s.matched(m, "")
			}
		}
	}
}

// field runs matchers on one short field.
func (s *scan) field(ms []*compiledMatcher, value, field string) {
	if len(ms) == 0 || value == "" {
		return
	}
	lower := strings.ToLower(value)
	for _, m := range ms {
		if s.over() {
			return
		}
		if len(m.keywords) > 0 && !containsAny(lower, m.keywords) {
			continue
		}
		if m.re == nil {
			s.matched(m, "")
			continue
		}
		s.runs++
		s.apply(m, []byte(value), 0, field, nil)
	}
}

// text runs the keyword-indexed matchers of a long text (body, scripts).
func (s *scan) text(ix *keywordIndex, data []byte, field string) {
	if ix == nil || len(ix.keywords) == 0 {
		return
	}
	// ASCII case folding keeps offsets aligned with data.
	lower := asciiLower(data)
	var lines *lineIndex
	done := map[*compiledMatcher]int{} // end of the last window read
	ix.walk(lower, func(kw, pos int) bool {
		if s.over() {
			return false
		}
		for _, m := range ix.matchers[kw] {
			if m.re == nil {
				s.matched(m, "")
				continue
			}
			if m.rule.kind == KindFingerprint && s.ruleDone(m) {
				continue
			}
			if end, ok := done[m]; ok && pos+len(ix.keywords[kw]) <= end-windowRadius {
				continue // this hit lies inside a window already read
			}
			from := max(0, pos-windowRadius)
			to := min(len(data), pos+len(ix.keywords[kw])+windowRadius)
			done[m] = to
			s.runs++
			if lines == nil && m.rule.kind == KindSecret {
				lines = newLineIndex(data)
			}
			s.apply(m, data[from:to], from, field, lines)
			if s.over() {
				return false
			}
		}
		return true
	})
}

// ruleDone reports whether a fingerprint rule needs no more evidence from m.
func (s *scan) ruleDone(m *compiledMatcher) bool {
	if !s.hit[m.rule][m.index] {
		return false
	}
	return m.version < 0 || s.version[m.rule] != ""
}

// apply runs m's pattern on window (which starts at offset in its field).
func (s *scan) apply(m *compiledMatcher, window []byte, offset int, field string, lines *lineIndex) {
	if m.rule.kind == KindFingerprint {
		loc := m.re.FindSubmatchIndex(window)
		if loc == nil {
			return
		}
		version := ""
		if m.version >= 0 && loc[2*m.version] >= 0 {
			version = string(window[loc[2*m.version]:loc[2*m.version+1]])
		}
		s.matched(m, version)
		return
	}
	for _, loc := range m.re.FindAllSubmatchIndex(window, 8) {
		start, end := loc[0], loc[1]
		if m.secret >= 0 && loc[2*m.secret] >= 0 {
			start, end = loc[2*m.secret], loc[2*m.secret+1]
		}
		if end <= start {
			continue
		}
		s.secretFound(m, window[start:end], offset+start, field, lines)
		if s.matches >= s.budget.MaxMatches {
			return
		}
	}
}

// matched records that a fingerprint matcher matched (secret matchers
// always have a pattern and go through secretFound).
func (s *scan) matched(m *compiledMatcher, version string) {
	if m.rule.kind != KindFingerprint {
		return
	}
	set := s.hit[m.rule]
	if set == nil {
		set = map[int]bool{}
		s.hit[m.rule] = set
	}
	set[m.index] = true
	if v := assettech.CleanVersion(version); v != "" && s.version[m.rule] == "" {
		s.version[m.rule] = v
	}
}

func (s *scan) secretFound(m *compiledMatcher, raw []byte, offset int, field string, lines *lineIndex) {
	value := strings.ToValidUTF8(string(raw), "�")
	sum := sha256.Sum256([]byte(m.rule.id + "\x00" + value))
	key := string(sum[:])
	if s.secretSeen[key] {
		return
	}
	s.secretSeen[key] = true
	line, col := 1, offset+1
	if lines != nil {
		line, col = lines.at(offset)
	}
	sm := SecretMatch{
		RuleID: m.rule.id, RuleName: m.rule.name, Origin: m.rule.origin,
		Category: m.rule.secret.Category, Severity: m.rule.secret.Severity,
		Field: field, Line: line, Column: col,
		Preview: vulnerability.MaskSecretPreviewOf(value, utf8.RuneCountInString(value)),
		Length:  utf8.RuneCountInString(value),
	}
	if s.fp != nil {
		sm.Fingerprint = s.fp(value)
	}
	s.res.Secrets = append(s.res.Secrets, sm)
	s.matches++
}

// finishTechnologies turns matched fingerprint rules into technologies.
func (s *scan) finishTechnologies(e *Engine) {
	for _, r := range e.rules {
		set := s.hit[r]
		if r.kind != KindFingerprint || len(set) == 0 || (r.all && len(set) < len(r.matchers)) {
			continue
		}
		v := s.version[r]
		t := TechMatch{
			RuleID: r.id, Origin: r.origin, Name: r.tech.Name, Version: v,
			Category: r.tech.Category, Confidence: r.confidence, CPE: FillCPE(r.tech.CPE, v),
		}
		s.res.Technologies = append(s.res.Technologies, t)
	}
}

// FillCPE puts version into a CPE template ("*" when unknown). A version
// with characters a CPE part cannot hold leaves the version "*".
func FillCPE(template, version string) string {
	if template == "" {
		return ""
	}
	v := strings.ToLower(version)
	if v == "" || strings.ContainsAny(v, ":* \t") {
		v = "*"
	}
	return strings.ReplaceAll(strings.ToLower(template), "{version}", v)
}

func containsAny(s string, kws []string) bool {
	for _, k := range kws {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func capField(s string, truncated *bool) string {
	if len(s) > MaxFieldBytes {
		*truncated = true
		return s[:MaxFieldBytes]
	}
	return s
}

func joinScripts(scripts []string, truncated *bool) []byte {
	var b bytes.Buffer
	for i, sc := range scripts {
		if i >= MaxScripts || b.Len()+len(sc)+1 > MaxScriptsBytes {
			*truncated = true
			break
		}
		b.WriteString(capField(sc, truncated))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// lineIndex maps byte offsets to 1-based line and column.
type lineIndex struct{ starts []int }

func newLineIndex(data []byte) *lineIndex {
	li := &lineIndex{starts: []int{0}}
	for i, c := range data {
		if c == '\n' {
			li.starts = append(li.starts, i+1)
		}
	}
	return li
}

func (li *lineIndex) at(off int) (int, int) {
	i := sort.Search(len(li.starts), func(i int) bool { return li.starts[i] > off }) - 1
	return i + 1, off - li.starts[i] + 1
}
