// Package templatefact maps the info matches of template scanners to what
// they are: facts about an asset, not vulnerabilities
// (docs/architecture/template-facts.md).
//
// A mapping file (YAML, schema 1, content pack kind template-facts) lists
// entries matched by template id, id prefix or tags. Each entry routes the
// match to one class:
//
//   - technology: an asset technology (name, version, category), so the
//     technology history and the inventory matcher see it;
//   - posture: keys of the origin's http_posture attribute (header posture
//     is an attribute, never one finding per header);
//   - surface: web surface entries (the matched path, or paths the
//     template extracted, such as the entries of robots.txt);
//   - exposure: an info exposure of the asset (panels, exposed consoles);
//   - discard: nothing is stored (personal data, noise), only counted.
//
// A match no entry names stays a generic info exposure and is counted, so a
// new template is reviewed and mapped.
//
// Everything a match carries is untrusted: the target chooses which
// matcher fires and what is extracted. Names and versions taken from a
// match are bounded single tokens; names from the pack are curated.
package templatefact

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
)

// Class is where an info match goes.
type Class string

// Classes.
const (
	ClassTechnology Class = "technology"
	ClassPosture    Class = "posture"
	ClassSurface    Class = "surface"
	ClassExposure   Class = "exposure"
	ClassDiscard    Class = "discard"
)

// IsValid reports whether c is a known class.
func (c Class) IsValid() bool {
	switch c {
	case ClassTechnology, ClassPosture, ClassSurface, ClassExposure, ClassDiscard:
		return true
	}
	return false
}

// IsFact reports whether a match of class c is stored as an asset fact (or
// dropped) instead of an exposure.
func (c Class) IsFact() bool {
	return c == ClassTechnology || c == ClassPosture || c == ClassSurface || c == ClassDiscard
}

// Limits.
const (
	MaxEntries        = 2000
	MaxNamesPerEntry  = 500
	MaxTemplates      = 200
	MaxTags           = 8
	MaxReasonLen      = 200
	MaxVersionPattern = 256
	// MaxConfidence keeps every template detection below the strong
	// evidence threshold of the technology history (research 376: probe at
	// 80 or more promotes at once): one match never displaces an
	// established version alone.
	MaxConfidence     = 79
	DefaultConfidence = 60
	// MaxPaths is the most surface paths one match adds.
	MaxPaths = 20
	// MaxExtractedLen is the longest extracted value read.
	MaxExtractedLen = 256
)

// versionFromExtracted reads the version from the extracted values (also
// the surface path_from that reads them).
const versionFromExtracted = "extracted"

// Surface sources a pack may name (CTIS endpoint sources).
var surfaceSources = []string{"probe", "robots", "sitemap"}

var (
	entryIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	templatePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	tagPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	metaKeyPattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	// tokenPattern bounds a name taken from a match (matcher name,
	// template metadata): one short token, no markup, no control
	// characters.
	tokenPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,63}$`)
	versionPattern = regexp.MustCompile(`^[0-9][0-9A-Za-z.+_-]{0,63}$`)
	// defaultVersion finds a dotted version inside an extracted value
	// ("nginx/1.25.3" gives 1.25.3).
	defaultVersion = regexp.MustCompile(`(?P<version>\d+(?:\.\d+){1,3})`)
)

// ErrInvalid is returned for a file that is not a valid mapping.
var ErrInvalid = errors.New("invalid template facts")

// File is one mapping file.
type File struct {
	Schema  int     `yaml:"schema"`
	Entries []Entry `yaml:"entries"`
}

// Entry routes the matches it selects to one class.
type Entry struct {
	ID     string `yaml:"id"`
	Match  Match  `yaml:"match"`
	Class  Class  `yaml:"class"`
	Reason string `yaml:"reason,omitempty"`

	Technology *TechSpec `yaml:"technology,omitempty"`
	// Names maps a matcher name (lower case) to the technology it means;
	// skip: true consumes the match without a technology (a generic
	// matcher that names no product).
	Names map[string]TechName `yaml:"names,omitempty"`
	// Posture maps a matcher name (lower case) to the http_posture keys
	// that matcher proves.
	Posture  map[string]map[string]any `yaml:"posture,omitempty"`
	Surface  *SurfaceSpec              `yaml:"surface,omitempty"`
	Exposure *ExposureSpec             `yaml:"exposure,omitempty"`
}

// Match selects template results. Every given part must hold.
type Match struct {
	// Templates are exact template ids.
	Templates []string `yaml:"templates,omitempty"`
	// TemplatePrefix selects ids that start with it.
	TemplatePrefix string `yaml:"template_prefix,omitempty"`
	// Tags must all be on the result.
	Tags []string `yaml:"tags,omitempty"`
	// Metadata names a template metadata key that must be present.
	Metadata string `yaml:"metadata,omitempty"`
}

// TechSpec says which technology a match proves.
type TechSpec struct {
	Name     string `yaml:"name,omitempty"`
	Category string `yaml:"category,omitempty"`
	Vendor   string `yaml:"vendor,omitempty"`
	// NameFrom takes the name from the match: "matcher" (the matcher name
	// when Names does not list it) or "metadata:<key>".
	NameFrom string `yaml:"name_from,omitempty"`
	// VersionFrom "extracted" reads the version from the extracted values.
	VersionFrom string `yaml:"version_from,omitempty"`
	// VersionPattern is an RE2 pattern with a group named version, run on
	// each extracted value.
	VersionPattern string `yaml:"version_pattern,omitempty"`
	Confidence     int    `yaml:"confidence,omitempty"`
}

// TechName is the technology one matcher name means.
type TechName struct {
	Name     string `yaml:"name,omitempty"`
	Category string `yaml:"category,omitempty"`
	Vendor   string `yaml:"vendor,omitempty"`
	Skip     bool   `yaml:"skip,omitempty"`
}

// SurfaceSpec says which web surface entries a match proves.
type SurfaceSpec struct {
	// PathFrom is "matched" (the matched URL's path) or "extracted" (each
	// extracted value that is a path or a same-origin URL).
	PathFrom string `yaml:"path_from"`
	// Source is the endpoint source: probe, robots or sitemap.
	Source string `yaml:"source"`
}

// ExposureSpec sets the exposure type of a match (default: by its tags).
type ExposureSpec struct {
	EventType string `yaml:"event_type,omitempty"`
}

// ParseFile reads and validates one mapping file.
func ParseFile(data []byte) ([]Entry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: not a template facts file (YAML with schema and entries; a key is unknown or a value has the wrong type)", ErrInvalid)
	}
	if f.Schema != 1 {
		return nil, fmt.Errorf("%w: schema must be 1", ErrInvalid)
	}
	if len(f.Entries) == 0 {
		return nil, fmt.Errorf("%w: the file holds no entries", ErrInvalid)
	}
	if len(f.Entries) > MaxEntries {
		return nil, fmt.Errorf("%w: more than %d entries", ErrInvalid, MaxEntries)
	}
	for i := range f.Entries {
		if err := f.Entries[i].Validate(); err != nil {
			return nil, fmt.Errorf("entry %d (%s): %w", i+1, f.Entries[i].ID, err)
		}
	}
	return f.Entries, nil
}

// Validate checks an entry and normalises its keys (lower-case matcher
// names). It returns every problem found, joined.
func (e *Entry) Validate() error {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	if !entryIDPattern.MatchString(e.ID) {
		add("id must be 2-64 of a-z 0-9 . _ - and start with a letter or digit")
	}
	if !e.Class.IsValid() {
		add("class must be technology, posture, surface, exposure or discard")
	}
	if !cleanText(e.Reason, MaxReasonLen) {
		add("reason must be one line of at most %d bytes", MaxReasonLen)
	}
	e.validateMatch(add)
	switch e.Class {
	case ClassTechnology:
		e.validateTechnology(add)
	case ClassPosture:
		e.validatePosture(add)
	case ClassSurface:
		e.validateSurface(add)
	case ClassExposure:
		if e.Exposure != nil && !exposureTypes[e.Exposure.EventType] && e.Exposure.EventType != "" {
			add("exposure.event_type %q is not an info exposure type", e.Exposure.EventType)
		}
	}
	if e.Class != ClassTechnology && (e.Technology != nil || len(e.Names) > 0) {
		add("technology and names belong to class technology")
	}
	if e.Class != ClassPosture && len(e.Posture) > 0 {
		add("posture belongs to class posture")
	}
	if e.Class != ClassSurface && e.Surface != nil {
		add("surface belongs to class surface")
	}
	if e.Class != ClassExposure && e.Exposure != nil {
		add("exposure belongs to class exposure")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(errs, "; "))
	}
	return nil
}

func (e *Entry) validateMatch(add func(string, ...any)) {
	m := &e.Match
	if len(m.Templates) == 0 && m.TemplatePrefix == "" && len(m.Tags) == 0 {
		add("match needs templates, template_prefix or tags")
	}
	if len(m.Templates) > MaxTemplates {
		add("at most %d templates", MaxTemplates)
	}
	for _, t := range m.Templates {
		if !templatePattern.MatchString(t) {
			add("template %q is not a template id", t)
		}
	}
	if m.TemplatePrefix != "" && (!templatePattern.MatchString(m.TemplatePrefix) || len(m.TemplatePrefix) < 3) {
		add("template_prefix %q must be a template id start of at least 3 characters", m.TemplatePrefix)
	}
	if len(m.Tags) > MaxTags {
		add("at most %d tags", MaxTags)
	}
	for _, t := range m.Tags {
		if !tagPattern.MatchString(t) {
			add("tag %q is not a tag", t)
		}
	}
	if m.Metadata != "" && !metaKeyPattern.MatchString(m.Metadata) {
		add("metadata %q is not a metadata key", m.Metadata)
	}
}

func (e *Entry) validateTechnology(add func(string, ...any)) {
	t := e.Technology
	if t == nil {
		add("class technology needs technology")
		return
	}
	switch {
	case t.NameFrom == "", t.NameFrom == "matcher":
	case strings.HasPrefix(t.NameFrom, "metadata:") && metaKeyPattern.MatchString(strings.TrimPrefix(t.NameFrom, "metadata:")):
	default:
		add("technology.name_from must be matcher or metadata:<key>")
	}
	if t.Name == "" && t.NameFrom == "" && len(e.Names) == 0 {
		add("technology needs a name, name_from or names")
	}
	if t.Name != "" && !tokenPattern.MatchString(t.Name) {
		add("technology.name %q must be one token of at most 64 characters", t.Name)
	}
	if t.Vendor != "" && !tokenPattern.MatchString(t.Vendor) {
		add("technology.vendor %q must be one token of at most 64 characters", t.Vendor)
	}
	if t.Category != "" && !assettech.Category(t.Category).IsValid() {
		add("technology.category %q is not a technology category", t.Category)
	}
	if t.Confidence < 0 || t.Confidence > MaxConfidence {
		add("technology.confidence must be 1-%d (a template detection is never strong evidence alone)", MaxConfidence)
	}
	if t.VersionFrom != "" && t.VersionFrom != versionFromExtracted {
		add("technology.version_from must be extracted")
	}
	if t.VersionPattern != "" {
		if t.VersionFrom == "" {
			add("technology.version_pattern needs version_from")
		}
		if len(t.VersionPattern) > MaxVersionPattern {
			add("technology.version_pattern is longer than %d bytes", MaxVersionPattern)
		} else if re, err := regexp.Compile(t.VersionPattern); err != nil || re.SubexpIndex("version") < 0 {
			add("technology.version_pattern must be RE2 with a group named version")
		}
	}
	e.validateNames(add)
}

// validateNames checks the matcher name table and lower-cases its keys.
func (e *Entry) validateNames(add func(string, ...any)) {
	if len(e.Names) > MaxNamesPerEntry {
		add("at most %d names", MaxNamesPerEntry)
	}
	names := make(map[string]TechName, len(e.Names))
	for k, n := range e.Names {
		key := strings.ToLower(strings.TrimSpace(k))
		if !tokenPattern.MatchString(key) {
			add("names key %q is not a matcher name", k)
			continue
		}
		if !n.Skip && !tokenPattern.MatchString(n.Name) {
			add("names.%s needs a name of one token, or skip", key)
		}
		if n.Category != "" && !assettech.Category(n.Category).IsValid() {
			add("names.%s.category %q is not a technology category", key, n.Category)
		}
		if n.Vendor != "" && !tokenPattern.MatchString(n.Vendor) {
			add("names.%s.vendor %q must be one token", key, n.Vendor)
		}
		names[key] = n
	}
	e.Names = names
}

func (e *Entry) validatePosture(add func(string, ...any)) {
	// An entry without posture keys consumes the matches it selects (the
	// probe's posture already records them).
	out := make(map[string]map[string]any, len(e.Posture))
	for k, keys := range e.Posture {
		key := strings.ToLower(strings.TrimSpace(k))
		if !tokenPattern.MatchString(key) {
			add("posture key %q is not a matcher name", k)
			continue
		}
		clean := webendpoint.SanitizePosture(keys)
		if len(clean) != len(keys) {
			add("posture.%s holds a key or value http_posture does not allow", key)
			continue
		}
		out[key] = clean
	}
	e.Posture = out
}

func (e *Entry) validateSurface(add func(string, ...any)) {
	s := e.Surface
	if s == nil {
		add("class surface needs surface")
		return
	}
	if s.PathFrom != "matched" && s.PathFrom != versionFromExtracted {
		add("surface.path_from must be matched or extracted")
	}
	ok := false
	for _, v := range surfaceSources {
		ok = ok || v == s.Source
	}
	if !ok {
		add("surface.source must be probe, robots or sitemap")
	}
}

// exposureTypes are the info exposure types a template match may take
// (docs/architecture/exposure-taxonomy.md).
var exposureTypes = map[string]bool{
	"web_interface_exposed": true, "ssl_issue": true, "header_missing": true,
	"email_security_weak": true, "misconfiguration": true, "custom": true, "api_exposed": true,
}

func cleanText(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// Map is a compiled set of entries.
type Map struct {
	// Origin names the packs it was built from ("template-facts-core@2026.11.1").
	Origin   string
	exact    map[string][]int
	prefixes []int
	tagged   []int
	entries  []compiled
}

type compiled struct {
	Entry
	version *regexp.Regexp
}

// Compile builds a map from validated entries. Earlier entries win among
// entries of the same precedence: an exact template id, then the longest
// prefix, then tags.
func Compile(origin string, entries []Entry) (*Map, error) {
	m := &Map{Origin: origin, exact: map[string][]int{}}
	seen := map[string]bool{}
	for i := range entries {
		e := entries[i]
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("entry %s: %w", e.ID, err)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("%w: entry id %s appears twice", ErrInvalid, e.ID)
		}
		seen[e.ID] = true
		c := compiled{Entry: e}
		if e.Technology != nil && e.Technology.VersionFrom == versionFromExtracted {
			c.version = defaultVersion
			if e.Technology.VersionPattern != "" {
				c.version = regexp.MustCompile(e.Technology.VersionPattern)
			}
		}
		idx := len(m.entries)
		m.entries = append(m.entries, c)
		switch {
		case len(e.Match.Templates) > 0:
			for _, t := range e.Match.Templates {
				m.exact[t] = append(m.exact[t], idx)
			}
		case e.Match.TemplatePrefix != "":
			m.prefixes = append(m.prefixes, idx)
		default:
			m.tagged = append(m.tagged, idx)
		}
	}
	sort.SliceStable(m.prefixes, func(a, b int) bool {
		return len(m.entries[m.prefixes[a]].Match.TemplatePrefix) > len(m.entries[m.prefixes[b]].Match.TemplatePrefix)
	})
	return m, nil
}

// Len is the number of entries.
func (m *Map) Len() int {
	if m == nil {
		return 0
	}
	return len(m.entries)
}

// Input is one info match as the router reads it. Every field is untrusted.
type Input struct {
	TemplateID string
	Matcher    string
	Tags       []string
	// Metadata is the template's metadata (key to value, unquoted).
	Metadata map[string]string
	// Extracted are the extracted values that are not marked sensitive.
	Extracted []string
	// URL is the matched URL (redacted: no user info, query or fragment).
	URL string
	// CPE is the template's CPE, when it names one.
	CPE string
}

// Technology is one technology a match proves.
type Technology struct {
	Name       string
	Version    string
	Category   string
	Vendor     string
	CPE        string
	Confidence int
}

// Fact is what a match proves.
type Fact struct {
	Class Class
	// Entry is the id of the entry that decided.
	Entry        string
	Technologies []Technology
	Posture      map[string]any
	Paths        []string
	Source       string
	EventType    string
}

// Classify routes one match. ok is false when no entry names it: the match
// stays a generic info exposure (and is counted as unmapped).
func (m *Map) Classify(in Input) (Fact, bool) {
	e := m.lookup(in)
	if e == nil {
		return Fact{}, false
	}
	f := Fact{Class: e.Class, Entry: e.ID}
	switch e.Class {
	case ClassTechnology:
		if t, ok := e.technology(in); ok {
			f.Technologies = []Technology{t}
		}
	case ClassPosture:
		if p, ok := e.Posture[strings.ToLower(strings.TrimSpace(in.Matcher))]; ok {
			f.Posture = copyPosture(p)
		}
	case ClassSurface:
		f.Source = e.Surface.Source
		f.Paths = e.surfacePaths(in)
	case ClassExposure:
		if e.Exposure != nil {
			f.EventType = e.Exposure.EventType
		}
	}
	return f, true
}

func (m *Map) lookup(in Input) *compiled {
	if m == nil {
		return nil
	}
	id := strings.ToLower(strings.TrimSpace(in.TemplateID))
	for _, i := range m.exact[id] {
		if e := &m.entries[i]; e.selects(id, in) {
			return e
		}
	}
	for _, i := range m.prefixes {
		if e := &m.entries[i]; strings.HasPrefix(id, e.Match.TemplatePrefix) && e.selects(id, in) {
			return e
		}
	}
	for _, i := range m.tagged {
		if e := &m.entries[i]; e.selects(id, in) {
			return e
		}
	}
	return nil
}

// selects checks the tags and metadata parts of the match.
func (e *compiled) selects(_ string, in Input) bool {
	for _, want := range e.Match.Tags {
		found := false
		for _, t := range in.Tags {
			found = found || strings.EqualFold(strings.TrimSpace(t), want)
		}
		if !found {
			return false
		}
	}
	if e.Match.Metadata != "" && strings.TrimSpace(in.Metadata[e.Match.Metadata]) == "" {
		return false
	}
	return true
}

func (e *compiled) technology(in Input) (Technology, bool) {
	spec := e.Technology
	t := Technology{Name: spec.Name, Category: spec.Category, Vendor: spec.Vendor, Confidence: spec.Confidence}
	if t.Confidence == 0 {
		t.Confidence = DefaultConfidence
	}
	matcher := strings.ToLower(strings.TrimSpace(in.Matcher))
	switch n, listed := e.Names[matcher]; {
	case listed && n.Skip:
		return Technology{}, false
	case listed:
		t.Name = n.Name
		if n.Category != "" {
			t.Category = n.Category
		}
		if n.Vendor != "" {
			t.Vendor = n.Vendor
		}
	case spec.NameFrom == "matcher" && matcher != "":
		t.Name = matcher
	case strings.HasPrefix(spec.NameFrom, "metadata:"):
		t.Name = strings.TrimSpace(in.Metadata[strings.TrimPrefix(spec.NameFrom, "metadata:")])
	}
	if !tokenPattern.MatchString(t.Name) {
		return Technology{}, false
	}
	if e.version != nil {
		t.Version = firstVersion(e.version, in.Extracted)
	}
	if c := strings.TrimSpace(in.CPE); c != "" && len(c) <= 256 && strings.HasPrefix(c, "cpe:2.3:") && cleanText(c, 256) {
		t.CPE = c
	}
	return t, true
}

func firstVersion(re *regexp.Regexp, values []string) string {
	gi := re.SubexpIndex("version")
	for i, v := range values {
		if i == MaxPaths {
			break
		}
		if len(v) > MaxExtractedLen {
			continue
		}
		sm := re.FindStringSubmatch(v)
		if gi < 0 || len(sm) <= gi {
			continue
		}
		if ver := strings.TrimPrefix(strings.TrimSpace(sm[gi]), "v"); versionPattern.MatchString(ver) {
			return ver
		}
	}
	return ""
}

func (e *compiled) surfacePaths(in Input) []string {
	origin, matchedPath, ok := splitURL(in.URL)
	if !ok {
		return nil
	}
	if e.Surface.PathFrom == "matched" {
		if p := cleanPath(matchedPath); p != "" {
			return []string{p}
		}
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for i, v := range in.Extracted {
		if i == MaxPaths || len(out) == MaxPaths {
			break
		}
		v = strings.TrimSpace(v)
		if len(v) > MaxExtractedLen {
			continue
		}
		if !strings.HasPrefix(v, "/") {
			o, p, ok := splitURL(v)
			if !ok || o != origin {
				continue // another origin is never added to this one
			}
			v = p
		}
		if p := cleanPath(v); p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// splitURL is an absolute http(s) URL's origin and path.
func splitURL(raw string) (origin, path string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", "", false
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	return strings.ToLower(u.Scheme + "://" + u.Host), p, true
}

// cleanPath is p when it is a concrete path: no query, fragment, wildcard
// (robots patterns), control character or space, at most the endpoint
// path limit.
func cleanPath(p string) string {
	if p == "" || p[0] != '/' || len(p) > webendpoint.MaxPathBytes ||
		strings.ContainsAny(p, "?#*$ \\") || !cleanText(p, webendpoint.MaxPathBytes) {
		return ""
	}
	return p
}

func copyPosture(p map[string]any) map[string]any {
	out := make(map[string]any, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}
