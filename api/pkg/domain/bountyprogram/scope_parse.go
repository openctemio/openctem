package bountyprogram

// Reading a program's published scope as the person pasted it (RFC-064 §5.2).
// Two forms are accepted:
//
//   - text: one target per line. "In scope" / "Out of scope" headings switch
//     the section; a line starting with "-" or "!" is out of scope wherever
//     it is; "#" starts a comment; list bullets ("* ", "• ", "+ ") are
//     dropped, so "* *.example.com" is the wildcard "*.example.com";
//   - CSV with a header row naming an identifier column ("identifier" or
//     "asset_identifier"), optionally "asset_type" and an eligibility column
//     ("eligible_for_submission" / "in_scope"): a false value puts the row
//     out of scope.
//
// Each item is classified into what a scope entry can hold. Items no scan can
// target (mobile apps, source code, hardware, free text, wildcards in the
// middle of a name) are kept as "not scannable" so the person sees them, and
// never become entries.

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Bounds of one paste.
const (
	MaxScopeTextBytes = 256 * 1024
	MaxScopeItems     = 2000
	maxItemLength     = 500
)

// Kind is what a pasted item is.
type Kind string

// Kinds of items.
const (
	KindDomain   Kind = "domain"   // an exact host name
	KindWildcard Kind = "wildcard" // *.example.com
	KindURL      Kind = "url"      // a URL limited to a path
	KindIP       Kind = "ip"       // one address
	KindCIDR     Kind = "cidr"     // a network or a-b range
	KindOther    Kind = "other"    // not scannable (app id, source, hardware, text)
)

// Item is one parsed scope line.
type Item struct {
	// Raw is the identifier as pasted (trimmed).
	Raw string `json:"raw"`
	// InScope is false for an out-of-scope item.
	InScope bool `json:"in_scope"`
	Kind    Kind `json:"kind"`
	// TargetType and Pattern are the scope entry or exclusion this item
	// becomes (empty for KindOther).
	TargetType scope.TargetType `json:"target_type,omitempty"`
	Pattern    string           `json:"pattern,omitempty"`
	// AssetType is the program's own type label from a CSV, if any.
	AssetType string `json:"asset_type,omitempty"`
	// Note says why an item is not scannable.
	Note string `json:"note,omitempty"`
}

// Scannable reports whether the item becomes a scope entry or exclusion.
func (i Item) Scannable() bool { return i.Kind != KindOther && i.Pattern != "" }

// ErrScopeTooLarge refuses an oversized paste.
var ErrScopeTooLarge = shared.NewDomainError("PROGRAM_SCOPE_TOO_LARGE",
	fmt.Sprintf("the pasted scope is larger than %d KiB or %d items", MaxScopeTextBytes/1024, MaxScopeItems), shared.ErrValidation)

// ErrScopeEmpty refuses a paste with no in-scope item.
var ErrScopeEmpty = shared.NewDomainError("PROGRAM_SCOPE_EMPTY", "the pasted scope lists no in-scope target", shared.ErrValidation)

// ParseScope reads a pasted scope (text or CSV). Items are de-duplicated by
// (section, pattern or raw text); the order of the paste is kept.
func ParseScope(text string) ([]Item, error) {
	if len(text) > MaxScopeTextBytes {
		return nil, ErrScopeTooLarge
	}
	text = strings.TrimPrefix(text, "\xef\xbb\xbf")
	var items []Item
	var err error
	if looksLikeCSV(text) {
		items, err = parseCSV(text)
	} else {
		items = parseText(text)
	}
	if err != nil {
		return nil, err
	}
	if len(items) > MaxScopeItems {
		return nil, ErrScopeTooLarge
	}
	items = dedupe(items)
	for _, it := range items {
		if it.InScope {
			return items, nil
		}
	}
	return nil, ErrScopeEmpty
}

func dedupe(items []Item) []Item {
	seen := make(map[string]bool, len(items))
	out := items[:0]
	for _, it := range items {
		key := fmt.Sprintf("%t|%s|%s", it.InScope, it.TargetType, strings.ToLower(it.Pattern))
		if it.Pattern == "" {
			key = fmt.Sprintf("%t|raw|%s", it.InScope, strings.ToLower(it.Raw))
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, it)
	}
	return out
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

func parseText(text string) []Item {
	lines := strings.Split(text, "\n")
	items := make([]Item, 0, min(len(lines), MaxScopeItems+1))
	inScope := true
	for _, line := range lines {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if i := strings.Index(line, "#"); i >= 0 && !strings.Contains(line[:i], "://") {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if s, ok := sectionHeading(line); ok {
			inScope = s
			continue
		}
		out := false
		if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "!") {
			out, line = true, strings.TrimSpace(line[1:])
		}
		line = stripBullet(line)
		if line == "" {
			continue
		}
		it := Classify(firstField(line))
		it.InScope = inScope && !out
		items = append(items, it)
		if len(items) > MaxScopeItems {
			break
		}
	}
	return items
}

// sectionHeading recognizes "In scope", "Out of scope" (and "In-scope:",
// "OUT OF SCOPE targets").
func sectionHeading(line string) (inScope, ok bool) {
	l := strings.ToLower(strings.Trim(line, " :#*=-"))
	l = strings.ReplaceAll(l, "-", " ")
	switch {
	case strings.HasPrefix(l, "out of scope"):
		return false, true
	case strings.HasPrefix(l, "in scope"):
		return true, true
	}
	return false, false
}

// stripBullet drops a list bullet. "*" counts as a bullet only when a space
// follows it; "*.example.com" is a wildcard.
func stripBullet(line string) string {
	for _, b := range []string{"* ", "• ", "+ ", "· "} {
		if strings.HasPrefix(line, b) {
			return strings.TrimSpace(line[len(b):])
		}
	}
	return line
}

// firstField is the identifier of a line ("example.com  (main site)").
func firstField(line string) string {
	if f := strings.Fields(line); len(f) > 0 {
		return strings.Trim(f[0], ",;")
	}
	return ""
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

func looksLikeCSV(text string) bool {
	first := strings.ToLower(strings.SplitN(text, "\n", 2)[0])
	return strings.ContainsAny(first, ",;\t") &&
		(strings.Contains(first, "identifier") || strings.Contains(first, "asset_type"))
}

func parseCSV(text string) ([]Item, error) {
	r := csv.NewReader(bytes.NewReader([]byte(text)))
	r.Comma = csvSeparator(strings.SplitN(text, "\n", 2)[0])
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("%w: the CSV header cannot be read", shared.ErrValidation)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	idCol, ok := col["identifier"]
	if !ok {
		if idCol, ok = col["asset_identifier"]; !ok {
			return nil, fmt.Errorf("%w: the CSV needs an identifier or asset_identifier column", shared.ErrValidation)
		}
	}
	typeCol, hasType := col["asset_type"]
	eligCol, hasElig := col["eligible_for_submission"]
	if !hasElig {
		eligCol, hasElig = col["in_scope"]
	}
	var items []Item
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: the CSV cannot be read", shared.ErrValidation)
		}
		if idCol >= len(rec) || strings.TrimSpace(rec[idCol]) == "" {
			continue
		}
		var assetType string
		if hasType && typeCol < len(rec) {
			assetType = strings.TrimSpace(rec[typeCol])
		}
		it := classifyTyped(strings.TrimSpace(rec[idCol]), assetType)
		it.InScope = true
		if hasElig && eligCol < len(rec) && isFalse(rec[eligCol]) {
			it.InScope = false
		}
		items = append(items, it)
		if len(items) > MaxScopeItems {
			break
		}
	}
	return items, nil
}

// csvSeparator picks tab, semicolon or comma from the header line (exports
// are tab-separated; older ones use commas or semicolons).
func csvSeparator(header string) rune {
	switch {
	case strings.Contains(header, "\t"):
		return '\t'
	case strings.Count(header, ";") > strings.Count(header, ","):
		return ';'
	}
	return ','
}

func isFalse(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "false", "no", "0", "n":
		return true
	}
	return false
}

// classifyTyped honors a program's asset type: types that are not network
// targets stay "other" even when the identifier looks like a name (a mobile
// app id such as com.example.app).
func classifyTyped(raw, assetType string) Item {
	t := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(assetType)), "-", "_")
	switch t {
	case "", "url", "wildcard", "domain", "cidr", "ip_address", "ip", "iprange", "ip_range",
		"api", "website", "web", "web_application", "network":
		it := Classify(raw)
		it.AssetType = assetType
		return it
	}
	return Item{Raw: clip(raw), Kind: KindOther, AssetType: assetType, Note: "not a network target (" + t + ")"}
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

// Classify reads one identifier into an item (InScope is left false).
func Classify(raw string) Item {
	raw = clip(strings.TrimSpace(raw))
	it := Item{Raw: raw, Kind: KindOther}
	if raw == "" {
		it.Note = "empty"
		return it
	}
	if a, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
		return withPattern(it, KindIP, scope.TargetTypeIPAddress, a.Unmap().String())
	}
	if p, err := netip.ParsePrefix(raw); err == nil {
		return withPattern(it, KindCIDR, scope.TargetTypeCIDR, p.Masked().String())
	}
	if strings.Count(raw, "-") == 1 && strings.Count(raw, ".") >= 6 {
		parts := strings.SplitN(raw, "-", 2)
		lo, e1 := netip.ParseAddr(strings.TrimSpace(parts[0]))
		hi, e2 := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if e1 == nil && e2 == nil {
			return withPattern(it, KindCIDR, scope.TargetTypeIPRange, lo.String()+"-"+hi.String())
		}
	}
	if strings.Contains(raw, "://") {
		return classifyURL(it)
	}
	host, path, _ := strings.Cut(raw, "/")
	if path != "" && strings.Trim(path, "*") != "" {
		// "example.com/api/*": a path-limited target.
		it2 := classifyURL(Item{Raw: "https://" + raw, Kind: KindOther})
		it2.Raw = raw
		return it2
	}
	return classifyHost(it, host)
}

func classifyURL(it Item) Item {
	u, err := url.Parse(it.Raw)
	if err != nil || u.Host == "" {
		it.Note = "not a URL, a name, an address or a network"
		return it
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		it.Note = "not a web URL (" + strings.ToLower(u.Scheme) + ")"
		return it
	}
	host := u.Hostname()
	path := strings.Trim(u.EscapedPath(), "/*")
	if path == "" {
		// The whole host: the entry is its name (or address).
		if a, err := netip.ParseAddr(host); err == nil {
			return withPattern(it, KindIP, scope.TargetTypeIPAddress, a.Unmap().String())
		}
		return classifyHost(it, host)
	}
	if strings.Contains(host, "*") {
		it.Note = "wildcard host with a path; add it by hand"
		return it
	}
	pattern := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + "/" + path + "*"
	return withPattern(it, KindURL, scope.TargetTypeURL, pattern)
}

func classifyHost(it Item, host string) Item {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i] // drop a port
	}
	wild := false
	switch {
	case strings.HasPrefix(h, "*."):
		wild, h = true, h[2:]
	case strings.HasPrefix(h, "**."):
		wild, h = true, h[3:]
	}
	if strings.Contains(h, "*") {
		it.Note = "a wildcard inside a name is not supported; list the names"
		return it
	}
	if err := scope.ValidatePattern(scope.TargetTypeDomain, h); err != nil || !strings.Contains(h, ".") {
		it.Note = "not a host name"
		return it
	}
	if wild {
		return withPattern(it, KindWildcard, scope.TargetTypeDomain, "*."+h)
	}
	return withPattern(it, KindDomain, scope.TargetTypeDomain, h)
}

func withPattern(it Item, k Kind, t scope.TargetType, pattern string) Item {
	if err := scope.ValidatePattern(t, pattern); err != nil {
		it.Kind, it.Note = KindOther, "not a valid "+string(t)
		return it
	}
	it.Kind, it.TargetType, it.Pattern = k, t, pattern
	return it
}

func clip(s string) string {
	if len(s) > maxItemLength {
		return s[:maxItemLength]
	}
	return s
}
