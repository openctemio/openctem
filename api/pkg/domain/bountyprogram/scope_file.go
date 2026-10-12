package bountyprogram

// Scope files a person imports for a program they follow (RFC-065 §15.2):
// the platform's CSV export, a Burp Suite target scope (JSON), or any CSV
// with a column mapping the person chose. A file is read once into items;
// the import then goes through the same preview, guardrails and attestation
// as a paste. Nothing is fetched and no credential is involved.
//
// Translation never widens: a Burp host expression becomes an entry only
// when it names exactly one host, or every subdomain of one name; anything
// else (".*", character classes, alternations, address ranges written as
// expressions) is kept as a not-scannable item for the person to read.

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// File formats.
const (
	FileFormatAuto        = "auto"
	FileFormatPlatformCSV = "platform_csv"
	FileFormatBurpJSON    = "burp_json"
	FileFormatGenericCSV  = "generic_csv"
	FileFormatText        = "text"
)

// Bounds of a column mapping.
const maxColumnName = 100

// ScopeFile is a scope file to import.
type ScopeFile struct {
	// Format is auto, platform_csv, burp_json, generic_csv or text.
	Format string `json:"format"`
	// Name is the file name as chosen (shown in the audit; never a path).
	Name string `json:"name"`
	// Content is the file's text.
	Content string `json:"content"`
	// Mapping names the columns of a generic CSV.
	Mapping *ColumnMapping `json:"mapping,omitempty"`
}

// ColumnMapping names the columns of a generic CSV: the identifier is
// required; the type and the in-scope flag are optional (every row is in
// scope without one).
type ColumnMapping struct {
	Identifier string `json:"identifier"`
	Type       string `json:"type,omitempty"`
	InScope    string `json:"in_scope,omitempty"`
}

// ErrFileFormat refuses a file that is not the format it claims.
var ErrFileFormat = shared.NewDomainError("PROGRAM_FILE_INVALID", "the scope file cannot be read in this format", shared.ErrValidation)

// ParseScopeFile reads a scope file into items, with the bounds of a paste
// (MaxScopeTextBytes, MaxScopeItems) and at least one in-scope item.
func ParseScopeFile(f ScopeFile) ([]Item, error) {
	if len(f.Content) > MaxScopeTextBytes {
		return nil, ErrScopeTooLarge
	}
	content := strings.TrimPrefix(f.Content, "\xef\xbb\xbf")
	format := f.Format
	if format == "" || format == FileFormatAuto {
		format = detectFormat(content)
	}
	var items []Item
	var err error
	switch format {
	case FileFormatPlatformCSV:
		if !looksLikeCSV(content) {
			return nil, fmt.Errorf("%w: the CSV needs an identifier or asset_identifier column", ErrFileFormat)
		}
		return ParseScope(content)
	case FileFormatText:
		return ParseScope(content)
	case FileFormatBurpJSON:
		items, err = parseBurp(content)
	case FileFormatGenericCSV:
		items, err = parseMappedCSV(content, f.Mapping)
	default:
		return nil, fmt.Errorf("%w: format must be auto, platform_csv, burp_json, generic_csv or text", shared.ErrValidation)
	}
	if err != nil {
		return nil, err
	}
	return NormalizeItems(items)
}

func detectFormat(content string) string {
	trimmed := strings.TrimSpace(content)
	switch {
	case strings.HasPrefix(trimmed, "{"):
		return FileFormatBurpJSON
	case looksLikeCSV(content):
		return FileFormatPlatformCSV
	}
	return FileFormatText
}

// ---------------------------------------------------------------------------
// Burp Suite target scope
// ---------------------------------------------------------------------------

type burpRule struct {
	Enabled  *bool  `json:"enabled"`
	Host     string `json:"host"`
	Prefix   string `json:"prefix"`
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	File     string `json:"file"`
}

type burpConfig struct {
	Target *struct {
		Scope *struct {
			AdvancedMode bool       `json:"advanced_mode"`
			Include      []burpRule `json:"include"`
			Exclude      []burpRule `json:"exclude"`
		} `json:"scope"`
	} `json:"target"`
}

func parseBurp(content string) ([]Item, error) {
	var cfg burpConfig
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, fmt.Errorf("%w: not a JSON document", ErrFileFormat)
	}
	if cfg.Target == nil || cfg.Target.Scope == nil {
		return nil, fmt.Errorf("%w: no target.scope in the file", ErrFileFormat)
	}
	sc := cfg.Target.Scope
	if len(sc.Include)+len(sc.Exclude) > MaxScopeItems {
		return nil, ErrScopeTooLarge
	}
	items := make([]Item, 0, len(sc.Include)+len(sc.Exclude))
	add := func(rules []burpRule, inScope bool) {
		for _, r := range rules {
			if r.Enabled != nil && !*r.Enabled {
				continue
			}
			it := burpItem(r)
			it.InScope = inScope
			items = append(items, it)
		}
	}
	add(sc.Include, true)
	add(sc.Exclude, false)
	return items, nil
}

// burpItem reads one rule: a prefix (non-advanced mode) is a URL or host;
// a host expression (advanced mode) is read by burpHost.
func burpItem(r burpRule) Item {
	if p := strings.TrimSpace(r.Prefix); p != "" {
		return Classify(p)
	}
	raw := strings.TrimSpace(r.Host)
	host, ok := burpHost(raw)
	if !ok {
		return Item{Raw: clip(raw), Kind: KindOther, Note: "a host expression that does not name one host or one domain's subdomains; add it by hand"}
	}
	it := Classify(host)
	it.Raw = clip(raw)
	return it
}

// Host expressions read exactly. Anything else is refused.
var (
	// ^.*\.example\.com$, ^(.*\.)?example\.com$, ^([a-z0-9-]+\.)*example\.com$
	burpWildcardRE = regexp.MustCompile(`^\^?(?:\.\*\\\.|\(\.\*\\\.\)\?|\(\[a-z0-9-\]\+\\\.\)\*|\(\[\^.\]\+\\\.\)\*)((?:[a-z0-9-]+\\\.)+[a-z0-9-]+)\$?$`)
	// ^www\.example\.com$
	burpExactRE = regexp.MustCompile(`^\^?((?:[a-z0-9-]+\\\.)+[a-z0-9-]+)\$?$`)
	// a plain name or address, no expression syntax at all
	burpLiteralRE = regexp.MustCompile(`^[a-z0-9.:-]+$`)
)

// burpHost turns a host expression into "*.name", "name" or an address.
// It is deliberately narrow: the result never covers more than the
// expression matches.
func burpHost(expr string) (string, bool) {
	e := strings.ToLower(strings.TrimSpace(expr))
	if e == "" {
		return "", false
	}
	if m := burpWildcardRE.FindStringSubmatch(e); m != nil {
		return "*." + strings.ReplaceAll(m[1], `\.`, "."), true
	}
	if m := burpExactRE.FindStringSubmatch(e); m != nil {
		return strings.ReplaceAll(m[1], `\.`, "."), true
	}
	if burpLiteralRE.MatchString(e) && strings.Contains(e, ".") {
		return e, true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Generic CSV with a column mapping
// ---------------------------------------------------------------------------

func validColumn(name string, required bool) bool {
	if name == "" {
		return !required
	}
	return len(name) <= maxColumnName && !hasControl(name)
}

func parseMappedCSV(content string, m *ColumnMapping) ([]Item, error) {
	if m == nil || !validColumn(m.Identifier, true) || !validColumn(m.Type, false) || !validColumn(m.InScope, false) {
		return nil, fmt.Errorf("%w: a generic CSV needs a column mapping that names the identifier column", shared.ErrValidation)
	}
	first := strings.SplitN(content, "\n", 2)[0]
	r := csv.NewReader(bytes.NewReader([]byte(content)))
	r.Comma = csvSeparator(first)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("%w: the CSV header cannot be read", ErrFileFormat)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	find := func(name string) (int, error) {
		if name == "" {
			return -1, nil
		}
		i, ok := col[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return -1, fmt.Errorf("%w: the CSV has no column %q", shared.ErrValidation, clip(name))
		}
		return i, nil
	}
	idCol, err := find(m.Identifier)
	if err != nil {
		return nil, err
	}
	typeCol, err := find(m.Type)
	if err != nil {
		return nil, err
	}
	scopeCol, err := find(m.InScope)
	if err != nil {
		return nil, err
	}
	var items []Item
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: the CSV cannot be read", ErrFileFormat)
		}
		if idCol >= len(rec) || strings.TrimSpace(rec[idCol]) == "" {
			continue
		}
		var assetType string
		if typeCol >= 0 && typeCol < len(rec) {
			assetType = strings.TrimSpace(rec[typeCol])
		}
		it := ClassifyTyped(strings.TrimSpace(rec[idCol]), assetType)
		it.InScope = !(scopeCol >= 0 && scopeCol < len(rec) && isFalse(rec[scopeCol]))
		items = append(items, it)
		if len(items) > MaxScopeItems {
			return nil, ErrScopeTooLarge
		}
	}
	return items, nil
}
