package webendpoint

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The sensitive-path catalog (RFC-056 WS5): platform-curated, versioned data
// that labels endpoints whose path is a well-known sensitive location (an
// admin console, a debug endpoint, a configuration file, a VCS directory).
// It is never learned from tenant data and never aggregated across tenants.

//go:embed catalog.json
var catalogJSON []byte

// CatalogEntry is one sensitive path.
type CatalogEntry struct {
	Key      string   `json:"key"`
	Path     string   `json:"path"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Tags     []string `json:"tags"`
	// Verify names the signed templates that prove the path is exposed. An
	// entry without it is a label only: nothing is verified or filed for it.
	Verify *CatalogVerify `json:"verify,omitempty"`
}

// CatalogVerify links a catalog path to the platform's signed templates.
type CatalogVerify struct {
	// Templates are template ids of the platform's signed template pack.
	Templates []string `json:"templates"`
	// Expect is what counts as verified: "hit", a match of one of the
	// templates. A status code alone never verifies anything.
	Expect string `json:"expect"`
}

// ExpectHit is the only verification outcome: a template match.
const ExpectHit = "hit"

// MaxVerifyTemplates bounds the templates of one entry.
const MaxVerifyTemplates = 5

var templateIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// validate reports a malformed verify block.
func (v *CatalogVerify) validate() error {
	if v.Expect != ExpectHit {
		return fmt.Errorf("verify.expect must be %q", ExpectHit)
	}
	if len(v.Templates) == 0 || len(v.Templates) > MaxVerifyTemplates {
		return fmt.Errorf("verify.templates must hold 1 to %d ids", MaxVerifyTemplates)
	}
	for _, t := range v.Templates {
		if !templateIDRe.MatchString(t) {
			return fmt.Errorf("verify.templates: %q is not a template id", t)
		}
	}
	return nil
}

// Catalog is the loaded catalog.
type Catalog struct {
	Version string         `json:"version"`
	Entries []CatalogEntry `json:"entries"`
	byLen   []CatalogEntry // longest path first: the most specific match wins
}

// DefaultCatalog is the embedded catalog.
var DefaultCatalog = mustCatalog(catalogJSON)

func mustCatalog(b []byte) *Catalog {
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		panic("webendpoint: invalid catalog: " + err.Error())
	}
	for _, e := range c.Entries {
		if e.Verify == nil {
			continue
		}
		if err := e.Verify.validate(); err != nil {
			panic("webendpoint: invalid catalog entry " + e.Key + ": " + err.Error())
		}
	}
	c.byLen = append([]CatalogEntry(nil), c.Entries...)
	sort.SliceStable(c.byLen, func(i, j int) bool {
		return segmentCount(c.byLen[i].Path) > segmentCount(c.byLen[j].Path)
	})
	return &c
}

func segmentCount(p string) int { return len(splitPath(p)) }

func splitPath(p string) []string {
	out := []string{}
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Match returns the most specific entry whose path is the template or a
// prefix of it, segment by segment ("*" = any one segment), or nil. A
// file-like entry ("/.env") matches only itself. Matching ignores case:
// many servers do, and over-labeling is the safe side.
func (c *Catalog) Match(template string) *CatalogEntry {
	if c == nil {
		return nil
	}
	ts := splitPath(strings.ToLower(template))
	for i := range c.byLen {
		e := &c.byLen[i]
		ps := splitPath(strings.ToLower(e.Path))
		if len(ps) == 0 || len(ts) < len(ps) {
			continue
		}
		last := ps[len(ps)-1]
		if strings.Contains(last, ".") && len(ts) != len(ps) && !strings.HasPrefix(last, ".") {
			continue // "/phpinfo.php" names a file, not a directory
		}
		ok := true
		for j, s := range ps {
			if s != "*" && s != ts[j] {
				ok = false
				break
			}
		}
		if ok {
			return e
		}
	}
	return nil
}

// ByKey returns the entry with key, or nil.
func (c *Catalog) ByKey(key string) *CatalogEntry {
	if c == nil {
		return nil
	}
	for i := range c.Entries {
		if c.Entries[i].Key == key {
			e := c.Entries[i]
			return &e
		}
	}
	return nil
}

// KeysBySeverity returns the keys of the catalog entries of severity high or
// critical (high holds the critical ones too) and the critical keys.
func KeysBySeverity() (high, critical []string) {
	high, critical = []string{}, []string{}
	for _, e := range DefaultCatalog.Entries {
		switch e.Severity {
		case "critical":
			critical = append(critical, e.Key)
			high = append(high, e.Key)
		case "high":
			high = append(high, e.Key)
		}
	}
	return high, critical
}
