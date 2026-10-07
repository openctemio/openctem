package webendpoint

import (
	_ "embed"
	"encoding/json"
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
