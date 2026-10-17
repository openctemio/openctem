// Package assettech is the technologies detected on an asset: every
// fingerprint a probe reports (a web server, a framework, a CDN, a security
// header), kept with a category, an optional version, the tool's confidence
// and when it was first and last seen.
//
// Design: docs/rfcs/RFC-112-asset-technologies.md.
//
// A technology is not a software component. Only a detection that names a
// real product with a version or a CPE also becomes a component for CVE
// matching (IsSoftwareCandidate); hosting, CDN, WAF, analytics and security
// header detections stay facts about the asset.
package assettech

import (
	"context"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// Bounds on what a producer may store. Sensors and imports are untrusted:
// every string is trimmed, checked for control characters and capped.
const (
	MaxNameLen    = 128
	MaxVersionLen = 64
	MaxSourceLen  = 100
	// MaxPerAsset is the technologies one report may record for an asset.
	MaxPerAsset = 100
	// MaxPerReport is the technologies one report may record in all.
	MaxPerReport = 5000
	// MaxFilterValues bounds the values of one list filter.
	MaxFilterValues = 20
	// MaxListed bounds the technologies one asset lists.
	MaxListed = 500
)

// Technology is one technology detected on an asset.
type Technology struct {
	AssetID shared.ID
	// Name is the product as the tool spelled it ("Next.js").
	Name string
	// Key is the normalised name the asset's technologies are unique by.
	Key        string
	Version    string
	Category   Category
	Confidence int // 0-100, 0 = the tool gave none
	Source     string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// Repository reads asset technologies and adds what reports know about
// them. Every method is tenant-scoped. The rows themselves are written by
// set reconciliation (the asset's resolved technologies set).
type Repository interface {
	// ListByAsset is an asset's technologies, ordered by category and name.
	ListByAsset(ctx context.Context, tenantID, assetID shared.ID) ([]Technology, error)
	// ListByAssets is, for each of the tenant's assets, at most perAsset of
	// its technologies, ordered by category and name.
	ListByAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, perAsset int) (map[shared.ID][]Technology, error)
	// Enrich adds what a report knew about technologies the assets already
	// show (the tool's category, confidence, source, last seen). It never
	// adds a technology and never changes a name or version: set
	// reconciliation decides those.
	Enrich(ctx context.Context, tenantID shared.ID, techs []Technology) error
}

// Facet is one technology across the organization's assets, for the asset
// list's filter: the name, its most common category and how many assets
// (that the caller may list) use it.
type Facet struct {
	Key        string
	Name       string
	Category   Category
	AssetCount int
}

// MaxFacets bounds one facet list.
const MaxFacets = 100

// Observation builds a technology from a producer's values: it trims,
// rejects control characters and over-long names, drops an unusable
// version, clamps the confidence and classifies the name. ok is false when
// the name is unusable.
func Observation(assetID shared.ID, name, version string, toolCategories []string, confidence int, source string, seen time.Time) (Technology, bool) {
	name = strings.Join(strings.Fields(strings.TrimSpace(name)), " ")
	key := Key(name)
	if key == "" {
		return Technology{}, false
	}
	return Technology{
		AssetID:    assetID,
		Name:       name,
		Key:        key,
		Version:    CleanVersion(version),
		Category:   Classify(key, toolCategories),
		Confidence: clampConfidence(confidence),
		Source:     clip(cleanText(source), MaxSourceLen),
		FirstSeen:  seen,
		LastSeen:   seen,
	}, true
}

// Key is the normalised name: lower case, single spaces. It is "" for an
// empty or over-long name or one with control or invalid UTF-8 characters.
func Key(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > MaxNameLen || !utf8.ValidString(name) {
		return ""
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return strings.Join(strings.Fields(strings.ToLower(name)), " ")
}

// Element is the stored form of a technology: "Name" or "Name:version",
// the name with single spaces and the version cleaned. It is "" when the
// name is unusable.
func Element(name, version string) string {
	name = strings.Join(strings.Fields(strings.TrimSpace(name)), " ")
	if Key(name) == "" {
		return ""
	}
	if v := CleanVersion(version); v != "" {
		return name + ":" + v
	}
	return name
}

// Collapse turns a reconciled set of elements into one element per key, in
// stored form, sorted by key. Two sources that report different versions
// of one product give one technology: a known version beats none, and the
// higher version wins.
func Collapse(elements []string) []string {
	best := map[string]string{}
	for _, e := range elements {
		name, version := Split(e)
		el := Element(name, version)
		if el == "" {
			continue
		}
		k := Key(name)
		prev, ok := best[k]
		if !ok || preferElement(el, prev) {
			best[k] = el
		}
	}
	keys := make([]string, 0, len(best))
	for k := range best {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, best[k])
	}
	return out
}

// preferElement reports whether stored element a beats b for one key: the
// better version, then (same version, other spelling) the smaller string,
// so the choice never depends on input order.
func preferElement(a, b string) bool {
	_, va := Split(a)
	_, vb := Split(b)
	if va == vb {
		return a < b
	}
	return preferVersion(va, vb)
}

// preferVersion reports whether version a beats version b (a != b).
func preferVersion(a, b string) bool {
	switch {
	case b == "":
		return true
	case a == "":
		return false
	}
	va, okA := vulnmatch.ParseVersion(a)
	vb, okB := vulnmatch.ParseVersion(b)
	if okA && okB {
		if c := va.Compare(vb); c != 0 {
			return c > 0
		}
	}
	return a > b
}

// ElementKey is the key of a stored technology element ("Name" or
// "Name:version", the reconciled set's form).
func ElementKey(element string) string {
	name, _ := Split(element)
	return Key(name)
}

// Split splits a technology string "Name:version" (the version may be
// missing: "Cloudflare"). A colon starts the version only when a digit
// follows, so "Name:Plugin" stays one name.
func Split(s string) (name, version string) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, ":"); i > 0 && startsWithDigit(strings.TrimSpace(s[i+1:])) {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

// CleanVersion trims a version and drops it ("" = unknown) when it is too
// long or has control characters.
func CleanVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > MaxVersionLen || !utf8.ValidString(v) {
		return ""
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return v
}

// IsSoftwareCandidate reports whether a detection should also become a
// software component (CVE matching): it names a real product, and has a
// CPE or a version. Security headers, hosting, CDN, WAF and analytics never
// do, whatever version string a tool attaches.
func IsSoftwareCandidate(name, version, cpe string, toolCategories []string) bool {
	key := Key(name)
	if strings.TrimSpace(cpe) != "" {
		return key == "" || Classify(key, toolCategories).Kind() == KindSoftware
	}
	if key == "" || CleanVersion(version) == "" {
		return false
	}
	return Classify(key, toolCategories).Kind() == KindSoftware
}

// ParseFilterValues splits a comma-separated filter into at most
// MaxFilterValues keys, dropping unusable values.
func ParseFilterValues(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, min(len(parts), MaxFilterValues))
	seen := map[string]bool{}
	for _, p := range parts {
		k := Key(p)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
		if len(out) == MaxFilterValues {
			break
		}
	}
	return out
}

func clampConfidence(c int) int {
	switch {
	case c < 0:
		return 0
	case c > 100:
		return 100
	}
	return c
}

func cleanText(s string) string {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return ""
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// clip cuts s to at most n bytes without splitting a character.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func startsWithDigit(s string) bool {
	if s != "" && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}
	return s != "" && s[0] >= '0' && s[0] <= '9'
}
