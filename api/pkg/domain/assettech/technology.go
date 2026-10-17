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
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
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

// Repository stores asset technologies. Every method is tenant-scoped.
type Repository interface {
	// Upsert records technologies seen on assets: a known (asset, key)
	// keeps its first_seen; last_seen, version, category, confidence and
	// source take the newer sighting's values when it has them.
	Upsert(ctx context.Context, tenantID shared.ID, techs []Technology) error
	// ListByAsset is an asset's technologies, ordered by category and name.
	ListByAsset(ctx context.Context, tenantID, assetID shared.ID) ([]Technology, error)
	// ShownKeys is, for each asset, the keys of the technologies the asset
	// currently shows (its reconciled properties.technologies).
	ShownKeys(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]map[string]bool, error)
}

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

// ElementKey is the key of a stored technology element ("Name" or
// "Name:version", the reconciled properties.technologies form).
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
