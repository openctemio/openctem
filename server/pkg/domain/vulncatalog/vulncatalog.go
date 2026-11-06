// Package vulncatalog is the read seam of the vulnerability catalog: the
// public vulnerability data (CVE records, affected ranges, the global product
// dictionary, KEV, EPSS, identifier aliases) that every tenant reads.
//
// Design: docs/rfcs/RFC-143-vulnerability-catalog.md. The catalog is the
// schema "vuln" of the intel database; until that database exists the
// Postgres reader runs over today's tables in the tenant database. Callers
// depend on Reader only, so moving the store changes no caller.
//
// The catalog holds no tenant data. A reader never returns a tenant-private
// product or alias, and nothing in this package is keyed by tenant.
package vulncatalog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnmatch"
)

// Mode is how the catalog can be read.
type Mode string

const (
	// ModeFull: the catalog is reachable and current.
	ModeFull Mode = "full"
	// ModeDegraded: the catalog is unreachable, stale or being rebuilt.
	// Reads may fail with ErrUnavailable; nothing treats that as "none".
	ModeDegraded Mode = "degraded"
	// ModeDisabled: the platform switched the catalog off, or it is not
	// installed. Every read fails with ErrUnavailable.
	ModeDisabled Mode = "disabled"
)

// ParseMode reads the install-time mode (VULN_CATALOG_MODE). Empty means
// full. Degraded is a runtime state, never configured.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case "", ModeFull:
		return ModeFull, nil
	case ModeDisabled:
		return ModeDisabled, nil
	default:
		return "", fmt.Errorf("%w: vulnerability catalog mode must be full or disabled", shared.ErrValidation)
	}
}

var (
	// ErrUnavailable means the catalog could not answer: it is disabled,
	// unreachable or being rebuilt. It means "unknown", never "none": a
	// matcher, reconcile, auto-close or planner that gets it stops its unit
	// of work and changes nothing.
	ErrUnavailable = errors.New("vulnerability catalog unavailable")
	// ErrNotFound means the catalog answered and has no such entry.
	ErrNotFound = fmt.Errorf("%w: vulnerability catalog entry", shared.ErrNotFound)
)

// Version identifies the catalog content a read saw: the sequence of the
// last signed bundle applied. Zero means nothing was applied yet.
type Version struct {
	Seq int64
}

// Product is a global product of the dictionary.
type Product struct {
	ID            shared.ID
	Part          string
	Vendor        string
	Name          string
	CPEVendor     string
	CPEProduct    string
	PurlType      string
	PurlNamespace string
	PurlName      string
}

// Affected is one affected statement of a product.
type Affected struct {
	// LegacyID is today's surrogate row id, kept as match evidence until
	// matches carry the content-addressed range digest.
	LegacyID int64
	Range    vulnmatch.Range
}

// KEV is a known-exploited entry.
type KEV struct {
	CVEID         string
	Name          string
	VendorProject string
	Product       string
	DateAdded     *time.Time
	DueDate       *time.Time
	Ransomware    bool
}

// EPSS is the current exploit prediction score of a CVE. Percentile is nil
// when the percentile curve has no point for the score.
type EPSS struct {
	CVEID      string
	Score      float64
	Percentile *float64
}

// Fact is the narrow, public view of a CVE that tenant pages and scoring use.
type Fact struct {
	CVEID       string
	Status      string
	Severity    string
	CVSSScore   *float64
	CVSSVersion string
	CVSSVector  string
	Published   *time.Time
	Modified    *time.Time
	CWEs        []string
	KEV         *KEV
	EPSS        *EPSS
}

// CVERecord is the full public record of a CVE.
type CVERecord struct {
	Fact
	Description string
}

// MaxBatch caps the ids one Facts or EPSS call takes.
const MaxBatch = 1000

// Reader reads the vulnerability catalog. Implementations: the Postgres
// reader and Disabled. Every method returns ErrUnavailable when the catalog
// cannot answer; ErrNotFound only when it answered "absent".
type Reader interface {
	Mode() Mode
	// Version is the catalog content version.
	Version(ctx context.Context) (Version, error)
	// ResolveAlias maps a global product alias (kind, value) to its product.
	ResolveAlias(ctx context.Context, kind, value string) (shared.ID, error)
	// Product reads a global product.
	Product(ctx context.Context, id shared.ID) (Product, error)
	// Ranges returns every affected statement of a product, in a stable
	// order. An empty result means the catalog has none.
	Ranges(ctx context.Context, productID shared.ID) ([]Affected, error)
	// Facts returns the facts of the CVEs the catalog has (at most
	// MaxBatch ids); ids it does not have are left out.
	Facts(ctx context.Context, cveIDs []string) ([]Fact, error)
	// CVE reads one full record.
	CVE(ctx context.Context, id string) (CVERecord, error)
	// CanonicalVulnID resolves an identifier to the canonical CVE id. An id
	// with no alias resolves to itself, normalised.
	CanonicalVulnID(ctx context.Context, id string) (string, error)
	// KEVSet returns the whole known-exploited set, keyed by CVE id.
	KEVSet(ctx context.Context) (map[string]KEV, error)
	// EPSS returns the scores of the CVEs that have one (at most MaxBatch).
	EPSS(ctx context.Context, cveIDs []string) ([]EPSS, error)
}

// CanonicalForm writes a vulnerability id in its canonical form: a CVE in
// upper case, a GHSA with the prefix in upper case and the body in lower
// case, any other id trimmed with its prefix in upper case.
func CanonicalForm(id string) string {
	s := strings.TrimSpace(id)
	i := strings.IndexByte(s, '-')
	if i <= 0 {
		return strings.ToUpper(s)
	}
	prefix, body := strings.ToUpper(s[:i]), s[i+1:]
	switch prefix {
	case "CVE":
		body = strings.ToUpper(body)
	case "GHSA":
		body = strings.ToLower(body)
	}
	return prefix + "-" + body
}

// NormalizeIDs writes ids in canonical form and de-duplicates them, dropping
// empty ones. It refuses more than MaxBatch ids.
func NormalizeIDs(ids []string) ([]string, error) {
	if len(ids) > MaxBatch {
		return nil, fmt.Errorf("%w: at most %d ids per vulnerability catalog read", shared.ErrValidation, MaxBatch)
	}
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		n := CanonicalForm(id)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, nil
}
