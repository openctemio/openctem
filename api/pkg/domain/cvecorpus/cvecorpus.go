// Package cvecorpus is the platform-wide CVE corpus used by inventory
// matching: CVE records and the affected ranges of global catalog products.
// It holds no tenant data and is written only by the vulnerability bundle
// importer.
//
// Design: docs/rfcs/RFC-066-inventory-vulnerability-matching.md (§5.3).
package cvecorpus

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// CVE is one corpus record and its ranges.
type CVE struct {
	ID           string
	Status       string
	Rejected     bool
	Published    *time.Time
	LastModified *time.Time
	Description  string
	CVSSScore    *float64
	CVSSVersion  string
	CVSSVector   string
	Severity     string
	CWEs         []string
	Ranges       []Range
	// TooManyRanges is set when the record named more statements than the
	// corpus keeps: the record is updated and its stored ranges are kept.
	TooManyRanges bool
}

// Range is one affected range of a CPE product, optionally only when the
// product runs on Condition.
type Range struct {
	Product   vulnmatch.CPE
	Range     vulnmatch.Range
	Condition *vulnmatch.CPE
	// Source is the advisory source of the statement: nvd (default), osv
	// or cve5.
	Source string
}

// PageResult says what one page changed.
type PageResult struct {
	Upserted      int
	RangesWritten int
	Skipped       int
}

// Store writes the corpus.
type Store interface {
	// EmptiedRanges is how many stored ranges the page would remove from
	// CVEs that keep no range although they were not rejected.
	EmptiedRanges(ctx context.Context, cves []CVE) (int, error)
	// ApplyPage writes one page in one transaction: each CVE that has
	// ranges or is already stored is upserted and its ranges replaced (a
	// rejected CVE keeps its record without ranges; a CVE with too many
	// statements keeps its old ranges); global products are created for
	// CPEs nothing resolves.
	ApplyPage(ctx context.Context, cves []CVE) (PageResult, error)
	// Counts reports the corpus size.
	Counts(ctx context.Context) (records, ranges int, err error)
}
