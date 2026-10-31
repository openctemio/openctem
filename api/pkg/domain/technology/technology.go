// Package technology is the Technologies view of the external attack
// surface: the technologies detected on the organization's assets, one row
// per technology and version, with how many assets run it and what the CVE
// corpus knows about that version. It reads asset_technologies through the
// list query contract (docs/architecture/list-query-contract.md); nothing
// is stored here.
package technology

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Version is one technology at one version (an empty Version is a version
// the tools could not tell) across the assets the caller may see.
type Version struct {
	// Key is the normalised name; Name the most common spelling of it.
	Key     string
	Name    string
	Version string
	// Category is the most common category of the rows.
	Category string
	// Vendor and CPE are what a tool reported, or else the vendor of the
	// software product the technology was matched to; "" when unknown.
	Vendor string
	CPE    string
	// Sources are the tools that detected it.
	Sources []string
	// AssetCount is how many visible assets run this version.
	AssetCount int64
	// CVECount is how many CVEs of the corpus affect the matched software
	// version; TopCVE and TopCVSS the highest scored of them.
	CVECount int64
	TopCVE   string
	TopCVSS  *float64
	// KEV is true when one of those CVEs is in the known-exploited catalog;
	// Exploit when one has a public exploit (or is in KEV).
	KEV     bool
	Exploit bool
	// ActiveAlerts counts the open emerging-threat alerts about those CVEs
	// on the visible assets that run this version.
	ActiveAlerts int64
	FirstSeen    time.Time
	LastSeen     time.Time
}

// Stats counts one filtered set of technology versions.
type Stats struct {
	Total          int64 `json:"total"`
	WithCVEs       int64 `json:"with_cves"`
	KEV            int64 `json:"kev"`
	UnknownVersion int64 `json:"unknown_version"`
	WithAlerts     int64 `json:"with_alerts"`
}

// Reader is the read side. Both take a filter compiled for the caller
// (tenant and data scope included).
type Reader interface {
	ListWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*Version], error)
	StatsWhere(ctx context.Context, w *filterspec.Where) (*Stats, error)
}
