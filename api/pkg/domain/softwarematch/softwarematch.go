// Package softwarematch is the storage contract of the inventory
// vulnerability matcher (RFC-066 §7, §8): global per-version evaluation and
// the per-tenant fan-out into findings.
//
// Design: docs/rfcs/RFC-066-inventory-vulnerability-matching.md.
package softwarematch

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// ToolName is the reserved tool name of matcher findings. Ingest refuses it
// from any report, so only the matcher writes findings under it.
const ToolName = "version-match"

// StaleAfter is how long a software link counts as current without being
// seen again (RFC-066 §8: not seen for 30 days → not_observed).
const StaleAfter = 30 * 24 * time.Hour

// Version is a global catalog version waiting for evaluation.
type Version struct {
	ID        shared.ID
	ProductID shared.ID
	Raw       string
	Scheme    vulnmatch.Scheme
	Edition   string
}

// AffectedRange is one stored range; Range.ID is the row id as text and
// Range.Condition the condition product id as text.
type AffectedRange struct {
	ID    int64
	Range vulnmatch.Range
}

// VersionVuln is one version × CVE result.
type VersionVuln struct {
	CVEID              string
	AffectedID         int64
	RangeText          string
	AllVersions        bool
	Adjustment         int
	Reasons            []string
	ConditionProductID *shared.ID
}

// Match is one active software link of a tenant joined with a CVE its
// version falls in, and what the policy needs to decide.
type Match struct {
	AssetID        shared.ID
	InternetFacing bool
	LinkConfidence int
	Location       string
	Port           int
	Transport      string
	Evidence       string
	ProductID      shared.ID
	Product        string
	Vendor         string
	VersionID      shared.ID
	Version        string
	Qualifier      string
	Result         VersionVuln
	ConditionMet   bool
	CVE            CVEInfo
}

// CVEInfo is the corpus data a finding carries.
type CVEInfo struct {
	ID          string
	Description string
	Severity    string
	CVSSScore   *float64
	CVSSVector  string
	CWEs        []string
	InKEV       bool
	EPSS        float64
}

// MatcherFinding is a finding the matcher owns: created by it and never
// reported by a scanner.
type MatcherFinding struct {
	ID          shared.ID
	AssetID     shared.ID
	CVEID       string
	Fingerprint string
	Status      string
	ProductID   *shared.ID
	VersionID   *shared.ID
	Location    string
	CVERejected bool
}

// LinkState says what happened to the software a matcher finding was built
// on.
type LinkState int

const (
	// LinkCurrent: the same version is still linked and current.
	LinkCurrent LinkState = iota
	// LinkUpgraded: another version of the product is current at the location.
	LinkUpgraded
	// LinkGone: nothing current at the location for the product.
	LinkGone
)

// LinkKey identifies the software of a matcher finding.
type LinkKey struct {
	AssetID   shared.ID
	ProductID shared.ID
	VersionID shared.ID
	Location  string
}

// LinkInfo is the state of one LinkKey.
type LinkInfo struct {
	State LinkState
	// VersionEvaluated: the version has been evaluated against the current
	// ranges (its matches are up to date).
	VersionEvaluated bool
}

// CloseKind is why the matcher closes a finding.
type CloseKind string

// Close kinds (RFC-066 §8).
const (
	CloseVersionChanged  CloseKind = "version_changed"
	CloseNotObserved     CloseKind = "not_observed"
	CloseAdvisoryUpdated CloseKind = "advisory_updated"
)

// Store is the matcher's storage. Version methods touch global rows only;
// every tenant method is scoped to that tenant.
type Store interface {
	// PendingVersions returns global versions not evaluated since they were
	// created or since their ranges changed.
	PendingVersions(ctx context.Context, limit int) ([]Version, error)
	// RangesForProduct returns the stored ranges of a product.
	RangesForProduct(ctx context.Context, productID shared.ID) ([]AffectedRange, error)
	// ReplaceVersionVulns stores the results of one version and marks it
	// evaluated. When the set of CVEs changed it queues every tenant that
	// links the version, and reports changed.
	ReplaceVersionVulns(ctx context.Context, versionID shared.ID, vulns []VersionVuln) (changed bool, err error)
	// ResetVersionsForCVEsSince marks for re-evaluation the versions of the
	// products named by CVEs synced after since (and those that matched
	// them), up to limit CVEs; it returns the new cursor.
	ResetVersionsForCVEsSince(ctx context.Context, since time.Time, limit int) (cursor time.Time, n int, err error)
	// State reads and writes the matcher's cursors.
	State(ctx context.Context, name string) (time.Time, error)
	SetState(ctx context.Context, name string, at time.Time) error

	// QueueTenants asks for a reconcile of these tenants.
	QueueTenants(ctx context.Context, tenantIDs []shared.ID) error
	// QueueAllTenantsWithSoftware queues every tenant that has software.
	QueueAllTenantsWithSoftware(ctx context.Context) (int, error)
	// DequeueTenants takes up to limit queued tenants.
	DequeueTenants(ctx context.Context, limit int) ([]shared.ID, error)

	// TenantMatches returns the tenant's current links (seen since
	// currentSince, not superseded) joined with their versions' matches.
	TenantMatches(ctx context.Context, tenantID shared.ID, currentSince time.Time, limit int) ([]Match, error)
	// AssetMatches is TenantMatches for one asset, whatever the link's age.
	AssetMatches(ctx context.Context, tenantID, assetID shared.ID) ([]Match, error)
	// MatcherFindings returns the tenant's matcher-owned findings.
	MatcherFindings(ctx context.Context, tenantID shared.ID) ([]MatcherFinding, error)
	// OpenCVEsOnAssets returns, per asset, the CVEs of its open findings
	// (any tool).
	OpenCVEsOnAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]map[string]bool, error)
	// ExistingFingerprints returns which of the fingerprints any finding of
	// the tenant already has (any tool, any status).
	ExistingFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]bool, error)
	// LinkStates resolves the state of the software of matcher findings.
	LinkStates(ctx context.Context, tenantID shared.ID, keys []LinkKey, currentSince time.Time) (map[LinkKey]LinkInfo, error)
	// CloseFindings closes open matcher-owned findings of the tenant.
	CloseFindings(ctx context.Context, tenantID shared.ID, ids []shared.ID, kind CloseKind) ([]shared.ID, error)
	// ReopenFindings reopens matcher-owned findings the matcher had closed.
	ReopenFindings(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]shared.ID, error)
	// EnsureDefinitions makes sure each CVE has its global catalog row and
	// returns the row ids.
	EnsureDefinitions(ctx context.Context, cves []CVEInfo) (map[string]shared.ID, error)
}
