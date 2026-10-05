// Package ingest provides unified ingestion of assets and findings from various formats.
package ingest

import (
	"context"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// =============================================================================
// Constants & Limits
// =============================================================================

const (
	// MaxAssetsPerReport is the maximum number of assets allowed in a single report.
	MaxAssetsPerReport = 100000

	// MaxFindingsPerReport is the maximum number of findings allowed in a single report.
	MaxFindingsPerReport = 100000

	// MaxPropertySize is the maximum size of a single property value in bytes.
	MaxPropertySize = 1024 * 1024 // 1MB

	// MaxPropertiesPerAsset is the maximum number of properties per asset.
	MaxPropertiesPerAsset = 100

	// MaxTagsPerAsset is the maximum number of tags per asset: the one limit
	// the domain, the API and the web share.
	MaxTagsPerAsset = asset.MaxTagsPerAsset

	// MaxErrorsToReturn limits the number of errors returned in the response.
	MaxErrorsToReturn = 100

	// BatchSize for database operations.
	BatchSize = 500

	// UnknownValue is used as a fallback when a required field is empty.
	UnknownValue = "unknown"
)

// =============================================================================
// Input/Output Types
// =============================================================================

// CoverageType indicates the scan coverage level.
type CoverageType string

const (
	// CoverageTypeFull indicates a full scan that covers the entire codebase.
	// Auto-resolve is only enabled for full scans.
	CoverageTypeFull CoverageType = "full"

	// CoverageTypeIncremental indicates an incremental/diff scan covering only changed files.
	// Auto-resolve is disabled for incremental scans to prevent false auto-resolution.
	CoverageTypeIncremental CoverageType = "incremental"

	// CoverageTypePartial indicates a partial scan (e.g., specific directories).
	// Auto-resolve is disabled for partial scans.
	CoverageTypePartial CoverageType = "partial"
)

// Input represents the unified input for ingestion.
// All formats (CTIS, SARIF, Recon, etc.) are converted to this via adapters.
type Input struct {
	Report *ctis.Report

	// CoverageType indicates the scan coverage level.
	// Auto-resolve is only enabled for full scans on default branch.
	// Default is empty, which disables auto-resolve for safety.
	CoverageType CoverageType

	// BranchInfo provides git branch context for branch-aware lifecycle.
	// Auto-resolve only applies when IsDefaultBranch=true and CoverageType=full.
	// If nil, branch info is read from Report.Metadata.Branch.
	BranchInfo *ctis.BranchInfo

	// Options are the protocol v2 ingest rules (RFC-026 §5). The zero value
	// is protocol v1 behavior.
	Options Options
}

// Options are the protocol v2 ingest rules (RFC-026 §5,
// docs/rfcs/RFC-026-sensor-results-ingest.md). Each is off in the zero value,
// so v1 ingest is unchanged.
type Options struct {
	// RequireAssetForFindings: no fallback asset. A report with findings but
	// no assets gets no asset made up from its metadata, and a finding is
	// attached only to the asset its asset_ref names, never to "the only
	// asset in the report" when that reference did not resolve.
	RequireAssetForFindings bool
	// NoCatalogWrites: the global vulnerability catalog is read, never
	// written. Findings link to catalog entries that exist; the sensor's CVE
	// text stays on the tenant's finding.
	NoCatalogWrites bool
	// DeferAutoResolve: no auto-resolve during ingest. A v2 report resolves
	// stale findings once, when it is committed (Service.CommitV2Report).
	DeferAutoResolve bool
	// DeferSensorStats: the sensor's totals are not updated per ingest. A v2
	// report counts once, as one scan, when it completes (it may arrive in
	// many segments).
	DeferSensorStats bool
	// Binding is the authority behind the report (RFC-040 §5.3). The zero
	// value is an unsolicited sensor report: it never changes an existing
	// asset and never reopens a finding a person resolved.
	Binding Binding
	// Admitted: the accept side already ran the unsolicited-results gate
	// (quarantine or warn) for this report, so Ingest does not run it again.
	Admitted bool
	// Route names the ingest route for a quarantined report (ctis, sarif,
	// recon, scan, chunk).
	Route string
	// Actor, when set, limits an ingest a person started (an upload) to the
	// assets that person may change: an existing asset outside it is not
	// touched at all (not even marked seen), a host the report names that
	// is not an existing in-scope asset is not created, and the findings of
	// both are skipped. Both cases count as AssetsSkippedOutOfScope, so the
	// response does not tell a hidden asset from a missing one. Nil means
	// unrestricted.
	Actor ActorScope
}

// ActorScope is the data scope of the person behind an upload.
type ActorScope interface {
	// AssetsInScope returns the subset of assetIDs the actor may change.
	AssetsInScope(ctx context.Context, assetIDs []shared.ID) ([]shared.ID, error)
}

// GetBranchInfo returns branch info from Input or Report metadata.
// Input.BranchInfo takes precedence over Report.Metadata.Branch.
func (i Input) GetBranchInfo() *ctis.BranchInfo {
	if i.BranchInfo != nil {
		return i.BranchInfo
	}
	if i.Report != nil && i.Report.Metadata.Branch != nil {
		return i.Report.Metadata.Branch
	}
	return nil
}

// IsDefaultBranchScan returns true if this is a scan on the default branch.
func (i Input) IsDefaultBranchScan() bool {
	branch := i.GetBranchInfo()
	return branch != nil && branch.IsDefaultBranch
}

// ShouldAutoResolve returns true if auto-resolve should be enabled for this scan.
// Conditions: CoverageType=full AND scanning default branch.
func (i Input) ShouldAutoResolve() bool {
	coverageType := i.CoverageType
	if coverageType == "" && i.Report != nil && i.Report.Metadata.CoverageType != "" {
		coverageType = CoverageType(i.Report.Metadata.CoverageType)
	}
	return coverageType == CoverageTypeFull && i.IsDefaultBranchScan()
}

// IsFullCoverage reports whether this is a full scan (covers the whole codebase),
// regardless of which branch it ran on. Used to gate per-branch occurrence
// auto-resolve: only a full scan can conclude that a no-longer-reported finding
// is actually gone from that branch (an incremental/partial scan cannot).
func (i Input) IsFullCoverage() bool {
	coverageType := i.CoverageType
	if coverageType == "" && i.Report != nil && i.Report.Metadata.CoverageType != "" {
		coverageType = CoverageType(i.Report.Metadata.CoverageType)
	}
	return coverageType == CoverageTypeFull
}

// Output represents the result of ingestion.
type Output struct {
	ReportID      string `json:"report_id"`
	AssetsCreated int    `json:"assets_created"`
	AssetsUpdated int    `json:"assets_updated"`
	// AssetsSkippedExcluded counts new assets not added because they match
	// an active scope exclusion (RFC-042 F16).
	AssetsSkippedExcluded int `json:"assets_skipped_excluded,omitempty"`
	// AssetsSkippedOutOfScope counts report assets an upload's actor may not
	// change (Options.Actor): existing assets outside their data scope and
	// hosts that would have been new. Their findings are skipped.
	AssetsSkippedOutOfScope int `json:"assets_skipped_out_of_scope,omitempty"`
	FindingsCreated         int `json:"findings_created"`
	FindingsUpdated         int `json:"findings_updated"`
	FindingsSkipped         int `json:"findings_skipped"`
	FindingsAutoResolved    int `json:"findings_auto_resolved,omitempty"`
	FindingsAutoReopened    int `json:"findings_auto_reopened,omitempty"`
	// FindingsSourceResolved counts open findings resolved because their
	// source reported them mitigated (Tenable.sc, RFC-047); in dry_run mode
	// FindingsSourceWouldResolve counts them instead.
	FindingsSourceResolved     int `json:"findings_source_resolved,omitempty"`
	FindingsSourceWouldResolve int `json:"findings_source_would_resolve,omitempty"`
	// FindingsSourceMitigated counts the report's findings its source said
	// are mitigated; they are never created or updated as sightings.
	FindingsSourceMitigated int `json:"findings_source_mitigated,omitempty"`
	// SourceResolveIDs are the findings source-asserted resolve closed (or,
	// in dry_run, would close); SourceResolveMode is the mode it ran in.
	SourceResolveIDs   []shared.ID       `json:"-"`
	SourceResolveMode  SourceResolveMode `json:"-"`
	FindingsSuppressed int               `json:"findings_suppressed,omitempty"`
	ComponentsCreated  int               `json:"components_created,omitempty"`
	ComponentsUpdated  int               `json:"components_updated,omitempty"`
	DependenciesLinked int               `json:"dependencies_linked,omitempty"`
	LicensesDiscovered int               `json:"licenses_discovered,omitempty"`
	LicensesLinked     int               `json:"licenses_linked,omitempty"`
	CVEsCreated        int               `json:"cves_created,omitempty"`
	CVEsUpdated        int               `json:"cves_updated,omitempty"`
	Errors             []string          `json:"errors,omitempty"`
	Warnings           []string          `json:"warnings,omitempty"`

	// Binding is the authority the report was applied under: command,
	// unsolicited or trusted (RFC-040 §5.3).
	Binding string `json:"binding,omitempty"`
	// AssetsLimited counts existing assets the report matched but was not
	// allowed to change (no command covering them): they were only marked
	// seen, and only while active.
	AssetsLimited int `json:"assets_limited,omitempty"`
	// ReopensWithheld counts re-detected findings a person had resolved that
	// were left resolved because no command covering their asset stood
	// behind the report.
	ReopensWithheld int `json:"reopens_withheld,omitempty"`
	// UnsolicitedWarned: an unsolicited report from a sensor whose role may
	// not push results on its own, applied because the tenant's mode is
	// "warn"; in "quarantine" mode it would have been held for review.
	UnsolicitedWarned bool `json:"unsolicited_warned,omitempty"`

	// FailedFindings contains detailed info about findings that failed to save.
	// This is used for audit logging and debugging purposes.
	FailedFindings []FailedFinding `json:"-"` // Not exposed in API response

	// AssetMap maps each CTIS asset id of the report to the persisted asset
	// it was merged into. Not exposed; v2 derives per-item outcomes from it.
	AssetMap map[string]shared.ID `json:"-"`

	// ExcludedAssetRefs are the CTIS asset ids of the report that were not
	// added because they match a scope exclusion. Their findings are skipped,
	// never attached to another asset of the report.
	ExcludedAssetRefs map[string]bool `json:"-"`

	// OutOfScopeAssetRefs are the CTIS asset ids of the report skipped
	// because the upload's actor may not change them (Options.Actor). Their
	// findings are skipped, never attached to another asset of the report.
	OutOfScopeAssetRefs map[string]bool `json:"-"`
}

// FailedFinding contains details about a finding that failed during ingestion.
// This provides debugging context for audit logs.
type FailedFinding struct {
	Index       int    `json:"index"`       // Index in the original report
	Fingerprint string `json:"fingerprint"` // Finding fingerprint
	RuleID      string `json:"rule_id"`     // Rule/check ID
	FilePath    string `json:"file_path"`   // File path if available
	Line        int    `json:"line"`        // Line number if available
	Error       string `json:"error"`       // Error message
}

// CheckFingerprintsInput is the input for fingerprint checking.
type CheckFingerprintsInput struct {
	Fingerprints []string `json:"fingerprints"`
}

// CheckFingerprintsOutput is the result of fingerprint checking.
type CheckFingerprintsOutput struct {
	Existing []string `json:"existing"`
	Missing  []string `json:"missing"`
}

// BaselineDiffInput asks which of the given fingerprints are NEW relative to a PR's
// base/target branch — i.e. not already present (open) on that branch.
type BaselineDiffInput struct {
	// Repository is the repository asset name (e.g. "owner/repo").
	Repository string `json:"repository"`
	// BaseBranch is the PR/MR target branch (e.g. "main").
	BaseBranch string `json:"base_branch"`
	// Fingerprints are the findings from the current (source-branch) scan.
	Fingerprints []string `json:"fingerprints"`
}

// BaselineDiffOutput reports which fingerprints are new vs the base branch.
type BaselineDiffOutput struct {
	// New are fingerprints NOT already open on the base branch (introduced by the PR).
	New []string `json:"new_fingerprints"`
	// PreExisting are fingerprints already open on the base branch (tech debt).
	PreExisting []string `json:"pre_existing_fingerprints"`
	// BaseBranchKnown is false when the base branch has no scan history yet
	// (then everything is treated as new).
	BaseBranchKnown bool `json:"base_branch_scanned"`
}
