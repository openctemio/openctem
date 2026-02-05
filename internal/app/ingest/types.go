// Package ingest provides unified ingestion of assets and findings from various formats.
package ingest

import (
	"github.com/openctemio/sdk/pkg/eis"
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

	// MaxTagsPerAsset is the maximum number of tags per asset.
	MaxTagsPerAsset = 50

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
// All formats (EIS, SARIF, Recon, etc.) are converted to this via adapters.
type Input struct {
	Report *eis.Report

	// CoverageType indicates the scan coverage level.
	// Auto-resolve is only enabled for full scans on default branch.
	// Default is empty, which disables auto-resolve for safety.
	CoverageType CoverageType

	// BranchInfo provides git branch context for branch-aware lifecycle.
	// Auto-resolve only applies when IsDefaultBranch=true and CoverageType=full.
	// If nil, branch info is read from Report.Metadata.Branch.
	BranchInfo *eis.BranchInfo
}

// GetBranchInfo returns branch info from Input or Report metadata.
// Input.BranchInfo takes precedence over Report.Metadata.Branch.
func (i Input) GetBranchInfo() *eis.BranchInfo {
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

// Output represents the result of ingestion.
type Output struct {
	ReportID             string   `json:"report_id"`
	AssetsCreated        int      `json:"assets_created"`
	AssetsUpdated        int      `json:"assets_updated"`
	FindingsCreated      int      `json:"findings_created"`
	FindingsUpdated      int      `json:"findings_updated"`
	FindingsSkipped      int      `json:"findings_skipped"`
	FindingsAutoResolved int      `json:"findings_auto_resolved,omitempty"`
	FindingsAutoReopened int      `json:"findings_auto_reopened,omitempty"`
	ComponentsCreated    int      `json:"components_created,omitempty"`
	ComponentsUpdated    int      `json:"components_updated,omitempty"`
	DependenciesLinked   int      `json:"dependencies_linked,omitempty"`
	LicensesDiscovered   int      `json:"licenses_discovered,omitempty"`
	LicensesLinked       int      `json:"licenses_linked,omitempty"`
	Errors               []string `json:"errors,omitempty"`
	Warnings             []string `json:"warnings,omitempty"`

	// FailedFindings contains detailed info about findings that failed to save.
	// This is used for audit logging and debugging purposes.
	FailedFindings []FailedFinding `json:"-"` // Not exposed in API response
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
