package core

import (
	"strings"

	"github.com/openctemio/ctis/fingerprint"
	"github.com/openctemio/ctis/severity"
)

// =============================================================================
// Fingerprint Generation (delegates to shared package)
// =============================================================================

// GenerateSastFingerprint creates a fingerprint for SAST/Secret findings.
// Deprecated: Use fingerprint.GenerateSAST from pkg/shared/fingerprint instead.
func GenerateSastFingerprint(file, ruleID string, startLine int) string {
	return fingerprint.GenerateSAST(file, ruleID, startLine, 0)
}

// GenerateScaFingerprint creates a fingerprint for SCA vulnerabilities.
// Deprecated: Use fingerprint.GenerateSCA from pkg/shared/fingerprint instead.
func GenerateScaFingerprint(pkgName, pkgVersion, vulnID string) string {
	return fingerprint.GenerateSCA(pkgName, pkgVersion, vulnID)
}

// GenerateSecretFingerprint creates a fingerprint for secret findings.
// Deprecated: Use fingerprint.GenerateSecret from pkg/shared/fingerprint instead.
func GenerateSecretFingerprint(file, ruleID string, startLine int, secretValue string) string {
	return fingerprint.GenerateSecret(file, ruleID, startLine, secretValue)
}

// =============================================================================
// CVSS Score Handling
// =============================================================================

// CVSSSource represents the source of CVSS data.
type CVSSSource string

const (
	CVSSSourceNVD     CVSSSource = "nvd"     // National Vulnerability Database
	CVSSSourceGHSA    CVSSSource = "ghsa"    // GitHub Security Advisory
	CVSSSourceRedHat  CVSSSource = "redhat"  // Red Hat
	CVSSSourceBitnami CVSSSource = "bitnami" // Bitnami
)

// CVSSData holds CVSS information from various sources.
type CVSSData struct {
	Source CVSSSource `json:"source"`
	Score  float64    `json:"score"`
	Vector string     `json:"vector"`
}

// CVSSPriority defines the priority order for CVSS sources.
// Higher priority sources are preferred.
var CVSSPriority = []CVSSSource{
	CVSSSourceNVD,     // Most authoritative
	CVSSSourceGHSA,    // Well-maintained
	CVSSSourceRedHat,  // Enterprise focused
	CVSSSourceBitnami, // Container focused
}

// SelectBestCVSS selects the best CVSS data from multiple sources.
// Uses priority order: NVD > GHSA > RedHat > Bitnami
func SelectBestCVSS(cvssMap map[CVSSSource]CVSSData) *CVSSData {
	for _, source := range CVSSPriority {
		if data, ok := cvssMap[source]; ok && data.Score > 0 {
			return &data
		}
	}
	return nil
}

// =============================================================================
// Severity Mapping (delegates to shared package)
// =============================================================================

// SeverityFromCVSS converts a CVSS score to severity level.
// Deprecated: Use severity.FromCVSS from pkg/shared/severity instead.
func SeverityFromCVSS(score float64) string {
	return severity.FromCVSS(score).String()
}

// NormalizeSeverity normalizes severity strings from different scanners.
// Deprecated: Use severity.FromString from pkg/shared/severity instead.
func NormalizeSeverity(sev string) string {
	return severity.FromString(sev).String()
}

// =============================================================================
// Package Type Detection
// =============================================================================

// PackageType represents the package ecosystem.
type PackageType string

const (
	PackageTypeMaven    PackageType = "maven"
	PackageTypeNPM      PackageType = "npm"
	PackageTypePyPI     PackageType = "pip"
	PackageTypeGo       PackageType = "gomod"
	PackageTypeCargo    PackageType = "cargo"
	PackageTypeNuGet    PackageType = "nuget"
	PackageTypeGem      PackageType = "gem"
	PackageTypeComposer PackageType = "composer"
)

// DetectPackageType detects the package type from a manifest file.
func DetectPackageType(filename string) PackageType {
	lower := strings.ToLower(filename)
	switch {
	case strings.Contains(lower, "pom.xml") || strings.Contains(lower, ".pom"):
		return PackageTypeMaven
	case strings.Contains(lower, "package.json") || strings.Contains(lower, "package-lock.json") || strings.Contains(lower, "yarn.lock"):
		return PackageTypeNPM
	case strings.Contains(lower, "requirements.txt") || strings.Contains(lower, "setup.py") || strings.Contains(lower, "pipfile") || strings.Contains(lower, "pyproject.toml"):
		return PackageTypePyPI
	case strings.Contains(lower, "go.mod") || strings.Contains(lower, "go.sum"):
		return PackageTypeGo
	case strings.Contains(lower, "cargo.toml") || strings.Contains(lower, "cargo.lock"):
		return PackageTypeCargo
	case strings.Contains(lower, ".csproj") || strings.Contains(lower, "packages.config") || strings.Contains(lower, ".nuspec"):
		return PackageTypeNuGet
	case strings.Contains(lower, "gemfile") || strings.Contains(lower, ".gemspec"):
		return PackageTypeGem
	case strings.Contains(lower, "composer.json") || strings.Contains(lower, "composer.lock"):
		return PackageTypeComposer
	default:
		return ""
	}
}

// =============================================================================
// Masking Utilities
// =============================================================================

// MaskSecret masks a secret value, showing only first and last few characters.
func MaskSecret(secret string) string {
	if len(secret) <= 8 {
		return "****"
	}
	return secret[:3] + "****" + secret[len(secret)-3:]
}

// MaskAPIKey masks an API key.
func MaskAPIKey(key string) string {
	if len(key) <= 10 {
		return "****"
	}
	return key[:4] + "..." + key[len(key)-4:]
}
