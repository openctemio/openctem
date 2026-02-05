// Package validator provides struct validation utilities with custom validators.
package validator

import (
	stderrors "errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/assetgroup"
	"github.com/openctemio/api/pkg/domain/branch"
	"github.com/openctemio/api/pkg/domain/component"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// slugRegex validates slugs: lowercase letters, numbers, hyphens
// Must start and end with alphanumeric, no consecutive hyphens
var slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// cveIDRegex validates CVE IDs: CVE-YYYY-NNNNN (4+ digits)
var cveIDRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// Validator wraps the go-playground validator with custom validations.
type Validator struct {
	validate *validator.Validate
}

// ValidationError represents a single field validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors []ValidationError

// Error implements the error interface.
func (v ValidationErrors) Error() string {
	if len(v) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, e := range v {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(fmt.Sprintf("%s: %s", e.Field, e.Message))
	}
	return sb.String()
}

// New creates a new Validator with custom validators registered.
func New() *Validator {
	v := validator.New(validator.WithRequiredStructEnabled())

	// Register custom validators for asset domain
	_ = v.RegisterValidation("asset_type", validateAssetType)
	_ = v.RegisterValidation("criticality", validateCriticality)
	_ = v.RegisterValidation("status", validateStatus)
	_ = v.RegisterValidation("scope", validateScope)
	_ = v.RegisterValidation("exposure", validateExposure)

	// Register custom validators for repository/SCM (now part of asset domain)
	_ = v.RegisterValidation("scm_provider", validateSCMProvider)
	_ = v.RegisterValidation("repo_visibility", validateRepoVisibility)

	// Register custom validators for tenant domain
	_ = v.RegisterValidation("slug", validateSlug)

	// Register custom validators for vulnerability domain
	_ = v.RegisterValidation("severity", validateSeverity)
	_ = v.RegisterValidation("finding_status", validateFindingStatus)
	_ = v.RegisterValidation("finding_source", validateFindingSource)
	_ = v.RegisterValidation("exploit_maturity", validateExploitMaturity)
	_ = v.RegisterValidation("vulnerability_status", validateVulnerabilityStatus)
	_ = v.RegisterValidation("cve_id", validateCVEID)

	// Register custom validators for component domain
	_ = v.RegisterValidation("ecosystem", validateEcosystem)
	_ = v.RegisterValidation("dependency_type", validateDependencyType)
	_ = v.RegisterValidation("component_status", validateComponentStatus)

	// Register custom validators for branch domain
	_ = v.RegisterValidation("branch_type", validateBranchType)
	_ = v.RegisterValidation("scan_status", validateScanStatus)
	_ = v.RegisterValidation("quality_gate_status", validateQualityGateStatus)

	// Register custom validators for asset group domain
	_ = v.RegisterValidation("asset_group_environment", validateAssetGroupEnvironment)
	_ = v.RegisterValidation("asset_group_criticality", validateAssetGroupCriticality)

	return &Validator{validate: v}
}

// Validate validates a struct and returns ValidationErrors if validation fails.
func (v *Validator) Validate(s interface{}) error {
	err := v.validate.Struct(s)
	if err == nil {
		return nil
	}

	var validationErrors validator.ValidationErrors
	if !stderrors.As(err, &validationErrors) {
		return err
	}

	result := make(ValidationErrors, 0, len(validationErrors))
	for _, e := range validationErrors {
		result = append(result, ValidationError{
			Field:   toSnakeCase(e.Field()),
			Message: formatErrorMessage(e),
		})
	}

	return result
}

// validateAssetType validates that a string is a valid AssetType.
func validateAssetType(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := asset.ParseAssetType(value)
	return err == nil
}

// validateCriticality validates that a string is a valid Criticality.
func validateCriticality(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := asset.ParseCriticality(value)
	return err == nil
}

// validateStatus validates that a string is a valid Status.
func validateStatus(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := asset.ParseStatus(value)
	return err == nil
}

// validateScope validates that a string is a valid Scope.
func validateScope(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := asset.ParseScope(value)
	return err == nil
}

// validateExposure validates that a string is a valid Exposure.
func validateExposure(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := asset.ParseExposure(value)
	return err == nil
}

// validateSCMProvider validates that a string is a valid SCM Provider.
func validateSCMProvider(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	p := asset.ParseProvider(value)
	return p.IsSCM()
}

// validateRepoVisibility validates that a string is a valid repository Visibility.
func validateRepoVisibility(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	// Check the exact input value, not the parsed result (Parse defaults unknown to "private")
	switch value {
	case "public", "private", "internal":
		return true
	default:
		return false
	}
}

// validateSlug validates that a string is a valid URL slug.
// Valid: lowercase letters, numbers, hyphens. Must start/end with alphanumeric.
// Examples: "my-team", "acme-corp", "team123"
func validateSlug(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	return slugRegex.MatchString(value)
}

// validateSeverity validates that a string is a valid vulnerability Severity.
func validateSeverity(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := vulnerability.ParseSeverity(value)
	return err == nil
}

// validateFindingStatus validates that a string is a valid FindingStatus.
func validateFindingStatus(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := vulnerability.ParseFindingStatus(value)
	return err == nil
}

// validateFindingSource validates that a string is a valid FindingSource.
func validateFindingSource(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := vulnerability.ParseFindingSource(value)
	return err == nil
}

// validateExploitMaturity validates that a string is a valid ExploitMaturity.
func validateExploitMaturity(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	em := vulnerability.ExploitMaturity(strings.ToLower(strings.TrimSpace(value)))
	return em.IsValid()
}

// validateVulnerabilityStatus validates that a string is a valid VulnerabilityStatus.
func validateVulnerabilityStatus(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	vs := vulnerability.VulnerabilityStatus(strings.ToLower(strings.TrimSpace(value)))
	return vs.IsValid()
}

// validateCVEID validates that a string is a valid CVE ID (CVE-YYYY-NNNNN).
func validateCVEID(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	return cveIDRegex.MatchString(strings.ToUpper(value))
}

// validateEcosystem validates that a string is a valid component Ecosystem.
func validateEcosystem(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := component.ParseEcosystem(value)
	return err == nil
}

// validateDependencyType validates that a string is a valid DependencyType.
func validateDependencyType(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := component.ParseDependencyType(value)
	return err == nil
}

// validateComponentStatus validates that a string is a valid component Status.
func validateComponentStatus(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := component.ParseStatus(value)
	return err == nil
}

// validateBranchType validates that a string is a valid branch Type.
func validateBranchType(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	bt := branch.ParseType(value)
	return bt != ""
}

// validateScanStatus validates that a string is a valid ScanStatus.
func validateScanStatus(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	ss := branch.ParseScanStatus(value)
	return ss != ""
}

// validateQualityGateStatus validates that a string is a valid QualityGateStatus.
func validateQualityGateStatus(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	qgs := branch.ParseQualityGateStatus(value)
	return qgs != ""
}

// validateAssetGroupEnvironment validates that a string is a valid asset group Environment.
func validateAssetGroupEnvironment(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, ok := assetgroup.ParseEnvironment(value)
	return ok
}

// validateAssetGroupCriticality validates that a string is a valid asset group Criticality.
func validateAssetGroupCriticality(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, ok := assetgroup.ParseCriticality(value)
	return ok
}

// formatErrorMessage converts validation errors to human-readable messages.
func formatErrorMessage(e validator.FieldError) string {
	switch e.Tag() {
	case "required":
		return "is required"
	case "min":
		return fmt.Sprintf("must be at least %s characters", e.Param())
	case "max":
		return fmt.Sprintf("must be at most %s characters", e.Param())
	case "email":
		return "must be a valid email address"
	case "url":
		return "must be a valid URL"
	case "asset_type":
		return fmt.Sprintf("must be one of: %s", formatAssetTypes())
	case "criticality":
		return fmt.Sprintf("must be one of: %s", formatCriticalities())
	case "status":
		return fmt.Sprintf("must be one of: %s", formatStatuses())
	case "scm_provider":
		return fmt.Sprintf("must be one of: %s", formatSCMProviders())
	case "repo_visibility":
		return "must be one of: public, private, internal"
	case "severity":
		return fmt.Sprintf("must be one of: %s", formatSeverities())
	case "finding_status":
		return fmt.Sprintf("must be one of: %s", formatFindingStatuses())
	case "finding_source":
		return fmt.Sprintf("must be one of: %s", formatFindingSources())
	case "exploit_maturity":
		return "must be one of: none, poc, functional, weaponized"
	case "vulnerability_status":
		return "must be one of: open, patched, mitigated, not_affected"
	case "cve_id":
		return "must be a valid CVE ID (e.g., CVE-2024-12345)"
	case "ecosystem":
		return fmt.Sprintf("must be one of: %s", formatEcosystems())
	case "dependency_type":
		return "must be one of: direct, transitive, dev, peer, optional"
	case "component_status":
		return fmt.Sprintf("must be one of: %s", formatComponentStatuses())
	case "branch_type":
		return "must be one of: default, feature, release, hotfix, develop, main"
	case "scan_status":
		return "must be one of: pending, running, completed, failed, canceled"
	case "quality_gate_status":
		return "must be one of: passed, failed, warning, unknown"
	case "asset_group_environment":
		return "must be one of: production, staging, development, testing"
	case "asset_group_criticality":
		return "must be one of: critical, high, medium, low"
	case "oneof":
		return fmt.Sprintf("must be one of: %s", e.Param())
	case "uuid":
		return "must be a valid UUID"
	case "slug":
		return "must be a valid slug (lowercase letters, numbers, hyphens only)"
	default:
		return fmt.Sprintf("failed on '%s' validation", e.Tag())
	}
}

// toSnakeCase converts PascalCase/camelCase to snake_case.
func toSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteByte('_')
		}
		result.WriteRune(r)
	}
	return strings.ToLower(result.String())
}

// formatAssetTypes returns a comma-separated list of valid asset types.
func formatAssetTypes() string {
	types := asset.AllAssetTypes()
	strs := make([]string, len(types))
	for i, t := range types {
		strs[i] = string(t)
	}
	return strings.Join(strs, ", ")
}

// formatCriticalities returns a comma-separated list of valid criticalities.
func formatCriticalities() string {
	criticalities := asset.AllCriticalities()
	strs := make([]string, len(criticalities))
	for i, c := range criticalities {
		strs[i] = string(c)
	}
	return strings.Join(strs, ", ")
}

// formatStatuses returns a comma-separated list of valid statuses.
func formatStatuses() string {
	statuses := asset.AllStatuses()
	strs := make([]string, len(statuses))
	for i, s := range statuses {
		strs[i] = string(s)
	}
	return strings.Join(strs, ", ")
}

// formatSCMProviders returns a comma-separated list of valid SCM providers.
func formatSCMProviders() string {
	// Only SCM providers
	providers := []asset.Provider{
		asset.ProviderGitHub,
		asset.ProviderGitLab,
		asset.ProviderBitbucket,
		asset.ProviderAzureDevOps,
	}
	strs := make([]string, len(providers))
	for i, p := range providers {
		strs[i] = string(p)
	}
	return strings.Join(strs, ", ")
}

// formatSeverities returns a comma-separated list of valid severities.
func formatSeverities() string {
	severities := vulnerability.AllSeverities()
	strs := make([]string, len(severities))
	for i, s := range severities {
		strs[i] = string(s)
	}
	return strings.Join(strs, ", ")
}

// formatFindingStatuses returns a comma-separated list of valid finding statuses.
func formatFindingStatuses() string {
	statuses := vulnerability.AllFindingStatuses()
	strs := make([]string, len(statuses))
	for i, s := range statuses {
		strs[i] = string(s)
	}
	return strings.Join(strs, ", ")
}

// formatFindingSources returns a comma-separated list of valid finding sources.
func formatFindingSources() string {
	sources := vulnerability.AllFindingSources()
	strs := make([]string, len(sources))
	for i, s := range sources {
		strs[i] = string(s)
	}
	return strings.Join(strs, ", ")
}

// formatEcosystems returns a comma-separated list of valid ecosystems.
func formatEcosystems() string {
	ecosystems := component.AllEcosystems()
	strs := make([]string, len(ecosystems))
	for i, e := range ecosystems {
		strs[i] = string(e)
	}
	return strings.Join(strs, ", ")
}

// formatComponentStatuses returns a comma-separated list of valid component statuses.
func formatComponentStatuses() string {
	statuses := component.AllStatuses()
	strs := make([]string, len(statuses))
	for i, s := range statuses {
		strs[i] = string(s)
	}
	return strings.Join(strs, ", ")
}
