package asset

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// RepoVisibility represents the visibility of a repository.
type RepoVisibility string

const (
	VisibilityPublic   RepoVisibility = "public"
	VisibilityPrivate  RepoVisibility = "private"
	VisibilityInternal RepoVisibility = "internal"

	// Aliases for backward compatibility
	RepoVisibilityPublic   = VisibilityPublic
	RepoVisibilityPrivate  = VisibilityPrivate
	RepoVisibilityInternal = VisibilityInternal
)

// ParseRepoVisibility parses a string into a RepoVisibility.
func ParseRepoVisibility(s string) RepoVisibility {
	switch s {
	case "public":
		return VisibilityPublic
	case "private":
		return VisibilityPrivate
	case "internal":
		return VisibilityInternal
	default:
		return VisibilityPrivate
	}
}

// String returns the string representation.
func (v RepoVisibility) String() string {
	return string(v)
}

// IsValid checks if the visibility is valid.
func (v RepoVisibility) IsValid() bool {
	return v == VisibilityPublic || v == VisibilityPrivate || v == VisibilityInternal
}

// RepositoryExtension represents the extension data for repository assets.
// This is linked 1:1 with an Asset of type "repository".
type RepositoryExtension struct {
	assetID shared.ID // FK to assets.id

	// RepositoryExtension identification
	repoID   string // External repo ID from provider
	fullName string // owner/repo format

	// SCM info
	scmOrganization string
	cloneURL        string
	webURL          string
	sshURL          string

	// RepositoryExtension settings
	defaultBranch string
	visibility    RepoVisibility

	// Language & tech
	language  string
	languages map[string]int64 // {"Go": 45000, "TypeScript": 30000}
	topics    []string

	// RepositoryExtension stats
	stars             int
	forks             int
	watchers          int
	openIssues        int
	contributorsCount int
	sizeKB            int

	// Security stats (cached)
	findingCount int
	riskScore    float64

	// Scan configuration
	scanEnabled   bool
	scanSchedule  string // cron expression
	lastScannedAt *time.Time

	// Branch stats (cached)
	branchCount          int
	protectedBranchCount int

	// Component stats (cached)
	componentCount           int
	vulnerableComponentCount int

	// Timestamps from external system
	repoCreatedAt *time.Time
	repoUpdatedAt *time.Time
	repoPushedAt  *time.Time
}

// NewRepositoryExtension creates a new RepositoryExtension extension.
func NewRepositoryExtension(assetID shared.ID, fullName string, visibility RepoVisibility) (*RepositoryExtension, error) {
	if assetID.IsZero() {
		return nil, fmt.Errorf("%w: asset ID is required", shared.ErrValidation)
	}
	if fullName == "" {
		return nil, fmt.Errorf("%w: full name is required", shared.ErrValidation)
	}
	if !visibility.IsValid() {
		visibility = VisibilityPrivate
	}

	return &RepositoryExtension{
		assetID:       assetID,
		fullName:      fullName,
		visibility:    visibility,
		defaultBranch: "main",
		languages:     make(map[string]int64),
		topics:        make([]string, 0),
		scanEnabled:   true,
	}, nil
}

// ReconstituteRepositoryExtension recreates a RepositoryExtension from persistence.
func ReconstituteRepositoryExtension(
	assetID shared.ID,
	repoID string,
	fullName string,
	scmOrganization string,
	cloneURL string,
	webURL string,
	sshURL string,
	defaultBranch string,
	visibility RepoVisibility,
	language string,
	languages map[string]int64,
	topics []string,
	stars int,
	forks int,
	watchers int,
	openIssues int,
	contributorsCount int,
	sizeKB int,
	findingCount int,
	riskScore float64,
	scanEnabled bool,
	scanSchedule string,
	lastScannedAt *time.Time,
	branchCount int,
	protectedBranchCount int,
	componentCount int,
	vulnerableComponentCount int,
	repoCreatedAt *time.Time,
	repoUpdatedAt *time.Time,
	repoPushedAt *time.Time,
) *RepositoryExtension {
	if languages == nil {
		languages = make(map[string]int64)
	}
	if topics == nil {
		topics = make([]string, 0)
	}
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	return &RepositoryExtension{
		assetID:                  assetID,
		repoID:                   repoID,
		fullName:                 fullName,
		scmOrganization:          scmOrganization,
		cloneURL:                 cloneURL,
		webURL:                   webURL,
		sshURL:                   sshURL,
		defaultBranch:            defaultBranch,
		visibility:               visibility,
		language:                 language,
		languages:                languages,
		topics:                   topics,
		stars:                    stars,
		forks:                    forks,
		watchers:                 watchers,
		openIssues:               openIssues,
		contributorsCount:        contributorsCount,
		sizeKB:                   sizeKB,
		findingCount:             findingCount,
		riskScore:                riskScore,
		scanEnabled:              scanEnabled,
		scanSchedule:             scanSchedule,
		lastScannedAt:            lastScannedAt,
		branchCount:              branchCount,
		protectedBranchCount:     protectedBranchCount,
		componentCount:           componentCount,
		vulnerableComponentCount: vulnerableComponentCount,
		repoCreatedAt:            repoCreatedAt,
		repoUpdatedAt:            repoUpdatedAt,
		repoPushedAt:             repoPushedAt,
	}
}

// AssetID returns the asset ID.
func (r *RepositoryExtension) AssetID() shared.ID {
	return r.assetID
}

// RepoID returns the external repository ID.
func (r *RepositoryExtension) RepoID() string {
	return r.repoID
}

// FullName returns the full repository name (owner/repo).
func (r *RepositoryExtension) FullName() string {
	return r.fullName
}

// SCMOrganization returns the SCM organization name.
func (r *RepositoryExtension) SCMOrganization() string {
	return r.scmOrganization
}

// CloneURL returns the clone URL.
func (r *RepositoryExtension) CloneURL() string {
	return r.cloneURL
}

// WebURL returns the web URL.
func (r *RepositoryExtension) WebURL() string {
	return r.webURL
}

// SSHURL returns the SSH URL.
func (r *RepositoryExtension) SSHURL() string {
	return r.sshURL
}

// DefaultBranch returns the default branch name.
func (r *RepositoryExtension) DefaultBranch() string {
	return r.defaultBranch
}

// Visibility returns the repository visibility.
func (r *RepositoryExtension) Visibility() RepoVisibility {
	return r.visibility
}

// Language returns the primary language.
func (r *RepositoryExtension) Language() string {
	return r.language
}

// Languages returns a copy of the language breakdown.
func (r *RepositoryExtension) Languages() map[string]int64 {
	result := make(map[string]int64, len(r.languages))
	for k, v := range r.languages {
		result[k] = v
	}
	return result
}

// Topics returns a copy of the topics.
func (r *RepositoryExtension) Topics() []string {
	result := make([]string, len(r.topics))
	copy(result, r.topics)
	return result
}

// Stars returns the star count.
func (r *RepositoryExtension) Stars() int {
	return r.stars
}

// Forks returns the fork count.
func (r *RepositoryExtension) Forks() int {
	return r.forks
}

// Watchers returns the watcher count.
func (r *RepositoryExtension) Watchers() int {
	return r.watchers
}

// OpenIssues returns the open issue count.
func (r *RepositoryExtension) OpenIssues() int {
	return r.openIssues
}

// ContributorsCount returns the contributor count.
func (r *RepositoryExtension) ContributorsCount() int {
	return r.contributorsCount
}

// SizeKB returns the repository size in KB.
func (r *RepositoryExtension) SizeKB() int {
	return r.sizeKB
}

// FindingCount returns the finding count.
func (r *RepositoryExtension) FindingCount() int {
	return r.findingCount
}

// RiskScore returns the risk score.
func (r *RepositoryExtension) RiskScore() float64 {
	return r.riskScore
}

// ScanEnabled returns whether scanning is enabled.
func (r *RepositoryExtension) ScanEnabled() bool {
	return r.scanEnabled
}

// ScanSchedule returns the scan schedule.
func (r *RepositoryExtension) ScanSchedule() string {
	return r.scanSchedule
}

// LastScannedAt returns the last scan timestamp.
func (r *RepositoryExtension) LastScannedAt() *time.Time {
	return r.lastScannedAt
}

// BranchCount returns the branch count.
func (r *RepositoryExtension) BranchCount() int {
	return r.branchCount
}

// ProtectedBranchCount returns the protected branch count.
func (r *RepositoryExtension) ProtectedBranchCount() int {
	return r.protectedBranchCount
}

// ComponentCount returns the component count.
func (r *RepositoryExtension) ComponentCount() int {
	return r.componentCount
}

// VulnerableComponentCount returns the vulnerable component count.
func (r *RepositoryExtension) VulnerableComponentCount() int {
	return r.vulnerableComponentCount
}

// RepoCreatedAt returns the external repo creation timestamp.
func (r *RepositoryExtension) RepoCreatedAt() *time.Time {
	return r.repoCreatedAt
}

// RepoUpdatedAt returns the external repo update timestamp.
func (r *RepositoryExtension) RepoUpdatedAt() *time.Time {
	return r.repoUpdatedAt
}

// RepoPushedAt returns the external repo last push timestamp.
func (r *RepositoryExtension) RepoPushedAt() *time.Time {
	return r.repoPushedAt
}

// SetRepoID sets the external repository ID.
func (r *RepositoryExtension) SetRepoID(repoID string) {
	r.repoID = repoID
}

// SetFullName sets the full repository name.
func (r *RepositoryExtension) SetFullName(fullName string) {
	r.fullName = fullName
}

// SetSCMOrganization sets the SCM organization name.
func (r *RepositoryExtension) SetSCMOrganization(org string) {
	r.scmOrganization = org
}

// SetCloneURL sets the clone URL.
func (r *RepositoryExtension) SetCloneURL(url string) {
	r.cloneURL = url
}

// SetWebURL sets the web URL.
func (r *RepositoryExtension) SetWebURL(url string) {
	r.webURL = url
}

// SetSSHURL sets the SSH URL.
func (r *RepositoryExtension) SetSSHURL(url string) {
	r.sshURL = url
}

// SetDefaultBranch sets the default branch.
func (r *RepositoryExtension) SetDefaultBranch(branch string) {
	if branch == "" {
		branch = "main"
	}
	r.defaultBranch = branch
}

// SetVisibility sets the repository visibility.
func (r *RepositoryExtension) SetVisibility(visibility RepoVisibility) {
	if !visibility.IsValid() {
		return
	}
	r.visibility = visibility
}

// SetLanguage sets the primary language.
func (r *RepositoryExtension) SetLanguage(language string) {
	r.language = language
}

// SetLanguages sets the language breakdown.
func (r *RepositoryExtension) SetLanguages(languages map[string]int64) {
	if languages == nil {
		languages = make(map[string]int64)
	}
	r.languages = languages
}

// SetTopics sets the topics.
func (r *RepositoryExtension) SetTopics(topics []string) {
	if topics == nil {
		topics = make([]string, 0)
	}
	r.topics = topics
}

// UpdateStats updates repository stats.
func (r *RepositoryExtension) UpdateStats(stars, forks, watchers, openIssues, contributorsCount, sizeKB int) {
	r.stars = stars
	r.forks = forks
	r.watchers = watchers
	r.openIssues = openIssues
	r.contributorsCount = contributorsCount
	r.sizeKB = sizeKB
}

// UpdateSecurityStats updates security stats.
func (r *RepositoryExtension) UpdateSecurityStats(findingCount int, riskScore float64) {
	r.findingCount = findingCount
	r.riskScore = riskScore
}

// UpdateBranchStats updates branch stats.
func (r *RepositoryExtension) UpdateBranchStats(branchCount, protectedBranchCount int) {
	r.branchCount = branchCount
	r.protectedBranchCount = protectedBranchCount
}

// UpdateComponentStats updates component stats.
func (r *RepositoryExtension) UpdateComponentStats(componentCount, vulnerableComponentCount int) {
	r.componentCount = componentCount
	r.vulnerableComponentCount = vulnerableComponentCount
}

// EnableScan enables scanning for this repository with an optional schedule.
func (r *RepositoryExtension) EnableScan(schedule string) {
	r.scanEnabled = true
	if schedule != "" {
		r.scanSchedule = schedule
	}
}

// DisableScan disables scanning for this repository.
func (r *RepositoryExtension) DisableScan() {
	r.scanEnabled = false
}

// SetScanSchedule sets the scan schedule.
func (r *RepositoryExtension) SetScanSchedule(schedule string) {
	r.scanSchedule = schedule
}

// MarkScanned updates the last scanned timestamp.
func (r *RepositoryExtension) MarkScanned() {
	now := time.Now().UTC()
	r.lastScannedAt = &now
}

// UpdateRepoTimestamps updates external repo timestamps.
func (r *RepositoryExtension) UpdateRepoTimestamps(createdAt, updatedAt, pushedAt *time.Time) {
	r.repoCreatedAt = createdAt
	r.repoUpdatedAt = updatedAt
	r.repoPushedAt = pushedAt
}

// IsPublic returns true if the repository is public.
func (r *RepositoryExtension) IsPublic() bool {
	return r.visibility == VisibilityPublic
}

// HasBranches returns true if the repository has branches.
func (r *RepositoryExtension) HasBranches() bool {
	return r.branchCount > 0
}

// HasComponents returns true if the repository has components.
func (r *RepositoryExtension) HasComponents() bool {
	return r.componentCount > 0
}

// HasVulnerableComponents returns true if the repository has vulnerable components.
func (r *RepositoryExtension) HasVulnerableComponents() bool {
	return r.vulnerableComponentCount > 0
}

// SetStars sets the star count.
func (r *RepositoryExtension) SetStars(stars int) {
	r.stars = stars
}

// SetForks sets the fork count.
func (r *RepositoryExtension) SetForks(forks int) {
	r.forks = forks
}

// SetWatchers sets the watcher count.
func (r *RepositoryExtension) SetWatchers(watchers int) {
	r.watchers = watchers
}

// SetOpenIssues sets the open issue count.
func (r *RepositoryExtension) SetOpenIssues(openIssues int) {
	r.openIssues = openIssues
}

// SetContributorsCount sets the contributor count.
func (r *RepositoryExtension) SetContributorsCount(count int) {
	r.contributorsCount = count
}

// SetSizeKB sets the repository size in KB.
func (r *RepositoryExtension) SetSizeKB(sizeKB int) {
	r.sizeKB = sizeKB
}

// SetBranchCount sets the branch count.
func (r *RepositoryExtension) SetBranchCount(count int) {
	r.branchCount = count
}

// SetProtectedBranchCount sets the protected branch count.
func (r *RepositoryExtension) SetProtectedBranchCount(count int) {
	r.protectedBranchCount = count
}

// SetComponentCount sets the component count.
func (r *RepositoryExtension) SetComponentCount(count int) {
	r.componentCount = count
}

// SetVulnerableComponentCount sets the vulnerable component count.
func (r *RepositoryExtension) SetVulnerableComponentCount(count int) {
	r.vulnerableComponentCount = count
}

// SetFindingCount sets the finding count.
func (r *RepositoryExtension) SetFindingCount(count int) {
	r.findingCount = count
}

// CalculateRiskScore calculates and sets the risk score based on actual security factors.
// The score reflects real risk indicators for repositories:
// - Unknown state (never scanned): +15 points
// - Security findings: up to 50 points
// - Vulnerable dependencies: up to 30 points
// - Public visibility (exposed): +15 points
// - Scanning disabled (no monitoring): +10 points
func (r *RepositoryExtension) CalculateRiskScore() {
	score := 0.0

	// 1. Uncertainty penalty - never scanned repos have unknown risk (15 points)
	if r.lastScannedAt == nil {
		score += 15
	}

	// 2. Finding impact - actual security issues found (up to 50 points)
	if r.findingCount > 0 {
		findingImpact := float64(r.findingCount) * 2.0
		if findingImpact > 50 {
			findingImpact = 50
		}
		score += findingImpact
	}

	// 3. Vulnerable component impact (up to 30 points)
	if r.vulnerableComponentCount > 0 {
		vulnImpact := float64(r.vulnerableComponentCount) * 3.0
		if vulnImpact > 30 {
			vulnImpact = 30
		}
		score += vulnImpact
	}

	// 4. Visibility risk - public repos are exposed to the world
	switch r.visibility {
	case VisibilityPublic:
		score += 15 // Highest exposure
	case VisibilityInternal:
		score += 5 // Some exposure within org
		// Private = 0 additional risk
	}

	// 5. Monitoring status - unmonitored repos are riskier
	if !r.scanEnabled {
		score += 10
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	r.riskScore = score
}

// RecordScan records a scan completion (alias for MarkScanned).
func (r *RepositoryExtension) RecordScan() {
	r.MarkScanned()
}
