package integration

import (
	"time"
)

// SCMExtension represents SCM-specific extension data for an integration.
// This follows the same pattern as asset + asset_repositories extension.
type SCMExtension struct {
	integrationID ID

	// SCM-specific fields
	scmOrganization string
	repositoryCount int

	// Webhook configuration
	webhookID     string
	webhookSecret string
	webhookURL    string

	// Repository sync settings
	defaultBranchPattern string
	autoImportRepos      bool
	importPrivateRepos   bool
	importArchivedRepos  bool

	// Repository filters
	includePatterns []string
	excludePatterns []string

	// Timestamps
	lastRepoSyncAt *time.Time
}

// NewSCMExtension creates a new SCM extension.
func NewSCMExtension(integrationID ID) *SCMExtension {
	return &SCMExtension{
		integrationID:        integrationID,
		defaultBranchPattern: "main,master",
		autoImportRepos:      false,
		importPrivateRepos:   true,
		importArchivedRepos:  false,
		includePatterns:      []string{},
		excludePatterns:      []string{},
	}
}

// ReconstructSCMExtension creates an SCM extension from stored data.
func ReconstructSCMExtension(
	integrationID ID,
	scmOrganization string,
	repositoryCount int,
	webhookID string,
	webhookSecret string,
	webhookURL string,
	defaultBranchPattern string,
	autoImportRepos bool,
	importPrivateRepos bool,
	importArchivedRepos bool,
	includePatterns []string,
	excludePatterns []string,
	lastRepoSyncAt *time.Time,
) *SCMExtension {
	if includePatterns == nil {
		includePatterns = []string{}
	}
	if excludePatterns == nil {
		excludePatterns = []string{}
	}
	if defaultBranchPattern == "" {
		defaultBranchPattern = "main,master"
	}
	return &SCMExtension{
		integrationID:        integrationID,
		scmOrganization:      scmOrganization,
		repositoryCount:      repositoryCount,
		webhookID:            webhookID,
		webhookSecret:        webhookSecret,
		webhookURL:           webhookURL,
		defaultBranchPattern: defaultBranchPattern,
		autoImportRepos:      autoImportRepos,
		importPrivateRepos:   importPrivateRepos,
		importArchivedRepos:  importArchivedRepos,
		includePatterns:      includePatterns,
		excludePatterns:      excludePatterns,
		lastRepoSyncAt:       lastRepoSyncAt,
	}
}

// Getters

func (s *SCMExtension) IntegrationID() ID            { return s.integrationID }
func (s *SCMExtension) SCMOrganization() string      { return s.scmOrganization }
func (s *SCMExtension) RepositoryCount() int         { return s.repositoryCount }
func (s *SCMExtension) WebhookID() string            { return s.webhookID }
func (s *SCMExtension) WebhookSecret() string        { return s.webhookSecret }
func (s *SCMExtension) WebhookURL() string           { return s.webhookURL }
func (s *SCMExtension) DefaultBranchPattern() string { return s.defaultBranchPattern }
func (s *SCMExtension) AutoImportRepos() bool        { return s.autoImportRepos }
func (s *SCMExtension) ImportPrivateRepos() bool     { return s.importPrivateRepos }
func (s *SCMExtension) ImportArchivedRepos() bool    { return s.importArchivedRepos }
func (s *SCMExtension) IncludePatterns() []string    { return s.includePatterns }
func (s *SCMExtension) ExcludePatterns() []string    { return s.excludePatterns }
func (s *SCMExtension) LastRepoSyncAt() *time.Time   { return s.lastRepoSyncAt }

// Setters

func (s *SCMExtension) SetSCMOrganization(org string) {
	s.scmOrganization = org
}

func (s *SCMExtension) SetRepositoryCount(count int) {
	s.repositoryCount = count
}

func (s *SCMExtension) SetWebhook(id, secret, url string) {
	s.webhookID = id
	s.webhookSecret = secret
	s.webhookURL = url
}

func (s *SCMExtension) SetDefaultBranchPattern(pattern string) {
	s.defaultBranchPattern = pattern
}

func (s *SCMExtension) SetAutoImportRepos(auto bool) {
	s.autoImportRepos = auto
}

func (s *SCMExtension) SetImportPrivateRepos(private bool) {
	s.importPrivateRepos = private
}

func (s *SCMExtension) SetImportArchivedRepos(archived bool) {
	s.importArchivedRepos = archived
}

func (s *SCMExtension) SetIncludePatterns(patterns []string) {
	s.includePatterns = patterns
}

func (s *SCMExtension) SetExcludePatterns(patterns []string) {
	s.excludePatterns = patterns
}

func (s *SCMExtension) UpdateLastRepoSync() {
	now := time.Now()
	s.lastRepoSyncAt = &now
}

// IntegrationWithSCM combines an Integration with its SCM extension.
type IntegrationWithSCM struct {
	*Integration
	SCM *SCMExtension
}

// NewIntegrationWithSCM creates a new integration with SCM extension.
func NewIntegrationWithSCM(integration *Integration, scm *SCMExtension) *IntegrationWithSCM {
	return &IntegrationWithSCM{
		Integration: integration,
		SCM:         scm,
	}
}
