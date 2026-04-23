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

	// Webhook configuration. webhookSecretEncrypted holds AES-GCM
	// ciphertext produced by pkg/crypto.Encryptor — the plaintext
	// secret never crosses the DB boundary. Callers that need to
	// emit or verify an HMAC decrypt inside the service layer, then
	// discard the plaintext. Column on disk is BYTEA; see
	// migration 000160.
	webhookID              string
	webhookSecretEncrypted []byte
	webhookURL             string

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
// webhookSecretEncrypted is the AES-GCM ciphertext read from the DB;
// the service layer calls Encryptor.DecryptString when (and only when)
// a live HMAC verify needs the plaintext.
func ReconstructSCMExtension(
	integrationID ID,
	scmOrganization string,
	repositoryCount int,
	webhookID string,
	webhookSecretEncrypted []byte,
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
		integrationID:          integrationID,
		scmOrganization:        scmOrganization,
		repositoryCount:        repositoryCount,
		webhookID:              webhookID,
		webhookSecretEncrypted: webhookSecretEncrypted,
		webhookURL:             webhookURL,
		defaultBranchPattern:   defaultBranchPattern,
		autoImportRepos:        autoImportRepos,
		importPrivateRepos:     importPrivateRepos,
		importArchivedRepos:    importArchivedRepos,
		includePatterns:        includePatterns,
		excludePatterns:        excludePatterns,
		lastRepoSyncAt:         lastRepoSyncAt,
	}
}

// Getters

func (s *SCMExtension) IntegrationID() ID            { return s.integrationID }
func (s *SCMExtension) SCMOrganization() string      { return s.scmOrganization }
func (s *SCMExtension) RepositoryCount() int         { return s.repositoryCount }
func (s *SCMExtension) WebhookID() string                { return s.webhookID }
func (s *SCMExtension) WebhookSecretEncrypted() []byte   { return s.webhookSecretEncrypted }
func (s *SCMExtension) WebhookURL() string               { return s.webhookURL }
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

// SetWebhook persists the webhook configuration. secretCiphertext MUST
// be the output of pkg/crypto.Encryptor.EncryptString — service-layer
// callers encrypt before reaching the domain. Passing a plaintext
// string here would land the secret on disk unencrypted (the threat
// this refactor is closing); tests that want a placeholder should pass
// []byte("dummy-ciphertext").
func (s *SCMExtension) SetWebhook(id string, secretCiphertext []byte, url string) {
	s.webhookID = id
	s.webhookSecretEncrypted = secretCiphertext
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
