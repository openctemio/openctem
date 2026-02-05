package app

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/api/internal/app/validators"
	"github.com/openctemio/api/internal/infra/fetchers"
	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/secretstore"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/templatesource"
	"github.com/openctemio/api/pkg/logger"
)

// TemplateSyncer handles syncing templates from external sources.
type TemplateSyncer struct {
	sourceRepo     templatesource.Repository
	templateRepo   scannertemplate.Repository
	secretStoreSvc *SecretStoreService
	templateSigner *scannertemplate.Signer
	logger         *logger.Logger
}

// NewTemplateSyncer creates a new TemplateSyncer.
func NewTemplateSyncer(
	sourceRepo templatesource.Repository,
	templateRepo scannertemplate.Repository,
	secretStoreSvc *SecretStoreService,
	signingKey []byte,
	log *logger.Logger,
) *TemplateSyncer {
	return &TemplateSyncer{
		sourceRepo:     sourceRepo,
		templateRepo:   templateRepo,
		secretStoreSvc: secretStoreSvc,
		templateSigner: scannertemplate.NewSigner(signingKey),
		logger:         log.With("service", "template_syncer"),
	}
}

// SyncResult contains the result of a sync operation.
type TemplateSyncResult struct {
	SourceID       shared.ID
	Success        bool
	Hash           string
	TemplatesFound int
	TemplatesAdded int
	Error          string
	Duration       time.Duration
}

// SyncSource syncs templates from a single source.
func (s *TemplateSyncer) SyncSource(ctx context.Context, source *templatesource.TemplateSource) (*TemplateSyncResult, error) {
	start := time.Now()
	result := &TemplateSyncResult{SourceID: source.ID}

	// Update status to in_progress
	source.LastSyncStatus = templatesource.SyncStatusInProgress
	source.UpdatedAt = time.Now()
	_ = s.sourceRepo.UpdateSyncStatus(ctx, source)

	// Create fetcher based on source type
	fetcher, err := s.createFetcher(ctx, source)
	if err != nil {
		result.Error = err.Error()
		s.markSyncFailed(ctx, source, err.Error())
		return result, err
	}
	defer fetcher.Close()

	// Check for updates first
	currentHash, hasChanges, err := fetcher.CheckForUpdates(ctx, source.LastSyncHash)
	if err != nil {
		// If check fails, proceed with full fetch
		s.logger.Warn("failed to check for updates, proceeding with full fetch",
			"source_id", source.ID.String(),
			"error", err,
		)
		hasChanges = true
	}

	if !hasChanges && source.LastSyncHash != "" {
		// No changes, update timestamp only
		source.LastSyncAt = ptr(time.Now())
		source.LastSyncStatus = templatesource.SyncStatusSuccess
		source.UpdatedAt = time.Now()
		_ = s.sourceRepo.UpdateSyncStatus(ctx, source)

		result.Success = true
		result.Hash = currentHash
		result.Duration = time.Since(start)
		return result, nil
	}

	// Fetch templates
	extensions := s.getExtensionsForTemplateType(source.TemplateType)
	fetchOpts := fetchers.FetchOptions{
		LastHash:    source.LastSyncHash,
		Extensions:  extensions,
		MaxFileSize: 1 * 1024 * 1024, // 1MB per file
	}

	fetchResult, err := fetcher.Fetch(ctx, fetchOpts)
	if err != nil {
		result.Error = err.Error()
		s.markSyncFailed(ctx, source, err.Error())
		return result, err
	}

	result.TemplatesFound = fetchResult.TotalFiles

	// Process and store templates
	addedCount, err := s.processTemplates(ctx, source, fetchResult.Files)
	if err != nil {
		result.Error = err.Error()
		s.markSyncFailed(ctx, source, err.Error())
		return result, err
	}

	result.TemplatesAdded = addedCount

	// Update source with success
	source.LastSyncAt = ptr(time.Now())
	source.LastSyncHash = fetchResult.Hash
	source.LastSyncStatus = templatesource.SyncStatusSuccess
	source.LastSyncError = nil
	source.TotalTemplates = fetchResult.TotalFiles
	source.LastSyncCount = addedCount
	source.UpdatedAt = time.Now()

	if err := s.sourceRepo.UpdateSyncStatus(ctx, source); err != nil {
		s.logger.Error("failed to update sync status", "error", err)
	}

	result.Success = true
	result.Hash = fetchResult.Hash
	result.Duration = time.Since(start)

	s.logger.Info("sync completed",
		"source_id", source.ID.String(),
		"source_name", source.Name,
		"templates_found", result.TemplatesFound,
		"templates_added", result.TemplatesAdded,
		"duration", result.Duration,
	)

	return result, nil
}

// SyncSourcesForScan syncs all sources that need updating for a scan.
func (s *TemplateSyncer) SyncSourcesForScan(ctx context.Context, tenantID shared.ID) ([]*TemplateSyncResult, error) {
	// Get enabled sources with auto_sync_on_scan
	sources, err := s.sourceRepo.ListEnabledForSync(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	results := make([]*TemplateSyncResult, 0, len(sources))

	for _, source := range sources {
		// Check if cache is still valid
		if !source.NeedsSync() {
			s.logger.Debug("source cache still valid, skipping sync",
				"source_id", source.ID.String(),
				"source_name", source.Name,
			)
			continue
		}

		result, err := s.SyncSource(ctx, source)
		if err != nil {
			s.logger.Error("failed to sync source",
				"source_id", source.ID.String(),
				"error", err,
			)
		}
		results = append(results, result)
	}

	return results, nil
}

func (s *TemplateSyncer) createFetcher(ctx context.Context, source *templatesource.TemplateSource) (fetchers.Fetcher, error) {
	switch source.SourceType {
	case templatesource.SourceTypeGit:
		return s.createGitFetcher(ctx, source)
	case templatesource.SourceTypeS3:
		return s.createS3Fetcher(ctx, source)
	case templatesource.SourceTypeHTTP:
		return s.createHTTPFetcher(ctx, source)
	default:
		return nil, fmt.Errorf("unsupported source type: %s", source.SourceType)
	}
}

func (s *TemplateSyncer) createGitFetcher(ctx context.Context, source *templatesource.TemplateSource) (*fetchers.GitFetcher, error) {
	if source.GitConfig == nil {
		return nil, fmt.Errorf("git config is required")
	}

	cfg := fetchers.GitConfig{
		URL:      source.GitConfig.URL,
		Branch:   source.GitConfig.Branch,
		Path:     source.GitConfig.Path,
		AuthType: source.GitConfig.AuthType,
	}

	// Get credentials if needed
	if source.CredentialID != nil && cfg.AuthType != "" && cfg.AuthType != "none" {
		cred, err := s.getCredential(ctx, source.TenantID, *source.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("failed to get credential: %w", err)
		}

		switch cfg.AuthType {
		case "token":
			if tokenData, ok := cred.(*secretstore.BearerTokenData); ok {
				cfg.Token = tokenData.Token
			} else if gitlabData, ok := cred.(*secretstore.GitLabTokenData); ok {
				cfg.Token = gitlabData.Token
			}
		case "ssh":
			if sshData, ok := cred.(*secretstore.SSHKeyData); ok {
				cfg.SSHKey = []byte(sshData.PrivateKey)
				cfg.SSHKeyPass = sshData.Passphrase
			}
		}
	}

	return fetchers.NewGitFetcher(cfg)
}

func (s *TemplateSyncer) createS3Fetcher(ctx context.Context, source *templatesource.TemplateSource) (*fetchers.S3Fetcher, error) {
	if source.S3Config == nil {
		return nil, fmt.Errorf("s3 config is required")
	}

	cfg := fetchers.S3Config{
		Bucket:     source.S3Config.Bucket,
		Region:     source.S3Config.Region,
		Prefix:     source.S3Config.Prefix,
		Endpoint:   source.S3Config.Endpoint,
		AuthType:   source.S3Config.AuthType,
		RoleARN:    source.S3Config.RoleArn,
		ExternalID: source.S3Config.ExternalID,
	}

	// Get credentials if using keys
	if source.CredentialID != nil && cfg.AuthType == "keys" {
		cred, err := s.getCredential(ctx, source.TenantID, *source.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("failed to get credential: %w", err)
		}

		if apiKeyData, ok := cred.(*secretstore.APIKeyData); ok {
			// Format: "ACCESS_KEY:SECRET_KEY"
			parts := strings.SplitN(apiKeyData.Key, ":", 2)
			if len(parts) == 2 {
				cfg.AccessKey = parts[0]
				cfg.SecretKey = parts[1]
			}
		}
	}

	return fetchers.NewS3Fetcher(ctx, cfg)
}

func (s *TemplateSyncer) createHTTPFetcher(ctx context.Context, source *templatesource.TemplateSource) (*fetchers.HTTPFetcher, error) {
	if source.HTTPConfig == nil {
		return nil, fmt.Errorf("http config is required")
	}

	cfg := fetchers.HTTPConfig{
		URL:      source.HTTPConfig.URL,
		AuthType: source.HTTPConfig.AuthType,
		Headers:  source.HTTPConfig.Headers,
		Timeout:  time.Duration(source.HTTPConfig.Timeout) * time.Second,
	}

	// Get credentials if needed
	if source.CredentialID != nil && cfg.AuthType != "" && cfg.AuthType != "none" {
		cred, err := s.getCredential(ctx, source.TenantID, *source.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("failed to get credential: %w", err)
		}

		switch cfg.AuthType {
		case "bearer":
			if tokenData, ok := cred.(*secretstore.BearerTokenData); ok {
				cfg.Token = tokenData.Token
			}
		case "basic":
			if basicData, ok := cred.(*secretstore.BasicAuthData); ok {
				cfg.Username = basicData.Username
				cfg.Password = basicData.Password
			}
		case "api_key":
			if apiKeyData, ok := cred.(*secretstore.APIKeyData); ok {
				cfg.Token = apiKeyData.Key
			}
		}
	}

	return fetchers.NewHTTPFetcher(cfg)
}

func (s *TemplateSyncer) getCredential(ctx context.Context, tenantID, credentialID shared.ID) (any, error) {
	return s.secretStoreSvc.DecryptCredentialData(ctx, tenantID, credentialID.String())
}

func (s *TemplateSyncer) processTemplates(ctx context.Context, source *templatesource.TemplateSource, files map[string][]byte) (int, error) {
	validator := s.getValidator(source.TemplateType)
	addedCount := 0

	for path, content := range files {
		// Validate template
		if validator != nil {
			result := validator.Validate(content)
			if result.HasErrors() {
				s.logger.Warn("invalid template, skipping",
					"source_id", source.ID.String(),
					"path", path,
					"errors", result.Errors,
				)
				continue
			}
		}

		// Generate name from path
		name := filepath.Base(path)
		name = strings.TrimSuffix(name, filepath.Ext(name))

		// Check if template exists
		existing, _ := s.templateRepo.GetByTenantAndName(ctx, source.TenantID, source.TemplateType, name)

		if existing != nil {
			// Update existing
			existing.Content = content
			existing.ContentHash = scannertemplate.ComputeHash(content)
			existing.SignatureHash = s.templateSigner.Sign(content)
			existing.SourcePath = &path
			existing.SourceID = &source.ID
			existing.UpdatedAt = time.Now()

			if validator != nil {
				existing.RuleCount = validator.CountRules(content)
			}

			if err := s.templateRepo.Update(ctx, existing); err != nil {
				s.logger.Error("failed to update template",
					"template_id", existing.ID.String(),
					"error", err,
				)
				continue
			}
		} else {
			// Create new template
			template, err := scannertemplate.NewScannerTemplate(
				source.TenantID,
				name,
				source.TemplateType,
				content,
				source.CreatedBy,
			)
			if err != nil {
				s.logger.Error("failed to create template entity",
					"name", name,
					"error", err,
				)
				continue
			}

			template.SourceID = &source.ID
			template.SourcePath = &path
			template.SyncSource = scannertemplate.SyncSource(source.SourceType)
			template.SignatureHash = s.templateSigner.Sign(content)

			if validator != nil {
				template.RuleCount = validator.CountRules(content)
			}

			if err := s.templateRepo.Create(ctx, template); err != nil {
				s.logger.Error("failed to create template",
					"name", name,
					"error", err,
				)
				continue
			}
			addedCount++
		}
	}

	return addedCount, nil
}

func (s *TemplateSyncer) getExtensionsForTemplateType(templateType scannertemplate.TemplateType) []string {
	switch templateType {
	case scannertemplate.TemplateTypeNuclei:
		return []string{".yaml", ".yml"}
	case scannertemplate.TemplateTypeSemgrep:
		return []string{".yaml", ".yml"}
	case scannertemplate.TemplateTypeGitleaks:
		return []string{".toml"}
	default:
		return nil
	}
}

func (s *TemplateSyncer) getValidator(templateType scannertemplate.TemplateType) validators.TemplateValidator {
	switch templateType {
	case scannertemplate.TemplateTypeNuclei:
		return &validators.NucleiValidator{}
	case scannertemplate.TemplateTypeSemgrep:
		return &validators.SemgrepValidator{}
	case scannertemplate.TemplateTypeGitleaks:
		return &validators.GitleaksValidator{}
	default:
		return nil
	}
}

func (s *TemplateSyncer) markSyncFailed(ctx context.Context, source *templatesource.TemplateSource, errMsg string) {
	source.LastSyncAt = ptr(time.Now())
	source.LastSyncStatus = templatesource.SyncStatusFailed
	source.LastSyncError = &errMsg
	source.UpdatedAt = time.Now()
	_ = s.sourceRepo.UpdateSyncStatus(ctx, source)
}

func ptr[T any](v T) *T {
	return &v
}
