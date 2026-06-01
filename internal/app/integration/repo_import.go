package integration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/internal/infra/scm"
	assetdom "github.com/openctemio/api/pkg/domain/asset"
	branchdom "github.com/openctemio/api/pkg/domain/branch"
	"github.com/openctemio/api/pkg/domain/shared"
)

const (
	// importPerPage is the page size used when listing repositories to import.
	importPerPage = 100
	// maxImportPages caps how many pages we walk, bounding a runaway import on
	// very large orgs (maxImportPages * importPerPage repositories).
	maxImportPages = 50
)

// ImportReposInput parameterizes ImportSCMRepositories.
type ImportReposInput struct {
	IntegrationID   string
	TenantID        string
	IncludeArchived bool // import archived repos too (default: skip them)
}

// ImportReposResult summarizes an import run.
type ImportReposResult struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
	Total   int `json:"total"`
}

// SetRepoImportRepos wires the asset/branch stores used by ImportSCMRepositories.
// When the asset stores are unset, repository import returns an error rather than
// silently no-op'ing. branchRepo is optional — when nil, branches are not synced.
func (s *IntegrationService) SetRepoImportRepos(assetRepo assetdom.Repository, repoExtRepo assetdom.RepositoryExtensionRepository, branchRepo branchdom.Repository) {
	s.assetRepo = assetRepo
	s.repoExtRepo = repoExtRepo
	s.branchRepo = branchRepo
}

// ImportSCMRepositories lists repositories from an SCM integration and upserts
// them as repository assets for the tenant. Dedup is by (tenant, full_name):
// an existing repository refreshes its metadata, a new one is created with its
// repository extension. Archived repos are skipped unless IncludeArchived.
//
// It never deletes assets — repos the token can no longer see are simply left
// alone (their findings/history are preserved).
func (s *IntegrationService) ImportSCMRepositories(ctx context.Context, input ImportReposInput) (*ImportReposResult, error) {
	if s.assetRepo == nil || s.repoExtRepo == nil {
		return nil, fmt.Errorf("%w: repository import is not configured", shared.ErrValidation)
	}
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	// Page through all accessible repositories, reusing ListSCMRepositories
	// (which handles client creation, credentials and tenant ownership).
	repos := make([]scm.Repository, 0, importPerPage)
	for page := 1; page <= maxImportPages; page++ {
		res, err := s.ListSCMRepositories(ctx, IntegrationListReposInput{
			IntegrationID: input.IntegrationID,
			TenantID:      input.TenantID,
			Page:          page,
			PerPage:       importPerPage,
		})
		if err != nil {
			return nil, err
		}
		repos = append(repos, res.Repositories...)
		if !res.HasMore || len(res.Repositories) == 0 {
			break
		}
	}

	// Build one SCM client up front for branch sync (best-effort: if it fails,
	// repos still import, just without branches).
	var branchClient scm.Client
	if s.branchRepo != nil {
		if intgID, err := shared.IDFromString(input.IntegrationID); err == nil {
			branchClient, _ = s.scmClientForIntegration(ctx, intgID)
		}
	}

	result := &ImportReposResult{Total: len(repos)}
	for i := range repos {
		r := repos[i]
		if r.FullName == "" || (r.IsArchived && !input.IncludeArchived) {
			result.Skipped++
			continue
		}
		created, err := s.upsertRepositoryAsset(ctx, tenantID, r)
		if err != nil {
			s.logger.Warn("failed to import repository",
				"full_name", r.FullName, "error", err)
			result.Skipped++
			continue
		}
		if created {
			result.Created++
		} else {
			result.Updated++
		}

		// Sync branches (incl. authoritative default) for the imported repo.
		if branchClient != nil {
			if ext, _ := s.repoExtRepo.GetByFullName(ctx, tenantID, r.FullName); ext != nil {
				s.syncBranches(ctx, branchClient, ext.AssetID(), r)
			}
		}
	}

	s.logger.Info("imported SCM repositories",
		"tenant_id", tenantID.String(),
		"integration_id", input.IntegrationID,
		"created", result.Created, "updated", result.Updated, "skipped", result.Skipped, "total", result.Total)
	return result, nil
}

// upsertRepositoryAsset creates (or refreshes) a repository asset + extension
// from an SCM repository DTO. Returns created=true on first import.
func (s *IntegrationService) upsertRepositoryAsset(ctx context.Context, tenantID shared.ID, r scm.Repository) (bool, error) {
	visibility := assetdom.RepoVisibilityPublic
	if r.IsPrivate {
		visibility = assetdom.RepoVisibilityPrivate
	}

	// Dedup by full name within the tenant — refresh metadata if it exists.
	if existing, _ := s.repoExtRepo.GetByFullName(ctx, tenantID, r.FullName); existing != nil {
		applyRepoFields(existing, r, visibility)
		if err := s.repoExtRepo.Update(ctx, existing); err != nil {
			return false, fmt.Errorf("update repository extension: %w", err)
		}
		return false, nil
	}

	a, err := assetdom.NewAssetWithTenant(tenantID, r.FullName, assetdom.AssetTypeRepository, assetdom.CriticalityMedium)
	if err != nil {
		return false, fmt.Errorf("new repository asset: %w", err)
	}
	if err := s.assetRepo.Create(ctx, a); err != nil {
		return false, fmt.Errorf("create repository asset: %w", err)
	}

	// asset Create may already have inserted a minimal asset_repositories row;
	// upsert the extension either way so rich metadata is stored.
	if cur, _ := s.repoExtRepo.GetByAssetID(ctx, a.ID()); cur != nil {
		applyRepoFields(cur, r, visibility)
		if err := s.repoExtRepo.Update(ctx, cur); err != nil {
			return false, fmt.Errorf("update repository extension: %w", err)
		}
		return true, nil
	}

	ext, err := assetdom.NewRepositoryExtension(a.ID(), r.FullName, visibility)
	if err != nil {
		return false, fmt.Errorf("new repository extension: %w", err)
	}
	applyRepoFields(ext, r, visibility)
	if err := s.repoExtRepo.Create(ctx, ext); err != nil {
		return false, fmt.Errorf("create repository extension: %w", err)
	}
	return true, nil
}

// applyRepoFields copies SCM repo metadata onto a repository extension.
func applyRepoFields(ext *assetdom.RepositoryExtension, r scm.Repository, visibility assetdom.RepoVisibility) {
	if r.ID != "" {
		ext.SetRepoID(r.ID)
	}
	ext.SetCloneURL(r.CloneURL)
	ext.SetWebURL(r.HTMLURL)
	ext.SetSSHURL(r.SSHURL)
	if r.DefaultBranch != "" {
		ext.SetDefaultBranch(r.DefaultBranch)
	}
	ext.SetVisibility(visibility)
	if r.Language != "" {
		ext.SetLanguage(r.Language)
	}
	if len(r.Topics) > 0 {
		ext.SetTopics(r.Topics)
	}
	ext.UpdateStats(r.Stars, r.Forks, 0, 0, 0, r.Size)
	if i := strings.Index(r.FullName, "/"); i > 0 {
		ext.SetSCMOrganization(r.FullName[:i])
	}
}

// scmClientForIntegration builds an SCM client for an integration (resolving
// org, base URL and decrypted credentials), mirroring ListSCMRepositories.
func (s *IntegrationService) scmClientForIntegration(ctx context.Context, intgID shared.ID) (scm.Client, error) {
	intg, err := s.repo.GetByID(ctx, intgID)
	if err != nil {
		return nil, err
	}
	if !intg.IsSCM() {
		return nil, fmt.Errorf("%w: not an SCM integration", shared.ErrValidation)
	}
	scmOrg := ""
	if scmExt, _ := s.scmExtRepo.GetByIntegrationID(ctx, intgID); scmExt != nil {
		scmOrg = scmExt.SCMOrganization()
	}
	baseURL := intg.BaseURL()
	if baseURL == "" {
		baseURL = s.getDefaultBaseURL(intg.Provider())
	}
	return s.scmFactory.CreateClient(scm.Config{
		Provider:     scm.Provider(intg.Provider()),
		BaseURL:      baseURL,
		AccessToken:  s.decryptCredentials(intg),
		Organization: scmOrg,
		AuthType:     scm.AuthType(intg.AuthType()),
	})
}

// syncBranches lists a repository's branches from the provider and upserts them
// as repository_branches, setting the provider's default branch as the
// authoritative default (atomic). Best-effort: provider/listing errors are
// logged and skipped. Providers without ListBranches support are silently
// skipped (ErrBranchListingUnsupported).
func (s *IntegrationService) syncBranches(ctx context.Context, client scm.Client, repositoryID shared.ID, r scm.Repository) {
	branches, err := client.ListBranches(ctx, r.FullName, scm.ListOptions{})
	if err != nil {
		if !errors.Is(err, scm.ErrBranchListingUnsupported) {
			s.logger.Warn("failed to list branches", "full_name", r.FullName, "error", err)
		}
		return
	}

	now := time.Now().UTC()
	var defaultBranchID *shared.ID
	for _, b := range branches {
		existing, _ := s.branchRepo.GetByName(ctx, repositoryID, b.Name)
		if existing != nil {
			if b.CommitSHA != "" && b.CommitSHA != existing.LastCommitSHA() {
				existing.UpdateLastCommit(b.CommitSHA, "", "", "", now)
			}
			existing.SetProtected(b.Protected)
			if err := s.branchRepo.Update(ctx, existing); err != nil {
				s.logger.Warn("failed to update branch", "branch", b.Name, "error", err)
			}
			if b.Name == r.DefaultBranch {
				id := existing.ID()
				defaultBranchID = &id
			}
			continue
		}

		nb, err := branchdom.NewBranch(repositoryID, b.Name, branchdom.DetectBranchType(b.Name, nil, nil))
		if err != nil {
			continue
		}
		nb.SetProtected(b.Protected)
		if b.CommitSHA != "" {
			nb.UpdateLastCommit(b.CommitSHA, "", "", "", now)
		}
		if err := s.branchRepo.Create(ctx, nb); err != nil {
			// Concurrent create — fall back to the existing row.
			if existing2, e2 := s.branchRepo.GetByName(ctx, repositoryID, b.Name); e2 == nil && existing2 != nil {
				if b.Name == r.DefaultBranch {
					id := existing2.ID()
					defaultBranchID = &id
				}
			}
			continue
		}
		if b.Name == r.DefaultBranch {
			id := nb.ID()
			defaultBranchID = &id
		}
	}

	// Provider's default branch is authoritative (atomic single-default).
	if defaultBranchID != nil {
		if err := s.branchRepo.SetDefaultBranch(ctx, repositoryID, *defaultBranchID); err != nil {
			s.logger.Warn("failed to set default branch", "repository_id", repositoryID.String(), "error", err)
		}
	}
}
