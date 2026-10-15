package integration

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/scm"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	branchdom "github.com/openctemio/openctem/api/pkg/domain/branch"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
			branchClient, _ = s.scmClientForIntegration(ctx, tenantID, intgID)
		}
	}

	webHost := ""
	if intgID, err := shared.IDFromString(input.IntegrationID); err == nil {
		if intg, err := s.repo.GetByTenantAndID(ctx, tenantID, intgID); err == nil && intg != nil {
			webHost = integrationWebHost(intg.Provider(), intg.BaseURL())
		}
	}

	result := &ImportReposResult{Total: len(repos)}
	for i := range repos {
		r := repos[i]
		if r.FullName == "" || (r.IsArchived && !input.IncludeArchived) {
			result.Skipped++
			continue
		}
		if !repositoryOnHost(r, webHost) {
			// Imported, but without an identity: no repository id is
			// recorded and the asset keeps the plain full name, so the
			// listing cannot claim another host's repository of that id.
			s.logger.Warn("repository imported without its id: its address is not on the integration's host",
				"integration_id", input.IntegrationID, "full_name", r.FullName)
			r = withoutIdentity(r)
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

// SyncAllConnectedSCMIntegrations imports repositories (and branches) for every
// connected SCM integration across all tenants. Used by the scheduled SCM sync
// controller. Per-integration failures (e.g. an expired token — which also marks
// that integration's status) are logged and skipped so one bad connection does
// not abort the run. Returns the total repos created+updated.
func (s *IntegrationService) SyncAllConnectedSCMIntegrations(ctx context.Context) (int, error) {
	if s.assetRepo == nil || s.repoExtRepo == nil {
		return 0, nil // import not wired — nothing to do
	}
	category := integrationdom.CategorySCM
	// No status filter: we want connected integrations AND those previously
	// flipped to error/expired by a transient auth failure, so a recovered
	// token re-syncs and (via ListSCMRepositories' recovery edge) flips the
	// status back to connected. Integrations the user deliberately disabled or
	// disconnected are skipped in the loop below.
	listed, err := s.repo.List(ctx, integrationdom.Filter{
		Category: &category,
		PerPage:  1000,
	})
	if err != nil {
		return 0, fmt.Errorf("list SCM integrations: %w", err)
	}

	total := 0
	for _, intg := range listed.Data {
		switch intg.Status() {
		case integrationdom.StatusConnected, integrationdom.StatusError, integrationdom.StatusExpired:
			// retry these — a successful sync recovers an errored connection
		default:
			continue // disabled / disconnected / pending — leave alone
		}
		res, err := s.ImportSCMRepositories(ctx, ImportReposInput{
			IntegrationID: intg.ID().String(),
			TenantID:      intg.TenantID().String(),
		})
		if err != nil {
			s.logger.Warn("scheduled SCM sync failed for integration",
				"integration_id", intg.ID().String(), "error", err)
			continue
		}
		total += res.Created + res.Updated
	}
	s.logger.Info("scheduled SCM sync complete",
		"integrations", len(listed.Data), "repos_synced", total)
	return total, nil
}

// RepositoryIdentity finds a repository asset by the code host's immutable
// repository id and renames it (postgres.RepositoryIdentityRepository).
type RepositoryIdentity interface {
	FindRepositoryByProviderID(ctx context.Context, tenantID shared.ID, host, repoID string) (shared.ID, bool, error)
	RenameRepositoryAsset(ctx context.Context, tenantID, assetID shared.ID, name string) (bool, error)
}

// RenameAuditor records repository asset renames (auditapp.AuditService).
type RenameAuditor interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// SetRepositoryIdentity makes repository import find a repository by its
// code host id first and name new assets host/path, the name CI uses, so one
// repository is one asset whichever reports it first. Renames are audited
// through audit (nil: logged only). Without it import dedups by full name
// only.
func (s *IntegrationService) SetRepositoryIdentity(r RepositoryIdentity, audit RenameAuditor) {
	s.repoIdentity, s.renameAudit = r, audit
}

// integrationWebHost is the lower-case host the integration's repositories
// live on: the configured base URL's host (a self-hosted server), else the
// provider's public host; an API host of a public provider maps to its web
// host (api.github.com -> github.com). "" when it cannot be told.
func integrationWebHost(provider integrationdom.Provider, baseURL string) string {
	if strings.TrimSpace(baseURL) == "" {
		switch provider {
		case integrationdom.ProviderGitHub:
			return "github.com"
		case integrationdom.ProviderGitLab:
			return "gitlab.com"
		case integrationdom.ProviderBitbucket:
			return "bitbucket.org"
		case integrationdom.ProviderAzureDevOps:
			return "dev.azure.com"
		}
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	host := strings.ToLower(u.Host)
	switch host {
	case "api.github.com":
		return "github.com"
	case "api.bitbucket.org":
		return "bitbucket.org"
	}
	return host
}

// withoutIdentity drops what would tie an imported repository to a code host
// identity (its id and addresses), keeping the rest of its metadata.
func withoutIdentity(r scm.Repository) scm.Repository {
	r.ID, r.HTMLURL, r.CloneURL, r.SSHURL = "", "", "", ""
	return r
}

// repositoryOnHost reports whether a repository the code host listed lives
// on that code host: its web address, or else its clone address, is on host.
// A repository a code host lists on another host (a tenant's self-hosted
// server answering with github.com addresses) is imported without its id
// (withoutIdentity): the id would otherwise claim the public host's
// repository of that id. An unknown integration host trusts no address.
func repositoryOnHost(r scm.Repository, host string) bool {
	if host == "" {
		return false
	}
	h, _ := cirun.RepositoryFromURL(r.HTMLURL)
	if h == "" {
		h, _ = cirun.RepositoryFromURL(r.CloneURL)
	}
	return h == "" || strings.EqualFold(h, host)
}

// upsertRepositoryAsset creates (or refreshes) a repository asset + extension
// from an SCM repository DTO. Returns created=true on first import.
//
// One repository is one asset, keyed by the code host and its immutable
// repository id: the asset is found by that id first (a renamed or
// transferred repository, or one CI reported first), then by full name (an
// asset imported before), then by its host/path name (created by CI). A new
// asset is named host/path, and an existing one is renamed to it when the
// name is free.
func (s *IntegrationService) upsertRepositoryAsset(ctx context.Context, tenantID shared.ID, r scm.Repository) (bool, error) {
	visibility := assetdom.RepoVisibilityPublic
	if r.IsPrivate {
		visibility = assetdom.RepoVisibilityPrivate
	}
	canonical, host := canonicalRepositoryName(r)
	refresh := func(ext *assetdom.RepositoryExtension) (bool, error) {
		applyRepoFields(ext, r, visibility)
		if err := s.repoExtRepo.Update(ctx, ext); err != nil {
			return false, fmt.Errorf("update repository extension: %w", err)
		}
		s.renameToCanonical(ctx, tenantID, ext.AssetID(), canonical)
		return false, nil
	}

	if s.repoIdentity != nil && canonical != "" && r.ID != "" {
		id, found, err := s.repoIdentity.FindRepositoryByProviderID(ctx, tenantID, host, r.ID)
		if err != nil {
			return false, err
		}
		if found {
			if ext, _ := s.repoExtRepo.GetByAssetID(ctx, id); ext != nil {
				return refresh(ext)
			}
		}
	}
	// Dedup by full name within the tenant — refresh metadata if it exists.
	if existing, _ := s.repoExtRepo.GetByFullName(ctx, tenantID, r.FullName); existing != nil {
		return refresh(existing)
	}
	name := r.FullName
	if canonical != "" {
		name = canonical
		// A repository CI reported first is already an asset of that name.
		if a, err := s.assetRepo.GetByName(ctx, tenantID, canonical); err == nil && a != nil && a.Type() == assetdom.AssetTypeRepository {
			if ext, _ := s.repoExtRepo.GetByAssetID(ctx, a.ID()); ext != nil {
				return refresh(ext)
			}
		}
	}

	a, err := assetdom.NewAssetWithTenant(tenantID, name, assetdom.AssetTypeRepository, assetdom.CriticalityMedium)
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

// canonicalRepositoryName is a repository's asset name, its code host and
// path from its web (else clone) address in lower case
// ("github.com/acme/api"), and the host; ("", "") without a usable address.
func canonicalRepositoryName(r scm.Repository) (name, host string) {
	host, path := cirun.RepositoryFromURL(r.HTMLURL)
	if host == "" || path == "" {
		host, path = cirun.RepositoryFromURL(r.CloneURL)
	}
	if host == "" || path == "" {
		return "", ""
	}
	return assetdom.NormalizeName(host+"/"+path, assetdom.AssetTypeRepository, ""), host
}

// renameToCanonical gives an existing repository asset its host/path name
// when no other asset holds it (best effort: a name held by a duplicate is
// settled by the duplicate merge).
func (s *IntegrationService) renameToCanonical(ctx context.Context, tenantID, assetID shared.ID, canonical string) {
	if s.repoIdentity == nil || canonical == "" {
		return
	}
	oldName := ""
	if a, err := s.assetRepo.GetByID(ctx, tenantID, assetID); err == nil && a != nil {
		oldName = a.Name()
	}
	renamed, err := s.repoIdentity.RenameRepositoryAsset(ctx, tenantID, assetID, canonical)
	if err != nil {
		s.logger.Warn("repository asset not renamed", "asset_id", assetID.String(), "error", err)
		return
	}
	if !renamed || s.renameAudit == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionAssetRenamed, auditdom.ResourceTypeAsset, assetID.String()).
		WithResourceName(canonical).
		WithMessage(fmt.Sprintf("Repository asset renamed from %s to %s by repository import", oldName, canonical)).
		WithMetadata("old_name", oldName).
		WithMetadata("new_name", canonical).
		WithMetadata("source", "repository_import")
	if err := s.renameAudit.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorEmail: "system:repository-import"}, ev); err != nil {
		s.logger.Warn("repository rename not audited", "asset_id", assetID.String(), "error", err)
	}
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

// scmClientForIntegration builds an SCM client for an integration of the
// tenant (resolving org, base URL and decrypted credentials), mirroring
// ListSCMRepositories. The lookup is tenant-scoped: an integration of another
// tenant is not found, so its credentials are never decrypted here.
func (s *IntegrationService) scmClientForIntegration(ctx context.Context, tenantID, intgID shared.ID) (scm.Client, error) {
	intg, err := s.repo.GetByTenantAndID(ctx, tenantID, intgID)
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
	token, err := s.decryptCredentials(intg)
	if err != nil {
		return nil, err
	}
	return s.scmFactory.CreateClient(scm.Config{
		Provider:     toSCMProvider(intg.Provider()),
		BaseURL:      baseURL,
		AccessToken:  token,
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
