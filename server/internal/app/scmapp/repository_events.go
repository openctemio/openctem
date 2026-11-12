package scmapp

// Repository lifecycle events from the GitHub App webhook: a repository
// renamed, transferred, archived or unarchived on the code host. They keep
// the platform consistent with the host without waiting for the next CI run:
//
//   - renamed / transferred: the repository asset (found by the host's
//     immutable repository id, never by name) and its pipelines take the new
//     name. The asset, its findings, branches and policies stay. A name that
//     another asset of the tenant holds is left alone (logged).
//   - archived / unarchived: the repository's pipelines are archived (no
//     stale alerts, findings not marked not observed) and revived.
//
// Trust: the delivery is verified by signature; the tenant is the one the
// installation is bound to, and every lookup is scoped to it. A repository id
// the tenant has no asset or pipeline for changes nothing. Trust
// configurations are never edited by a webhook: a name pattern that no longer
// matches the new name stays an administrator's decision.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/scmapp"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RepositoryLifecycle is what repository events change
// (postgres.RepositoryIdentityRepository). Every method is tenant-scoped.
type RepositoryLifecycle interface {
	FindRepositoryByProviderID(ctx context.Context, tenantID shared.ID, host, repoID string) (shared.ID, bool, error)
	RenameRepositoryAsset(ctx context.Context, tenantID, assetID shared.ID, name string) (bool, error)
	RenamePipelineRepository(ctx context.Context, tenantID shared.ID, provider, issuer, repoID, name string) (int64, error)
	SetPipelinesRepositoryArchived(ctx context.Context, tenantID shared.ID, provider, issuer, repoID string, archived bool) (int64, error)
}

// SetRepositoryLifecycle enables repository events; without it they are
// acknowledged and ignored.
func (s *Service) SetRepositoryLifecycle(l RepositoryLifecycle) { s.lifecycle = l }

const (
	actionArchived   = "archived"
	actionUnarchived = "unarchived"
)

type repositoryEvent struct {
	Action     string `json:"action"`
	Repository struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

func (s *Service) handleRepositoryEvent(ctx context.Context, body []byte) error {
	if s.lifecycle == nil {
		return nil
	}
	var p repositoryEvent
	if err := json.Unmarshal(body, &p); err != nil || p.Installation.ID <= 0 || p.Repository.ID <= 0 {
		return nil //nolint:nilerr // a verified but unusable delivery is acknowledged and ignored
	}
	switch p.Action {
	case "renamed", "transferred", actionArchived, actionUnarchived:
	default:
		return nil
	}
	inst, err := s.repo.GetByInstallationID(ctx, scmapp.ProviderGitHub, p.Installation.ID)
	if err != nil {
		if err == scmapp.ErrNotFound { //nolint:errorlint // sentinel returned as is
			return nil
		}
		return err
	}
	if inst.Status != scmapp.StatusActive {
		return nil
	}
	repoID := strconv.FormatInt(p.Repository.ID, 10)
	switch p.Action {
	case actionArchived, actionUnarchived:
		archived := p.Action == actionArchived
		n, err := s.lifecycle.SetPipelinesRepositoryArchived(ctx, inst.TenantID, string(cirun.ProviderGitHub), cirun.GitHubIssuer, repoID, archived)
		if err != nil {
			return err
		}
		if n > 0 {
			s.logAudit(ctx, inst.TenantID, Actor{Email: "github"},
				auditapp.NewSuccessEvent(auditdom.ActionSCMAppStatusChanged, auditdom.ResourceTypeSCMApp, inst.ID.String()).
					WithResourceName(p.Repository.FullName).
					WithMessage(fmt.Sprintf("Repository %s was %s on GitHub: %d CI pipeline(s) updated", p.Repository.FullName, p.Action, n)).
					WithMetadata("repository_id", repoID).
					WithMetadata("event", p.Action))
		}
		return nil
	}
	// renamed / transferred
	u, err := url.Parse(p.Repository.HTMLURL)
	if err != nil || u.Host == "" || p.Repository.FullName == "" {
		return nil //nolint:nilerr // a delivery without the repository's address is ignored
	}
	host := strings.ToLower(u.Host)
	name := asset.NormalizeName(host+"/"+p.Repository.FullName, asset.AssetTypeRepository, "")
	if _, err := s.lifecycle.RenamePipelineRepository(ctx, inst.TenantID, string(cirun.ProviderGitHub), cirun.GitHubIssuer, repoID, name); err != nil {
		return err
	}
	id, found, err := s.lifecycle.FindRepositoryByProviderID(ctx, inst.TenantID, host, repoID)
	if err != nil || !found {
		return err
	}
	renamed, err := s.lifecycle.RenameRepositoryAsset(ctx, inst.TenantID, id, name)
	if err != nil {
		return err
	}
	if !renamed {
		s.log.Info("repository event: asset keeps its name (unchanged or the new name is taken)", "asset_id", id.String(), "event", p.Action)
		return nil
	}
	s.logAudit(ctx, inst.TenantID, Actor{Email: "github"},
		auditapp.NewSuccessEvent(auditdom.ActionAssetRenamed, auditdom.ResourceTypeAsset, id.String()).
			WithResourceName(name).
			WithMessage(fmt.Sprintf("Repository asset renamed to %s (GitHub repository %s)", name, p.Action)).
			WithMetadata("new_name", name).
			WithMetadata("repository_id", repoID).
			WithMetadata("source", "github_webhook"))
	return nil
}
