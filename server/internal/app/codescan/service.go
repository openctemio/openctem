// Package codescan manages platform code scanning of repositories: the
// tenant's template, each repository's settings, and the baseline state of
// its protected branches. Design: docs/rfcs/RFC-091-code-scanning-baseline.md.
package codescan

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/codescan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Auditor writes audit records.
type Auditor interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Actor is who acts.
type Actor struct {
	UserID    string
	Email     string
	IP        string
	UserAgent string
}

// Service manages code scanning settings and baselines.
type Service struct {
	repo  codescan.Repository
	audit Auditor
	log   *logger.Logger
	now   func() time.Time
}

// NewService creates the service; audit may be nil.
func NewService(repo codescan.Repository, audit Auditor, log *logger.Logger) *Service {
	return &Service{repo: repo, audit: audit, log: log, now: time.Now}
}

// SettingsInput is a change of settings.
type SettingsInput struct {
	ProtectedBranches []string
	Capabilities      []string
	Schedule          string
	Routing           string
	Enabled           bool
}

// Template returns the tenant's template (the built-in defaults when it has
// none) and where it comes from.
func (s *Service) Template(ctx context.Context, tenantID shared.ID) (codescan.Settings, string, error) {
	t, err := s.repo.GetSettings(ctx, tenantID, nil)
	if err != nil {
		return codescan.Settings{}, "", err
	}
	eff, src := codescan.Effective(tenantID, nil, t)
	return eff, src, nil
}

// UpdateTemplate stores the tenant's template.
func (s *Service) UpdateTemplate(ctx context.Context, tenantID shared.ID, in SettingsInput, a Actor) (codescan.Settings, error) {
	set := settingsFrom(tenantID, nil, in, a)
	if err := set.Validate(); err != nil {
		return codescan.Settings{}, err
	}
	if err := s.repo.UpsertSettings(ctx, &set); err != nil {
		return codescan.Settings{}, err
	}
	s.logAudit(ctx, tenantID, a, auditdom.ActionCodeScanSettingsUpdated, "template", "Code scanning template updated", set)
	return set, nil
}

// RepositoryStatus is one repository's code scanning: its effective
// settings and its branches, the protected ones marked.
type RepositoryStatus struct {
	Repository codescan.RepositoryRef
	Settings   codescan.Settings
	Source     string
	Branches   []BranchStatus
}

// BranchStatus is a branch with whether the settings protect it.
type BranchStatus struct {
	codescan.Branch
	Protected bool
}

// Summary counts a repository's protected branches by baseline state.
func (r RepositoryStatus) Summary() map[string]int {
	out := map[string]int{}
	for _, b := range r.Branches {
		if b.Protected {
			out[b.BaselineState]++
		}
	}
	return out
}

// Repository returns one repository's code scanning. The caller has checked
// the data scope.
func (s *Service) Repository(ctx context.Context, tenantID, assetID shared.ID) (*RepositoryStatus, error) {
	ref, err := s.repo.GetRepository(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	list, err := s.statuses(ctx, tenantID, []codescan.RepositoryRef{*ref})
	if err != nil {
		return nil, err
	}
	return &list[0], nil
}

// ListRepositories lists repositories within a data scope with their code
// scanning.
func (s *Service) ListRepositories(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit, offset int) ([]RepositoryStatus, int, error) {
	refs, total, err := s.repo.ListRepositories(ctx, tenantID, scope, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	list, err := s.statuses(ctx, tenantID, refs)
	return list, total, err
}

func (s *Service) statuses(ctx context.Context, tenantID shared.ID, refs []codescan.RepositoryRef) ([]RepositoryStatus, error) {
	ids := make([]shared.ID, len(refs))
	for i, r := range refs {
		ids[i] = r.AssetID
	}
	template, err := s.repo.GetSettings(ctx, tenantID, nil)
	if err != nil {
		return nil, err
	}
	own, err := s.repo.RepositorySettings(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	branches, err := s.repo.Branches(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	out := make([]RepositoryStatus, 0, len(refs))
	for _, ref := range refs {
		var mine *codescan.Settings
		if o, ok := own[ref.AssetID]; ok {
			mine = &o
		}
		eff, src := codescan.Effective(tenantID, mine, template)
		st := RepositoryStatus{Repository: ref, Settings: eff, Source: src, Branches: []BranchStatus{}}
		for _, b := range branches[ref.AssetID] {
			def := ref.DefaultBranch
			if b.IsDefault {
				def = b.Name
			}
			st.Branches = append(st.Branches, BranchStatus{Branch: b, Protected: eff.Matches(b.Name, def)})
		}
		out = append(out, st)
	}
	return out, nil
}

// UpdateRepository stores a repository's own settings. The caller has checked
// the data scope.
func (s *Service) UpdateRepository(ctx context.Context, tenantID, assetID shared.ID, in SettingsInput, a Actor) (*RepositoryStatus, error) {
	ref, err := s.repo.GetRepository(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	set := settingsFrom(tenantID, &assetID, in, a)
	if err := set.Validate(); err != nil {
		return nil, err
	}
	if err := s.repo.UpsertSettings(ctx, &set); err != nil {
		return nil, err
	}
	s.logAudit(ctx, tenantID, a, auditdom.ActionCodeScanSettingsUpdated, ref.Name,
		fmt.Sprintf("Code scanning settings of repository '%s' updated", ref.Name), set)
	return s.Repository(ctx, tenantID, assetID)
}

// ResetRepository removes a repository's own settings: it inherits the
// template again.
func (s *Service) ResetRepository(ctx context.Context, tenantID, assetID shared.ID, a Actor) (*RepositoryStatus, error) {
	ref, err := s.repo.GetRepository(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	if err := s.repo.DeleteSettings(ctx, tenantID, assetID); err != nil {
		return nil, err
	}
	s.logAudit(ctx, tenantID, a, auditdom.ActionCodeScanSettingsUpdated, ref.Name,
		fmt.Sprintf("Code scanning settings of repository '%s' reset to the template", ref.Name), codescan.Settings{})
	return s.Repository(ctx, tenantID, assetID)
}

// Rebaseline queues a full scan of the repository's protected branches (the
// default branch is recorded first when no branch is known yet). It returns
// how many branches were queued; branches already queued or running are
// left as they are.
func (s *Service) Rebaseline(ctx context.Context, tenantID, assetID shared.ID, a Actor) (int, *RepositoryStatus, error) {
	ref, err := s.repo.GetRepository(ctx, tenantID, assetID)
	if err != nil {
		return 0, nil, err
	}
	if ref.DefaultBranch != "" {
		if err := s.repo.EnsureDefaultBranch(ctx, tenantID, assetID, ref.DefaultBranch); err != nil {
			return 0, nil, err
		}
	}
	st, err := s.Repository(ctx, tenantID, assetID)
	if err != nil {
		return 0, nil, err
	}
	if !st.Settings.Enabled {
		return 0, nil, fmt.Errorf("%w: code scanning is turned off for this repository", shared.ErrValidation)
	}
	var ids []shared.ID
	for _, b := range st.Branches {
		if b.Protected {
			ids = append(ids, b.ID)
		}
	}
	if len(ids) == 0 {
		return 0, nil, codescan.ErrNoProtectedBranch
	}
	n, err := s.repo.QueueFullScan(ctx, tenantID, assetID, ids, codescan.TriggerManual)
	if err != nil {
		return 0, nil, err
	}
	s.logAudit(ctx, tenantID, a, auditdom.ActionCodeScanRebaselineRequested, ref.Name,
		fmt.Sprintf("Full scan of %d protected branch(es) of repository '%s' requested", n, ref.Name), codescan.Settings{})
	st, err = s.Repository(ctx, tenantID, assetID)
	return n, st, err
}

func settingsFrom(tenantID shared.ID, assetID *shared.ID, in SettingsInput, a Actor) codescan.Settings {
	set := codescan.Settings{TenantID: tenantID, RepositoryAssetID: assetID, ProtectedBranches: in.ProtectedBranches,
		Capabilities: in.Capabilities, Schedule: in.Schedule, Routing: in.Routing, Enabled: in.Enabled}
	if uid, err := shared.IDFromString(a.UserID); err == nil {
		set.UpdatedBy = &uid
	}
	return set
}

func (s *Service) logAudit(ctx context.Context, tenantID shared.ID, a Actor, action auditdom.Action, name, msg string, set codescan.Settings) {
	if s.audit == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeCodeScan, name).WithResourceName(name).WithMessage(msg)
	if len(set.ProtectedBranches) > 0 {
		ev = ev.WithMetadata("protected_branches", set.ProtectedBranches).WithMetadata("capabilities", set.Capabilities).
			WithMetadata("schedule", set.Schedule).WithMetadata("routing", set.Routing).WithMetadata("enabled", set.Enabled)
	}
	if err := s.audit.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorID: a.UserID,
		ActorEmail: a.Email, ActorIP: a.IP, UserAgent: a.UserAgent}, ev); err != nil {
		s.log.Warn("code scanning audit record not written", "action", action.String(), "error", logger.SanitizeError(err))
	}
}
