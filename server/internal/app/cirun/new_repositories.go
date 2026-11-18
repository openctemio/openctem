package cirun

// New repositories of an all-projects trust configuration (rules
// all_repositories, self-managed GitLab only). Any user of the instance can
// create a project and protect its branches, so a project seen for the first
// time is not trusted on sight: it is recorded as pending for an
// administrator, who approves the project (it joins Repositories), its whole
// group (the group joins Owners: every current and future project of that
// group is admitted with no further approval) or blocks either (refused at
// once, reversible). Only approved projects reach scope. Design:
// docs/architecture/ci-runner-identity.md ("Every project on this GitLab").

import (
	"context"
	"fmt"
	"slices"
	"strings"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// SetNewRepositoryStore wires the new repositories. Without it an
// all-projects configuration admits approved repositories only.
func (s *Service) SetNewRepositoryStore(st cirun.NewRepositoryStore) { s.newRepos = st }

// checkNewRepository decides a job's repository under an all-projects
// configuration: blocked (refused), approved (admitted), or new (recorded
// as pending, refused until approved unless the configuration admits new
// repositories).
func (s *Service) checkNewRepository(ctx context.Context, tenantID shared.ID, cfg *cirun.TrustConfig, c cirun.Claims) (*cirun.Refusal, error) {
	group, project := strings.ToLower(c.Owner()), strings.ToLower(c.Repository)
	if s.newRepos != nil {
		blocked, err := s.newRepos.NewRepositoryBlocked(ctx, tenantID, cfg.ID, group, project)
		if err != nil {
			return nil, fmt.Errorf("check blocked repository: %w", err)
		}
		if blocked {
			return &cirun.Refusal{Code: cirun.RefuseRepositoryBlocked,
				Detail: fmt.Sprintf("project %q or its group %q is blocked", project, group)}, nil
		}
	}
	if cfg.Rules.ApprovedRepository(c) {
		return nil, nil
	}
	pending := &cirun.Refusal{Code: cirun.RefuseRepositoryPending,
		Detail: fmt.Sprintf("project %q is new and waits for an administrator's approval", project)}
	if s.newRepos == nil {
		return pending, nil
	}
	recorded, firstOfGroup, err := s.newRepos.RecordPendingRepository(ctx, tenantID, cfg.ID, group, project, s.now())
	if err != nil {
		return nil, fmt.Errorf("record new repository: %w", err)
	}
	if !recorded {
		s.log.Warn("ci new repository not recorded: pending list full", "trust_config_id", cfg.ID.String())
	}
	if recorded && firstOfGroup && cfg.Rules.NotifyNewGroups {
		s.alertAdmins(ctx, tenantID, AdminAlert{
			EventType: string(integration.EventTypeCINewRepositoryGroup), Severity: notificationdom.SeverityMedium,
			Title: fmt.Sprintf("A new GitLab group asks to send CI results: %s", group),
			Body: fmt.Sprintf("Project %s of group %s ran a CI job under the trust configuration %q, which admits every project "+
				"on its GitLab. Approve the project or its whole group, or block it, under CI/CD > Trusted pipelines > New repositories.",
				project, group, cfg.Name),
			URL: "/ci-cd?tab=setup&section=new-repositories", Metadata: map[string]any{"trust_config_id": cfg.ID.String(),
				"group": group, "project": project},
		})
	}
	if cfg.Rules.AdmitNewRepositories {
		return nil, nil
	}
	return pending, nil
}

// NewRepositoryList is the configuration's new repositories.
type NewRepositoryList struct {
	Config *cirun.TrustConfig
	Rows   []cirun.NewRepository
}

// ListNewRepositories lists an all-projects configuration's pending and
// blocked projects and groups.
func (s *Service) ListNewRepositories(ctx context.Context, tenantID, configID shared.ID) (*NewRepositoryList, error) {
	cfg, err := s.repo.GetTrustConfig(ctx, tenantID, configID)
	if err != nil {
		return nil, err
	}
	out := &NewRepositoryList{Config: cfg, Rows: []cirun.NewRepository{}}
	if s.newRepos == nil || !cfg.Rules.AllRepositories {
		return out, nil
	}
	if out.Rows, err = s.newRepos.ListNewRepositories(ctx, tenantID, configID); err != nil {
		return nil, err
	}
	return out, nil
}

// ErrNotAllRepositories refuses a decision on a configuration that names
// its owners and repositories.
var ErrNotAllRepositories = fmt.Errorf("%w: the trust configuration does not admit every project", shared.ErrValidation)

// cleanDecision checks and normalizes a decision.
func cleanDecision(d cirun.NewRepositoryDecision) (cirun.NewRepositoryDecision, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", shared.ErrValidation, fmt.Sprintf(format, a...))
	}
	switch d.Action {
	case cirun.DecisionApprove, cirun.DecisionBlock, cirun.DecisionUnblock:
	default:
		return d, bad("decision must be approve, block or unblock")
	}
	if len(d.Items) == 0 || len(d.Items) > cirun.MaxDecisionItems {
		return d, bad("items: 1 to %d", cirun.MaxDecisionItems)
	}
	out := cirun.NewRepositoryDecision{Action: d.Action, Items: make([]cirun.NewRepositoryItem, 0, len(d.Items))}
	for _, it := range d.Items {
		name := strings.ToLower(strings.Trim(strings.TrimSpace(it.Name), "/"))
		switch {
		case name == "" || len(name) > 500 || strings.ContainsAny(name, " \t\r\n*?[\\"):
			return d, bad("items: %q is not a project path or group", it.Name)
		case it.Kind == cirun.NewRepoGroup && strings.Contains(name, "/"):
			return d, bad("items: a group is one top-level group name, %q is a path", it.Name)
		case it.Kind == cirun.NewRepoProject && !strings.Contains(name, "/"):
			return d, bad("items: a project is a full path such as group/project, %q is not", it.Name)
		case it.Kind != cirun.NewRepoGroup && it.Kind != cirun.NewRepoProject:
			return d, bad("items: kind must be project or group")
		}
		item := cirun.NewRepositoryItem{Kind: it.Kind, Name: name}
		if !slices.Contains(out.Items, item) {
			out.Items = append(out.Items, item)
		}
	}
	return out, nil
}

// DecideNewRepositories approves, blocks or unblocks projects and groups of
// an all-projects configuration. Approving adds them to the configuration
// (a group to Owners: every current and future project of the group is
// admitted; a project to Repositories) and clears their pending rows;
// blocking refuses them at once (and takes them out of the configuration);
// unblocking makes them new again. The configuration change is the ordinary
// audited change, and the decision is audited with its items.
func (s *Service) DecideNewRepositories(ctx context.Context, tenantID, configID shared.ID, d cirun.NewRepositoryDecision, a Actor) (*cirun.TrustConfig, error) {
	d, err := cleanDecision(d)
	if err != nil {
		return nil, err
	}
	cur, err := s.repo.GetTrustConfig(ctx, tenantID, configID)
	if err != nil {
		return nil, err
	}
	if !cur.Rules.AllRepositories {
		return nil, ErrNotAllRepositories
	}
	if s.newRepos == nil {
		return nil, fmt.Errorf("new repositories are not available")
	}
	rules := cur.Rules
	rules.Owners, rules.Repositories = slices.Clone(rules.Owners), slices.Clone(rules.Repositories)
	for _, it := range d.Items {
		list := &rules.Repositories
		if it.Kind == cirun.NewRepoGroup {
			list = &rules.Owners
		}
		switch d.Action {
		case cirun.DecisionApprove:
			if !slices.Contains(*list, it.Name) {
				*list = append(*list, it.Name)
			}
		case cirun.DecisionBlock:
			*list = slices.DeleteFunc(*list, func(v string) bool { return v == it.Name })
		}
	}
	by := nonEmpty(a.Email, a.UserID)
	updateConfig := func() (*cirun.TrustConfig, error) {
		if slices.Equal(rules.Owners, cur.Rules.Owners) && slices.Equal(rules.Repositories, cur.Rules.Repositories) {
			return cur, nil
		}
		enabled, manage := cur.Enabled, cur.ManageScope
		return s.UpdateTrustConfig(ctx, tenantID, configID, TrustConfigInput{Name: cur.Name, Provider: string(cur.Provider),
			Issuer: cur.Issuer, Audience: cur.Audience, DefaultBranch: cur.DefaultBranch, Rules: rules,
			Enabled: &enabled, ManageScope: &manage}, a)
	}
	var next *cirun.TrustConfig
	if d.Action == cirun.DecisionBlock {
		// The block is what refuses: record it before the configuration
		// stops listing the item.
		if err := s.newRepos.ApplyNewRepositoryDecision(ctx, tenantID, configID, d, by, s.now()); err != nil {
			return nil, fmt.Errorf("record decision: %w", err)
		}
		if next, err = updateConfig(); err != nil {
			return nil, err
		}
	} else {
		if next, err = updateConfig(); err != nil {
			return nil, err
		}
		if err := s.newRepos.ApplyNewRepositoryDecision(ctx, tenantID, configID, d, by, s.now()); err != nil {
			return nil, fmt.Errorf("record decision: %w", err)
		}
	}
	names := make([]string, 0, len(d.Items))
	for _, it := range d.Items {
		names = append(names, it.Kind+":"+it.Name)
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCINewRepositoriesDecided, auditdom.ResourceTypeCITrustConfig, configID.String()).
		WithResourceName(cur.Name).
		WithMessage(fmt.Sprintf("CI trust configuration %q: %s %s", cur.Name, d.Action, logger.SanitizeValue(strings.Join(names, ", ")))).
		WithMetadata("decision", d.Action).
		WithMetadata("items", names))
	return next, nil
}
