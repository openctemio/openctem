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
	"sync"
	"time"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// SetNewRepositoryStore wires the new repositories. Without it an
// all-projects configuration admits approved repositories only.
func (s *Service) SetNewRepositoryStore(st cirun.NewRepositoryStore) { s.newRepos = st }

// pendingRefusal is the refusal of a project the configuration has not
// approved, or nil when it is approved. The preview and the exchange share it.
func pendingRefusal(cfg *cirun.TrustConfig, c cirun.Claims) *cirun.Refusal {
	if cfg.Rules.ApprovedRepository(c) {
		return nil
	}
	return &cirun.Refusal{Code: cirun.RefuseRepositoryPending,
		Detail: fmt.Sprintf("project %q is new and waits for an administrator's approval", strings.ToLower(c.Repository))}
}

// checkNewRepository decides a job's repository under an all-projects
// configuration: blocked (refused), approved (admitted when it carries the
// project id it was approved with), or new (recorded as pending with its
// verified ids, refused until approved unless the configuration admits new
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
	pending := pendingRefusal(cfg, c)
	if pending == nil {
		if s.newRepos == nil {
			return nil, nil
		}
		// An approved project is bound to the project id it was seen and
		// approved with: a project that took the path over since is refused.
		approvedID, ok, err := s.newRepos.ApprovedProjectID(ctx, tenantID, cfg.ID, project)
		if err != nil {
			return nil, fmt.Errorf("check approved repository: %w", err)
		}
		if ok && approvedID != "" && approvedID != strings.TrimSpace(c.RepositoryID) {
			return &cirun.Refusal{Code: RefuseRepositoryBinding,
				Detail: fmt.Sprintf("project %q was approved with project id %s; the token names id %s", project, approvedID, c.RepositoryID)}, nil
		}
		return nil, nil
	}
	if s.newRepos == nil {
		return pending, nil
	}
	outcome, firstOfGroup, err := s.newRepos.RecordPendingRepository(ctx, tenantID, cfg.ID, cirun.Sighting{
		Group: group, Project: project, ProjectID: clip(c.RepositoryID, 64),
		NamespacePath: clip(c.OwnerName, 500), NamespaceID: clip(c.OwnerID, 64)}, s.now())
	if err != nil {
		return nil, fmt.Errorf("record new repository: %w", err)
	}
	if outcome != cirun.SightingRecorded {
		s.log.Warn("ci new repository not recorded: pending list full", "trust_config_id", cfg.ID.String(), "outcome", outcome)
	}
	if outcome == cirun.SightingRecorded && firstOfGroup && cfg.Rules.NotifyNewGroups {
		s.noticeNewGroup(ctx, tenantID, cfg, group, project)
	}
	if cfg.Rules.AdmitNewRepositories {
		return nil, nil
	}
	return pending, nil
}

// clip trims v; a value longer than n bytes is not a real id and is dropped.
func clip(v string, n int) string {
	v = strings.TrimSpace(v)
	if len(v) > n {
		return ""
	}
	return v
}

// Notices of new groups: at most newGroupNoticesPerHour per configuration
// and hour (any user of the instance can create namespaces); the rest are
// counted and the next notice after the hour says how many were held back.
const (
	newGroupNoticesPerHour = 10
	newGroupNoticeWindow   = time.Hour
	newGroupNoticeConfigs  = 1000
)

// groupNoticeBudget is one configuration's notices in the current window.
type groupNoticeBudget struct {
	start time.Time
	sent  int
	held  int
}

// groupNotices throttles the new-group notices per configuration, in memory
// (per server), with bounded memory: past newGroupNoticeConfigs tracked
// configurations it stays quiet rather than grow.
type groupNotices struct {
	mu  sync.Mutex
	cfg map[string]*groupNoticeBudget
}

// take reports whether a notice may go out now and how many were held back
// since the last one that went out.
func (g *groupNotices) take(cfgID string, now time.Time) (send bool, held int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cfg == nil {
		g.cfg = map[string]*groupNoticeBudget{}
	}
	b := g.cfg[cfgID]
	if b == nil {
		if len(g.cfg) >= newGroupNoticeConfigs {
			for k, v := range g.cfg {
				if now.Sub(v.start) >= newGroupNoticeWindow && v.held == 0 {
					delete(g.cfg, k)
				}
			}
			if len(g.cfg) >= newGroupNoticeConfigs {
				return false, 0
			}
		}
		b = &groupNoticeBudget{start: now}
		g.cfg[cfgID] = b
	}
	if now.Sub(b.start) >= newGroupNoticeWindow {
		b.start, b.sent = now, 0
	}
	if b.sent >= newGroupNoticesPerHour {
		b.held++
		return false, 0
	}
	b.sent++
	held, b.held = b.held, 0
	return true, held
}

// noticeNewGroup tells the administrators that a project of a group not seen
// before asks, within the per-configuration budget.
func (s *Service) noticeNewGroup(ctx context.Context, tenantID shared.ID, cfg *cirun.TrustConfig, group, project string) {
	send, held := s.groupNotices.take(cfg.ID.String(), s.now())
	if !send {
		return
	}
	body := fmt.Sprintf("Project %s of group %s ran a CI job under the trust configuration %q, which admits every project "+
		"on its GitLab. Approve the project or its whole group, or block it, under CI/CD > Trusted pipelines > New repositories.",
		project, group, cfg.Name)
	if held > 0 {
		body += fmt.Sprintf(" %d more new groups asked since the last notice; they are in the same list.", held)
	}
	s.alertAdmins(ctx, tenantID, newGroupAlert(AdminAlert{
		Title: fmt.Sprintf("A new GitLab group asks to send CI results: %s", group),
		Body:  body,
		URL:   "/ci-cd?tab=setup&section=new-repositories", Metadata: map[string]any{"trust_config_id": cfg.ID.String(),
			"group": group, "project": project, "held_back": held},
	}))
}

// NewRepositoryList is the configuration's new repositories.
type NewRepositoryList struct {
	Config *cirun.TrustConfig
	Rows   []cirun.NewRepository
	// ListFull: the configuration holds cirun.MaxPendingRepositories pending
	// projects; a new project is refused without being listed.
	ListFull bool
	// FullGroups hold cirun.MaxPendingPerGroup pending projects each; a new
	// project of such a group is refused without being listed.
	FullGroups []string
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
	perGroup, total := map[string]int{}, 0
	for _, r := range out.Rows {
		if r.State == cirun.NewRepoPending && r.Kind == cirun.NewRepoProject {
			perGroup[r.Group]++
			total++
		}
	}
	out.ListFull = total >= cirun.MaxPendingRepositories
	out.FullGroups = []string{}
	for g, n := range perGroup {
		if n >= cirun.MaxPendingPerGroup {
			out.FullGroups = append(out.FullGroups, g)
		}
	}
	slices.Sort(out.FullGroups)
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

// ErrApprovalIDConflict refuses an approval whose sightings disagree with
// each other, or with a pin, on a namespace id: the name changed hands.
var ErrApprovalIDConflict = fmt.Errorf("%w: the namespace was seen with another id", shared.ErrValidation)

// pinApprovedNamespaces pins each namespace an approval covers to the id its
// pending projects were seen with, so the first admitted run of the approved
// project or group must come from that namespace. Sightings that disagree on
// an id, or an existing pin to another id, refuse the approval: an
// administrator blocks the item and looks at the instance first.
func (s *Service) pinApprovedNamespaces(ctx context.Context, tenantID, configID shared.ID, d cirun.NewRepositoryDecision) error {
	rows, err := s.newRepos.ListNewRepositories(ctx, tenantID, configID)
	if err != nil {
		return err
	}
	want := map[string]string{}
	for _, r := range rows {
		if r.State != cirun.NewRepoPending || r.Kind != cirun.NewRepoProject || r.NamespacePath == "" || r.NamespaceID == "" {
			continue
		}
		covered := slices.ContainsFunc(d.Items, func(it cirun.NewRepositoryItem) bool {
			return (it.Kind == cirun.NewRepoProject && it.Name == r.Name) || (it.Kind == cirun.NewRepoGroup && it.Name == r.Group)
		})
		if !covered {
			continue
		}
		if prev, ok := want[r.NamespacePath]; ok && prev != r.NamespaceID {
			return fmt.Errorf("%w: %s", ErrApprovalIDConflict, r.NamespacePath)
		}
		want[r.NamespacePath] = r.NamespaceID
	}
	if len(want) == 0 {
		return nil
	}
	pins, err := s.repo.OwnerPins(ctx, tenantID, configID)
	if err != nil {
		return err
	}
	for _, p := range pins {
		if id, ok := want[p.OwnerName]; ok && id != p.OwnerID {
			return fmt.Errorf("%w: %s", ErrApprovalIDConflict, p.OwnerName)
		}
	}
	for name, id := range want {
		if _, _, err := s.repo.PinOwner(ctx, tenantID, configID, name, id); err != nil {
			return fmt.Errorf("pin approved namespace: %w", err)
		}
	}
	return nil
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
	if d.Action == cirun.DecisionApprove {
		if err := s.pinApprovedNamespaces(ctx, tenantID, configID, d); err != nil {
			return nil, err
		}
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
