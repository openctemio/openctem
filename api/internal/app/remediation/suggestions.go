package remediation

// Remediation suggestions: docs/rfcs/RFC-098-remediation-tasks.md §5.
//
// The generator reads the deterministic remediation keys (the candidate
// index), partitions each key's findings by the asset's primary owner, ranks
// by risk reduced and stores proposals. It never creates an action, a task
// or a membership: a person accepts. A dismissal is remembered until the
// suggestion changes materially; at most a daily number of new suggestions
// is shown per tenant; reviewers get one daily digest, never one message per
// suggestion.
//
// Authorization: the route gates decide who may read (findings:remediation:
// read) and decide (findings:remediation:write). A restricted member sees a
// suggestion only through its findings in their scope, never the ids of the
// others, and may not decide on one with findings outside their scope.

import (
	"context"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// SuggestionNotifier enqueues a notification (*outbox.Service).
type SuggestionNotifier interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

// ModuleGuard reports the modules a tenant has off (*module.ModuleService).
type ModuleGuard interface {
	TenantDisabledModules(ctx context.Context, tenantID string) map[string]bool
}

// SuggestionService generates and serves remediation suggestions.
type SuggestionService struct {
	repo      remediationdom.SuggestionRepository
	dataScope *datascope.Enforcer
	audit     TaskAuditLogger
	notifier  SuggestionNotifier
	modules   ModuleGuard
	tasks     *TaskService
	logger    *logger.Logger
	now       func() time.Time
}

// NewSuggestionService creates the service.
func NewSuggestionService(repo remediationdom.SuggestionRepository, log *logger.Logger) *SuggestionService {
	return &SuggestionService{repo: repo, logger: log, now: func() time.Time { return time.Now().UTC() }}
}

// SetDataScope wires the data-scope enforcer.
func (s *SuggestionService) SetDataScope(e *datascope.Enforcer) { s.dataScope = e }

// SetAuditLogger wires the audit log.
func (s *SuggestionService) SetAuditLogger(a TaskAuditLogger) { s.audit = a }

// SetNotifier wires the digest notification.
func (s *SuggestionService) SetNotifier(n SuggestionNotifier) { s.notifier = n }

// SetModuleGuard skips tenants with the remediation module off.
func (s *SuggestionService) SetModuleGuard(g ModuleGuard) { s.modules = g }

// refreshInterval throttles a person's "refresh now".
const refreshInterval = time.Minute

// digestInterval is how often a tenant gets the suggestions digest.
const digestInterval = 24 * time.Hour

// RunTenant runs the generator for one tenant.
func (s *SuggestionService) RunTenant(ctx context.Context, tenantID shared.ID) (remediationdom.RunStats, error) {
	cands, err := s.repo.Candidates(ctx, tenantID)
	if err != nil {
		return remediationdom.RunStats{}, err
	}
	keys := make([]string, 0, len(cands))
	seen := map[string]bool{}
	for _, c := range cands {
		if !seen[c.Key] {
			seen[c.Key] = true
			keys = append(keys, c.Key)
		}
	}
	accepted, err := s.repo.AcceptedActions(ctx, tenantID, keys)
	if err != nil {
		return remediationdom.RunStats{}, err
	}
	excluded, err := s.repo.Exclusions(ctx, tenantID)
	if err != nil {
		return remediationdom.RunStats{}, err
	}
	ss := remediationdom.BuildSuggestions(tenantID, cands, accepted, excluded)
	// The auto-join rule a person turned on applies before anything is
	// proposed; what it could not take (cap, task state) stays a suggestion.
	autoJoined := s.applyAutoJoin(ctx, tenantID, ss, accepted)
	if autoJoined > 0 {
		if cands, err = s.repo.Candidates(ctx, tenantID); err != nil {
			return remediationdom.RunStats{}, err
		}
		ss = remediationdom.BuildSuggestions(tenantID, cands, accepted, excluded)
	}
	st, err := s.repo.ApplyRun(ctx, tenantID, ss, s.now())
	if err != nil {
		return st, err
	}
	st.Candidates, st.AutoJoined = len(cands), autoJoined
	return st, nil
}

// Refresh runs the generator for the caller's tenant now, at most once a
// minute.
func (s *SuggestionService) Refresh(ctx context.Context, tenantID shared.ID, actx auditapp.AuditContext) (remediationdom.RunStats, error) {
	last, _, err := s.repo.RunInfo(ctx, tenantID)
	if err != nil {
		return remediationdom.RunStats{}, err
	}
	if last != nil && s.now().Sub(*last) < refreshInterval {
		return remediationdom.RunStats{}, remediationdom.ErrRunTooSoon
	}
	st, err := s.RunTenant(ctx, tenantID)
	if err != nil {
		return st, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationSuggestionsRefreshed, auditdom.ResourceTypeRemediationSuggestion, tenantID.String()).
		WithMessage(fmt.Sprintf("Remediation suggestions refreshed: %d new, %d updated, %d expired", st.Created, st.Updated, st.Expired)).
		WithMetadata("created", st.Created).WithMetadata("updated", st.Updated).WithMetadata("expired", st.Expired))
	return st, nil
}

// RunAll runs the generator for every tenant with keyed findings (the
// background job) and sends the daily digests. One tenant's failure does not
// stop the others.
func (s *SuggestionService) RunAll(ctx context.Context) (int, error) {
	tenants, err := s.repo.TenantsWithKeysForPlatform(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, tid := range tenants {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		if s.modules != nil && s.modules.TenantDisabledModules(ctx, tid.String())[moduledom.ModuleRemediation] {
			continue
		}
		if _, err := s.RunTenant(ctx, tid); err != nil {
			s.logger.Warn("remediation suggestion run failed", "tenant", tid.String(), "error", logger.SanitizeError(err))
			continue
		}
		n++
		s.maybeDigest(ctx, tid)
	}
	return n, nil
}

// maybeDigest sends the tenant one digest a day when new suggestions were
// surfaced since the last one.
func (s *SuggestionService) maybeDigest(ctx context.Context, tenantID shared.ID) {
	if s.notifier == nil {
		return
	}
	now := s.now()
	_, lastDigest, err := s.repo.RunInfo(ctx, tenantID)
	if err != nil {
		s.logger.Warn("suggestion digest: read run", "tenant", tenantID.String(), "error", logger.SanitizeError(err))
		return
	}
	since := now.Add(-digestInterval)
	if lastDigest != nil {
		if now.Sub(*lastDigest) < digestInterval {
			return
		}
		since = *lastDigest
	}
	fresh, err := s.repo.SurfacedSince(ctx, tenantID, since)
	if err != nil || fresh == 0 {
		return
	}
	counts, err := s.repo.CountSuggestions(ctx, tenantID, nil)
	if err != nil {
		return
	}
	err = s.notifier.Enqueue(ctx, outbox.EnqueueParams{
		TenantID:      tenantID,
		EventType:     string(integration.EventTypeRemediationSuggestionsDigest),
		AggregateType: "remediation_suggestions",
		Title:         fmt.Sprintf("%d new remediation suggestions to review", fresh),
		Body: fmt.Sprintf("%d new suggestions since the last digest; %d open in total. Suggestions group findings that one fix closes; nothing changes until someone accepts one.",
			fresh, counts.Proposed),
		Severity: "info",
		URL:      "/remediation/suggestions",
		Metadata: map[string]any{"new": fresh, "open": counts.Proposed, "by_kind": counts.ByKind},
	})
	if err != nil {
		s.logger.Warn("suggestion digest: enqueue", "tenant", tenantID.String(), "error", logger.SanitizeError(err))
		return
	}
	if err := s.repo.MarkDigest(ctx, tenantID, now); err != nil {
		s.logger.Warn("suggestion digest: record", "tenant", tenantID.String(), "error", logger.SanitizeError(err))
	}
}

func (s *SuggestionService) scope(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error) {
	if s.dataScope == nil {
		return nil, nil
	}
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	return scope, nil
}

// List lists the suggestions the caller may see, best first.
func (s *SuggestionService) List(ctx context.Context, tenantID shared.ID, f remediationdom.SuggestionFilter, page pagination.Pagination) (pagination.Result[*remediationdom.Suggestion], error) {
	scope, err := s.scope(ctx, tenantID)
	if err != nil {
		return pagination.Result[*remediationdom.Suggestion]{}, err
	}
	f.Scope = scope
	return s.repo.ListSuggestions(ctx, tenantID, f, page)
}

// Get returns a suggestion the caller may see.
func (s *SuggestionService) Get(ctx context.Context, tenantID, id shared.ID) (*remediationdom.Suggestion, error) {
	scope, err := s.scope(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.repo.GetSuggestion(ctx, tenantID, id, scope)
}

// Members lists a suggestion's findings the caller may see.
func (s *SuggestionService) Members(ctx context.Context, tenantID, id shared.ID, page pagination.Pagination) (pagination.Result[remediationdom.TaskMember], error) {
	scope, err := s.scope(ctx, tenantID)
	if err != nil {
		return pagination.Result[remediationdom.TaskMember]{}, err
	}
	if _, err := s.repo.GetSuggestion(ctx, tenantID, id, scope); err != nil {
		return pagination.Result[remediationdom.TaskMember]{}, err
	}
	return s.repo.SuggestionMembers(ctx, tenantID, id, scope, page)
}

// Counts summarizes the open suggestions the caller may see.
func (s *SuggestionService) Counts(ctx context.Context, tenantID shared.ID) (remediationdom.SuggestionCounts, error) {
	scope, err := s.scope(ctx, tenantID)
	if err != nil {
		return remediationdom.SuggestionCounts{}, err
	}
	return s.repo.CountSuggestions(ctx, tenantID, scope)
}

// decidable loads a suggestion for a decision: visible, with no finding
// outside the caller's scope.
func (s *SuggestionService) decidable(ctx context.Context, tenantID, id shared.ID) (*remediationdom.Suggestion, error) {
	sg, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if sg.HiddenMembers > 0 {
		return nil, remediationdom.ErrSuggestionHiddenMembers
	}
	return sg, nil
}

// DismissInput dismisses a suggestion.
type DismissInput struct {
	TenantID shared.ID
	ID       shared.ID
	Version  int
	Reason   remediationdom.DismissReason
	Note     string
	ActorID  *shared.ID
}

// Dismiss dismisses a suggestion with a reason. It is not proposed again
// unless it changes materially.
func (s *SuggestionService) Dismiss(ctx context.Context, in DismissInput, actx auditapp.AuditContext) (*remediationdom.Suggestion, error) {
	if !in.Reason.IsValid() {
		return nil, fmt.Errorf("%w: a dismiss reason is required", shared.ErrValidation)
	}
	note, err := suggestionNote(in.Note)
	if err != nil {
		return nil, err
	}
	if in.Reason == remediationdom.DismissOther && note == "" {
		return nil, fmt.Errorf("%w: say why when the reason is other", shared.ErrValidation)
	}
	if _, err := s.decidable(ctx, in.TenantID, in.ID); err != nil {
		return nil, err
	}
	sg, err := s.repo.DecideSuggestion(ctx, in.TenantID, in.ID, in.Version, remediationdom.SuggestionDecision{
		State: remediationdom.SuggestionDismissed, Reason: in.Reason, Note: note, ActorID: in.ActorID,
	})
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationSuggestionDismissed, auditdom.ResourceTypeRemediationSuggestion, sg.ID.String()).
		WithResourceName(sg.Title).WithMessage(fmt.Sprintf("Remediation suggestion %q dismissed: %s", sg.Title, in.Reason)).
		WithMetadata("reason", string(in.Reason)).WithMetadata("kind", string(sg.Kind)).
		WithMetadata("key_kind", sg.KeyKind).WithMetadata("members", sg.MemberCount))
	return sg, nil
}

// SnoozeInput snoozes a suggestion until a time.
type SnoozeInput struct {
	TenantID shared.ID
	ID       shared.ID
	Version  int
	Until    time.Time
	ActorID  *shared.ID
}

// Snooze hides a suggestion until a time; the next run after it proposes it
// again.
func (s *SuggestionService) Snooze(ctx context.Context, in SnoozeInput, actx auditapp.AuditContext) (*remediationdom.Suggestion, error) {
	now := s.now()
	if !in.Until.After(now) || in.Until.Sub(now) > remediationdom.MaxSnooze {
		return nil, fmt.Errorf("%w: snooze until a time in the next 180 days", shared.ErrValidation)
	}
	if _, err := s.decidable(ctx, in.TenantID, in.ID); err != nil {
		return nil, err
	}
	until := in.Until.UTC()
	sg, err := s.repo.DecideSuggestion(ctx, in.TenantID, in.ID, in.Version, remediationdom.SuggestionDecision{
		State: remediationdom.SuggestionSnoozed, SnoozedUntil: &until, ActorID: in.ActorID,
	})
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationSuggestionSnoozed, auditdom.ResourceTypeRemediationSuggestion, sg.ID.String()).
		WithResourceName(sg.Title).WithMessage(fmt.Sprintf("Remediation suggestion %q snoozed until %s", sg.Title, until.Format(time.RFC3339))))
	return sg, nil
}

// Reopen undoes a dismissal or a snooze.
func (s *SuggestionService) Reopen(ctx context.Context, tenantID, id shared.ID, version int, actor *shared.ID, actx auditapp.AuditContext) (*remediationdom.Suggestion, error) {
	if _, err := s.decidable(ctx, tenantID, id); err != nil {
		return nil, err
	}
	sg, err := s.repo.DecideSuggestion(ctx, tenantID, id, version, remediationdom.SuggestionDecision{
		State: remediationdom.SuggestionProposed, ActorID: actor,
	})
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationSuggestionReopened, auditdom.ResourceTypeRemediationSuggestion, sg.ID.String()).
		WithResourceName(sg.Title).WithMessage(fmt.Sprintf("Remediation suggestion %q reopened", sg.Title)))
	return sg, nil
}

func suggestionNote(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > remediationdom.MaxStateNote {
		return "", fmt.Errorf("%w: the note is longer than %d characters", shared.ErrValidation, remediationdom.MaxStateNote)
	}
	return s, nil
}

func (s *SuggestionService) logAudit(ctx context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Warn("remediation suggestion audit failed", "error", logger.SanitizeError(err))
	}
}
