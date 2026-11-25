package cirun

// Re-judging a stored CI run after a final decision in the platform, so the
// merge request the gate blocked opens without a new push
// (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md, "Verdict
// revisions"; docs/architecture/ci-gate-rejudge.md).
//
// Threat model: a re-judge can open a merge request, so it must never be a
// way around the gate.
//   - Only final decisions count: the gate reads the finding's status and
//     the approved, unexpired suppression rules (cirun.Decision); a pending
//     request changes neither.
//   - Everything but the decisions is the first verdict's (JudgeSnapshot):
//     the policy as applied, the baseline comparison and the run's own
//     failures (scan failure, upload not applied, missing or failed
//     capability, too many findings), which a re-judge therefore never
//     clears. A run without a usable snapshot is never re-judged.
//   - A new push never inherits a pass: only the latest run of a pull
//     request and pipeline is a candidate, and a revision is appended only
//     while the code host says the pull request's head is still the judged
//     commit. Forks, unverified commits and runs judged more than 14 days ago
//     are never candidates.
//   - Tenant isolation: the tenant is the durable job's, which the decision
//     wrote from its own authenticated tenant; every query is scoped by it.
//   - Abuse of a stolen account: each person's reopens are limited per hour
//     (circuit breaker, owners told), a reopen that unblocks a secret, a
//     known-exploited or a critical finding is announced to the owners and
//     administrators, every revision is audited, and the organization can
//     turn re-judging off.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/durablejob"
	"github.com/openctemio/openctem/server/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/suppression"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// HeadChecker tells whether a pull or merge request run judged the request
// as it stands now on the code host (DecorationJob.HeadIsCurrent).
type HeadChecker interface {
	HeadIsCurrent(ctx context.Context, run *cirun.Run) (bool, error)
}

// SuppressionRuleReader reads one of the tenant's suppression rules.
type SuppressionRuleReader interface {
	FindByID(ctx context.Context, tenantID, id shared.ID) (*suppression.Rule, error)
}

// SetHeadChecker enables re-judging: without a code-host check nothing is
// re-judged (a new push could otherwise inherit a pass).
func (s *Service) SetHeadChecker(h HeadChecker) { s.heads = h }

// SetSuppressionRuleReader lets an approved suppression rule re-judge runs.
func (s *Service) SetSuppressionRuleReader(r SuppressionRuleReader) { s.ruleReader = r }

// metaRepository names the repository in an alert's metadata.
const metaRepository = "repository"

// Re-judge causes (the payload of a ci_rejudge durable job).
const (
	RejudgeCauseFinding         = "finding"
	RejudgeCauseSuppressionRule = "suppression_rule"
)

// RejudgeRequest is one decision to re-judge runs for.
type RejudgeRequest struct {
	TenantID shared.ID
	Cause    string
	// SubjectID is the decided finding or the approved suppression rule.
	SubjectID shared.ID
	// ActorID is the person whose decision it is (nil: none known, the
	// circuit breaker does not apply but the switch and audit do).
	ActorID *shared.ID
}

// RejudgeResult counts what happened to the candidate runs.
type RejudgeResult struct {
	Candidates int
	Reopened   int
	Unchanged  int
	Stale      int
	Paused     int
	Skipped    int
}

// Outcomes of one run.
const (
	rejudgeReopened  = "reopened"
	rejudgeUnchanged = "unchanged"
	rejudgeStale     = "stale"
	rejudgePaused    = "paused"
	rejudgeSkipped   = "skipped"
)

// Rejudge re-judges the runs one decision may reopen. An error means a
// retry may help (the job is retried); outcomes that will not change are
// counted, not returned.
func (s *Service) Rejudge(ctx context.Context, req RejudgeRequest) (RejudgeResult, error) {
	var res RejudgeResult
	if req.TenantID.IsZero() || req.SubjectID.IsZero() {
		return res, nil
	}
	on, err := s.repo.ReopenOnDecision(ctx, req.TenantID)
	if err != nil {
		return res, fmt.Errorf("read the re-judge switch: %w", err)
	}
	if !on || s.heads == nil {
		return res, nil
	}
	f := cirun.RejudgeFilter{Since: s.now().UTC().Add(-cirun.RejudgeWindow), Limit: cirun.MaxRejudgeRuns}
	switch req.Cause {
	case RejudgeCauseFinding:
		id := req.SubjectID
		f.FindingID = &id
	case RejudgeCauseSuppressionRule:
		if s.ruleReader == nil {
			return res, nil
		}
		rule, err := s.ruleReader.FindByID(ctx, req.TenantID, req.SubjectID)
		if errors.Is(err, shared.ErrNotFound) || errors.Is(err, suppression.ErrRuleNotFound) || (err == nil && rule == nil) {
			return res, nil
		}
		if err != nil {
			return res, fmt.Errorf("read suppression rule: %w", err)
		}
		// Only a rule that applies now: approved and unexpired.
		if rule.TenantID() != req.TenantID || !rule.IsActive() {
			return res, nil
		}
		f.AssetID = rule.AssetID()
		f.AnyRepository = f.AssetID == nil
	default:
		return res, nil
	}
	runs, err := s.repo.RejudgeCandidates(ctx, req.TenantID, f)
	if err != nil {
		return res, fmt.Errorf("find runs to re-judge: %w", err)
	}
	res.Candidates = len(runs)
	var firstErr error
	for i := range runs {
		run := &runs[i]
		if run.TenantID != req.TenantID {
			continue // never another tenant's run
		}
		out, err := s.rejudgeRun(ctx, run, req)
		if err != nil {
			s.log.Warn("ci re-judge failed", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		switch out {
		case rejudgeReopened:
			res.Reopened++
		case rejudgeStale:
			res.Stale++
		case rejudgePaused:
			res.Paused++
		case rejudgeSkipped:
			res.Skipped++
		default:
			res.Unchanged++
		}
		if out == rejudgePaused {
			break // the person is paused: the other runs wait for an owner
		}
	}
	return res, firstErr
}

// rejudgeRun re-judges one candidate run.
func (s *Service) rejudgeRun(ctx context.Context, run *cirun.Run, req RejudgeRequest) (string, error) {
	snap, err := s.runSnapshot(ctx, run)
	if errors.Is(err, cirun.ErrNotRejudgeable) {
		return rejudgeSkipped, nil
	}
	if err != nil {
		return "", err
	}
	// A cheap look first: no code-host call and no lock when the decisions
	// do not open the run.
	gv, _, err := s.rejudgeVerdict(ctx, run, snap)
	if err != nil {
		return "", err
	}
	if gv.Verdict != cirun.VerdictPass {
		return rejudgeUnchanged, nil
	}
	current, err := s.heads.HeadIsCurrent(ctx, run)
	if err != nil {
		return "", fmt.Errorf("check the pull request head: %w", err)
	}
	if !current {
		return rejudgeStale, nil
	}
	var (
		prev     cirun.GateVerdict
		decided  []shared.ID
		verdict  *Verdict
		previous string
	)
	rev, err := s.repo.AppendVerdictRevision(ctx, run.TenantID, run.ID, cirun.RevisionAppend{
		ActorID: req.ActorID, ReopenLimit: cirun.DefaultReopenLimit,
		Build: func(locked *cirun.Run) (*cirun.VerdictRevision, error) {
			// The run moved on while we looked (a new attempt re-opened it,
			// or another decision reopened it first): nothing to append.
			if locked.Status != cirun.StatusEvaluated || locked.Verdict != cirun.VerdictFail || locked.Fork ||
				locked.TenantID != run.TenantID {
				return nil, nil //nolint:nilnil // nothing to append
			}
			lsnap, err := s.runSnapshot(ctx, locked)
			if errors.Is(err, cirun.ErrNotRejudgeable) {
				return nil, nil //nolint:nilnil // nothing to append
			}
			if err != nil {
				return nil, err
			}
			gv, findings, err := s.rejudgeVerdict(ctx, locked, lsnap)
			if err != nil {
				return nil, err
			}
			if gv.Verdict != cirun.VerdictPass {
				return nil, nil //nolint:nilnil // still failing
			}
			var pv Verdict
			if len(locked.VerdictDetail) > 0 {
				_ = json.Unmarshal(locked.VerdictDetail, &pv)
			}
			prev, previous = pv.GateVerdict, locked.Verdict
			now := s.now().UTC()
			counts, ids := cirun.DecidedByDecision(prev, findings, now)
			decided = ids
			verdict = &Verdict{RunID: locked.ID.String(), GateVerdict: gv, RepoFile: lsnap.RepoFile, Links: VerdictLinks{
				Run:      s.webURL(locked.TenantID, RunPath(locked.ID)),
				Findings: s.webURL(locked.TenantID, gateFindingsPath(locked)),
			}, Revision: &cirun.RevisionView{Number: locked.CurrentRevision() + 1, Cause: cirun.RevisionCauseDecision,
				Previous: locked.Verdict, At: now, Decided: counts}}
			detail, err := json.Marshal(verdict)
			if err != nil {
				return nil, err
			}
			decisionIDs := append([]shared.ID{}, ids...)
			if req.Cause == RejudgeCauseSuppressionRule {
				decisionIDs = append(decisionIDs, req.SubjectID)
			}
			var actors []shared.ID
			if req.ActorID != nil {
				actors = []shared.ID{*req.ActorID}
			}
			return &cirun.VerdictRevision{Verdict: gv.Verdict, Detail: detail, Cause: cirun.RevisionCauseDecision,
				DecisionIDs: decisionIDs, ActorIDs: actors, Reopened: true, CreatedAt: now}, nil
		},
	})
	var paused *cirun.ErrReopenPaused
	if errors.As(err, &paused) {
		if paused.PausedNow {
			s.reopenPaused(ctx, run, req)
		}
		return rejudgePaused, nil
	}
	if err != nil {
		return "", err
	}
	if rev == nil {
		return rejudgeUnchanged, nil
	}
	s.refreshPipeline(ctx, run.TenantID, run.PipelineID)
	s.auditRejudge(ctx, run, req, rev, previous, decided)
	if cirun.SeriousReopen(prev, decided) {
		s.alertSeriousReopen(ctx, run, rev, len(decided))
	}
	return rejudgeReopened, nil
}

func (s *Service) runSnapshot(ctx context.Context, run *cirun.Run) (cirun.JudgeSnapshot, error) {
	raw, err := s.repo.RunSnapshot(ctx, run.TenantID, run.ID)
	if err != nil {
		return cirun.JudgeSnapshot{}, err
	}
	return cirun.ParseJudgeSnapshot(raw)
}

// rejudgeVerdict judges the stored run with the snapshot and the decisions
// as they are now (the same finding, rule and break-glass reads as a CI
// job's evaluation).
func (s *Service) rejudgeVerdict(ctx context.Context, run *cirun.Run, snap cirun.JudgeSnapshot) (cirun.GateVerdict, []cirun.RunFinding, error) {
	findings, err := s.repo.RunFindings(ctx, run.TenantID, run.ID, run.RepositoryAssetID)
	if err != nil {
		return cirun.GateVerdict{}, nil, fmt.Errorf("load run findings: %w", err)
	}
	s.applyActiveRules(ctx, run.TenantID, findings, run.RepositoryAssetID)
	now := s.now().UTC()
	var override *cirun.GateOverride
	if run.CommitVerified {
		if override, err = s.repo.ActiveOverride(ctx, run.TenantID, run.RepositoryAssetID, run.CommitSHA, now); err != nil {
			return cirun.GateVerdict{}, nil, fmt.Errorf("load gate override: %w", err)
		}
	}
	gv := cirun.Rejudge(snap, findings, override, now, func(id shared.ID) string { return s.findingURL(run.TenantID, id) })
	return gv, findings, nil
}

func actorOf(req RejudgeRequest) Actor {
	if req.ActorID == nil {
		return Actor{Email: "system"}
	}
	return Actor{UserID: req.ActorID.String()}
}

func (s *Service) auditRejudge(ctx context.Context, run *cirun.Run, req RejudgeRequest, rev *cirun.VerdictRevision, previous string, decided []shared.ID) {
	ids := make([]string, 0, len(decided))
	for _, id := range decided {
		ids = append(ids, id.String())
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionCIRunRejudged, auditdom.ResourceTypeCIRun, run.ID.String()).
		WithResourceName(run.Repository).
		WithMessage(fmt.Sprintf("CI gate re-judged after a decision: %s at %s went from %s to %s (revision %d, %d finding(s) decided)",
			run.Repository, shortSHA(run.CommitSHA), previous, rev.Verdict, rev.Revision, len(decided))).
		WithSeverity(auditdom.SeverityHigh).
		WithMetadata("revision", rev.Revision).
		WithMetadata("previous_verdict", previous).
		WithMetadata("verdict", rev.Verdict).
		WithMetadata("cause", req.Cause).
		WithMetadata("decision_subject", req.SubjectID.String()).
		WithMetadata("finding_ids", ids).
		WithMetadata("commit_sha", run.CommitSHA).
		WithMetadata("pull_request", run.PullRequest)
	s.logAudit(ctx, run.TenantID, actorOf(req), ev)
}

// alertSeriousReopen tells the owners and administrators that a decision
// opened a merge request a serious finding blocked.
func (s *Service) alertSeriousReopen(ctx context.Context, run *cirun.Run, rev *cirun.VerdictRevision, decided int) {
	rid := run.ID
	s.alertAdmins(ctx, run.TenantID, AdminAlert{
		EventType: string(integration.EventTypeCIGateReopened), Severity: notificationdom.SeverityHigh,
		Title: "Merge request reopened by a decision: " + run.Repository,
		Body: fmt.Sprintf("A decision in %s opened pull request %s of %s at %s: %d finding(s) that blocked it, among them a secret, a known-exploited or a critical finding, no longer count.",
			"the platform", plain(run.PullRequest, 32), run.Repository, shortSHA(run.CommitSHA), decided),
		URL: RunPath(run.ID), Aggregate: "ci_run", AggregateID: &rid,
		Metadata: map[string]any{alertActionKey: "reopened", metaRepository: run.Repository, "pull_request": run.PullRequest,
			"revision": rev.Revision, "decided": decided},
	})
}

// reopenPaused records and announces that a person's decisions stopped
// reopening merge requests (circuit breaker).
func (s *Service) reopenPaused(ctx context.Context, run *cirun.Run, req RejudgeRequest) {
	who := ""
	if req.ActorID != nil {
		who = req.ActorID.String()
	}
	s.logAudit(ctx, run.TenantID, actorOf(req),
		auditapp.NewSuccessEvent(auditdom.ActionCIReopenPaused, auditdom.ResourceTypeCISettings, who).
			WithSeverity(auditdom.SeverityHigh).
			WithMessage(fmt.Sprintf("Decisions of one person reopened %d merge requests within an hour: their decisions no longer reopen merge requests until an owner resumes them",
				cirun.DefaultReopenLimit)).
			WithMetadata("user_id", who).
			WithMetadata("limit", cirun.DefaultReopenLimit))
	tid := run.TenantID
	s.alertAdmins(ctx, run.TenantID, AdminAlert{
		EventType: string(integration.EventTypeCIGateReopened), Severity: notificationdom.SeverityHigh,
		Title: "Reopening merge requests paused for one person",
		Body: fmt.Sprintf("One person's decisions reopened %d blocked merge requests within an hour. Their decisions still apply to findings but no longer reopen merge requests; an owner resumes them in the CI settings.",
			cirun.DefaultReopenLimit),
		URL: "/ci-cd?view=settings", Aggregate: "ci_settings", AggregateID: &tid,
		Metadata: map[string]any{alertActionKey: "reopen_paused", "user_id": who},
	})
}

// -------------------------------------------------------------- queueing --

// DurableEnqueuer queues durable jobs outside a transaction (the decision
// committed just before), due after delay.
type DurableEnqueuer interface {
	Enqueue(ctx context.Context, delay time.Duration, jobs ...durablejob.Job) error
}

// rejudgeCoalesce delays a re-judge so a burst of decisions (a bulk dismiss,
// a second approver right after the first) is judged once per finding.
const rejudgeCoalesce = 20 * time.Second

// RejudgePayload is the payload of a ci_rejudge job.
type RejudgePayload struct {
	Cause   string `json:"cause"`
	ActorID string `json:"actor_id,omitempty"`
}

// RejudgeQueue queues a re-judge after each final decision. Best effort: the
// decision is committed; a job that could not be queued leaves the merge
// request blocked until its next pipeline run (fail closed), and is logged.
type RejudgeQueue struct {
	store DurableEnqueuer
	log   *logger.Logger
}

// NewRejudgeQueue creates the queue.
func NewRejudgeQueue(store DurableEnqueuer, log *logger.Logger) *RejudgeQueue {
	if log == nil {
		log = logger.NewNop()
	}
	return &RejudgeQueue{store: store, log: log.With("component", "ci-rejudge-queue")}
}

// FindingsDecided queues a re-judge for each finding whose status became a
// decision the gate honors (false positive, duplicate, accepted). Only
// statuses are passed here, so only applied (final) decisions queue one.
func (q *RejudgeQueue) FindingsDecided(ctx context.Context, tenantID shared.ID, actorID string, findingIDs []shared.ID) {
	if q == nil || q.store == nil || len(findingIDs) == 0 {
		return
	}
	payload := rejudgePayload(RejudgeCauseFinding, actorID)
	jobs := make([]durablejob.Job, 0, len(findingIDs))
	for _, id := range findingIDs {
		jobs = append(jobs, durablejob.Job{Kind: durablejob.KindCIRejudge, TenantID: tenantID, SubjectID: id, Payload: payload})
	}
	if err := q.store.Enqueue(ctx, rejudgeCoalesce, jobs...); err != nil {
		q.log.Warn("ci re-judge not queued", "count", len(jobs), "error", logger.SanitizeError(err))
	}
}

// RuleApproved queues a re-judge for a suppression rule that became
// approved (every required approval given).
func (q *RejudgeQueue) RuleApproved(ctx context.Context, tenantID, ruleID, approvedBy shared.ID) {
	if q == nil || q.store == nil {
		return
	}
	job := durablejob.Job{Kind: durablejob.KindCIRejudge, TenantID: tenantID, SubjectID: ruleID,
		Payload: rejudgePayload(RejudgeCauseSuppressionRule, approvedBy.String())}
	if err := q.store.Enqueue(ctx, rejudgeCoalesce, job); err != nil {
		q.log.Warn("ci re-judge not queued", "rule_id", ruleID.String(), "error", logger.SanitizeError(err))
	}
}

func rejudgePayload(cause, actorID string) string {
	p := RejudgePayload{Cause: cause}
	if _, err := uuid.Parse(actorID); err == nil {
		p.ActorID = actorID
	}
	b, _ := json.Marshal(p)
	return string(b)
}

// ParseRejudgeJob turns a claimed ci_rejudge job into a request; the tenant
// is the job row's, never the payload's.
func ParseRejudgeJob(j durablejob.Claimed) (RejudgeRequest, error) {
	var p RejudgePayload
	if err := json.Unmarshal([]byte(j.Payload), &p); err != nil {
		return RejudgeRequest{}, fmt.Errorf("%w: ci_rejudge payload", shared.ErrValidation)
	}
	req := RejudgeRequest{TenantID: j.TenantID, Cause: p.Cause, SubjectID: j.SubjectID}
	if p.ActorID != "" {
		id, err := shared.IDFromString(p.ActorID)
		if err != nil {
			return RejudgeRequest{}, fmt.Errorf("%w: ci_rejudge actor", shared.ErrValidation)
		}
		req.ActorID = &id
	}
	return req, nil
}
