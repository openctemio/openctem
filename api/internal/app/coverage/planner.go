package coverage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Planning bounds. A batch is one run of one capability; a tenant has at
// most one active run per capability (the next batch waits), and a daily
// budget of attempted pairs.
const (
	DefaultBatch       = 200
	DefaultDailyBudget = 5000
	// BlockedRecheck is when a pair the gate refused is tried again (scope
	// may have changed).
	BlockedRecheck = 6 * time.Hour
	// StallAfter fails a queued pair whose run never finished.
	StallAfter = 24 * time.Hour
	// RefusalRetry is when a capability the trigger refused as a whole (a
	// readiness refusal the readiness check did not see) is tried again.
	RefusalRetry = 30 * time.Minute
)

// RunStarter starts one capability on a batch of targets (scan.Service).
type RunStarter interface {
	StartCoverage(ctx context.Context, in scanapp.CoverageInput) (*scanapp.CoverageResult, error)
}

// TenantSwitch says whether automatic coverage runs for a tenant.
type TenantSwitch interface {
	CoverageEnabled(ctx context.Context, tenantID shared.ID) (bool, error)
}

// Config bounds the planner.
type Config struct {
	Batch       int
	DailyBudget int
	// FillBatches holds a due batch back until it fills one task of the
	// capability's tool or its oldest pair has waited covdom.BatchWait of
	// the cadence (the server sets it). Without it a batch starts as soon
	// as one pair is due.
	FillBatches bool
}

// EnablePlanning wires dispatch. Without it the service only reconciles.
func (s *Service) EnablePlanning(planner covdom.Planner, starter RunStarter, sw TenantSwitch, cfg Config) {
	if cfg.Batch <= 0 || cfg.Batch > 500 {
		cfg.Batch = DefaultBatch
	}
	if cfg.DailyBudget <= 0 {
		cfg.DailyBudget = DefaultDailyBudget
	}
	s.planner, s.starter, s.tenantSwitch, s.cfg = planner, starter, sw, cfg
}

// plannedCapabilities are the capabilities of the policy the planner
// starts: stages up to the active tier. Platform checks (dns.*) run on
// their own schedule and write the ledger themselves.
func plannedCapabilities(rules []covdom.Rule) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		st, ok := stage.Lookup(stage.Key(r.Capability))
		if !ok || st.Tier >= stage.TierIntrusive || seen[r.Capability] {
			continue
		}
		seen[r.Capability] = true
		out = append(out, r.Capability)
	}
	return out
}

// ruleOf returns the rule of a capability (the first: cadences of one
// capability are the same across types in the default policy; settlement
// uses it for the next due time and the output check).
func (s *Service) ruleOf(capability string) covdom.Rule {
	for _, r := range s.rules {
		if r.Capability == capability {
			return r
		}
	}
	return covdom.Rule{Capability: capability, Every: 24 * time.Hour}
}

// settle settles the queued pairs of every finished run of the tenant, per
// target: from what happened to each pair's own target across every task of
// the run (claim-time splits and follow-ups included), never from the run's
// overall status. A target no task carried fails as not dispatched, with the
// run's error; a run unfinished after a day fails its pairs as stalled.
// parked is how many names the pass found without an address (resolve.dns
// no answer).
func (s *Service) settle(ctx context.Context, tenantID shared.ID) (total, parked int, err error) {
	runs, err := s.planner.QueuedRuns(ctx, tenantID)
	if err != nil {
		return 0, 0, err
	}
	for _, rs := range runs {
		stalled := false
		switch rs.Status {
		case "completed", "partial", "failed", "canceled", "timeout", "blocked":
		default:
			if s.now().Sub(rs.QueuedAt) < StallAfter {
				continue // still running
			}
			stalled = true
		}
		n, p, err := s.settleRun(ctx, tenantID, rs, stalled)
		total += n
		parked += p
		if err != nil {
			return total, parked, err
		}
	}
	return total, parked, nil
}

func (s *Service) settleRun(ctx context.Context, tenantID shared.ID, rs covdom.RunState, stalled bool) (n, parked int, err error) {
	rule := s.ruleOf(rs.Capability)
	queued, err := s.planner.QueuedTargets(ctx, tenantID, rs.RunID, rs.Capability)
	if err != nil {
		return 0, 0, err
	}
	var verdicts map[string]covdom.Verdict
	if !stalled {
		tasks, err := s.planner.RunTasks(ctx, tenantID, rs.RunID)
		if err != nil {
			return 0, 0, err
		}
		verdicts = covdom.Verdicts(tasks, rs.Unfinished)
	}
	var covered, noAnswer []shared.ID
	var failed, targetSide, unresolved []covdom.FailedPair
	blocked := map[shared.ID]string{}
	for _, d := range queued {
		v, ok := verdicts[covdom.TargetKey(d.Target())]
		switch {
		case stalled:
			failed = append(failed, covdom.FailedPair{AssetID: d.AssetID, Outcome: covdom.OutcomeStalled,
				Error: "the run did not finish within a day"})
		case !ok:
			msg := rs.Error
			if msg == "" {
				msg = "no task of the run carried this target"
			}
			failed = append(failed, covdom.FailedPair{AssetID: d.AssetID, Outcome: covdom.OutcomeNotDispatched, Error: msg})
		case v.Kind == covdom.VerdictCovered:
			covered = append(covered, d.AssetID)
		case v.Kind == covdom.VerdictBlocked:
			blocked[d.AssetID] = v.Reason
		case v.Kind == covdom.VerdictUnresolved:
			// A name that does not resolve: for the DNS resolution that is
			// the answer (the name is parked); for any other capability the
			// pair waits for the name on the dead-name schedule. Never a
			// failure, so never a gap or a failure streak.
			if rs.Capability == covdom.CapabilityResolveDNS && v.Outcome == covdom.OutcomeNoAnswer {
				noAnswer = append(noAnswer, d.AssetID)
				continue
			}
			reason := covdom.ReasonUnresolvable
			if v.Outcome == covdom.ReasonResolverFailed {
				reason = covdom.ReasonResolverFailed
			}
			unresolved = append(unresolved, covdom.FailedPair{AssetID: d.AssetID, Outcome: reason, Error: v.Error})
		default:
			msg := v.Error
			if msg == "" {
				msg = rs.Error
			}
			fp := covdom.FailedPair{AssetID: d.AssetID, Outcome: v.Outcome, Error: msg, Observer: v.Observer}
			if covdom.IsTargetSide(v.Outcome) {
				// The target did not answer: an observation, rechecked on a
				// widening schedule, not a failure retried every few hours.
				targetSide = append(targetSide, fp)
				continue
			}
			failed = append(failed, fp)
		}
	}
	n, err = s.planner.SettleCovered(ctx, tenantID, rs.RunID, rs.Capability, covered, rule.Every, rule.Expects == "http_service")
	if err != nil {
		return n, 0, err
	}
	k, err := s.planner.SettleFailed(ctx, tenantID, rs.RunID, rs.Capability, failed, rule.Every)
	n += k
	if err == nil {
		countPlatformFailures(rs.Capability, failed)
	}
	if err != nil {
		return n, 0, err
	}
	k, err = s.planner.SettleTargetSide(ctx, tenantID, rs.RunID, rs.Capability, targetSide)
	n += k
	if err != nil {
		return n, 0, err
	}
	parked, err = s.planner.SettleNoAnswer(ctx, tenantID, rs.RunID, rs.Capability, noAnswer)
	n += parked
	if err != nil {
		return n, parked, err
	}
	k, err = s.planner.SettleUnresolved(ctx, tenantID, rs.RunID, rs.Capability, unresolved)
	n += k
	if err != nil {
		return n, parked, err
	}
	if err := s.planner.MarkBlocked(ctx, tenantID, rs.Capability, blocked, BlockedRecheck); err != nil {
		return n, parked, err
	}
	if !stalled {
		if err := s.countRunClaim(ctx, tenantID, rs); err != nil {
			return n, parked, err
		}
	}
	return n + len(blocked), parked, nil
}

// countRunClaim counts a finished run on the capability's hold: a run no
// sensor took (NO_SENSOR) grows the streak, any other resets it. At
// covdom.NotClaimedStreak the capability is paused (not_claimed) until the
// fleet changes or the probe time; each further unclaimed run (a probe)
// doubles the wait. Pausing only narrows what is dispatched.
func (s *Service) countRunClaim(ctx context.Context, tenantID shared.ID, rs covdom.RunState) error {
	streak, err := s.planner.RecordRunClaim(ctx, tenantID, rs.Capability, rs.NoSensor)
	if err != nil {
		return err
	}
	if !rs.NoSensor || streak < covdom.NotClaimedStreak {
		return nil
	}
	return s.hold(ctx, tenantID, rs.Capability, streak)
}

// hold pauses the capability with not_claimed for covdom.NotClaimedRetry
// of streak, recording the fleet it was paused under. A fingerprint that
// cannot be read is recorded empty: the pause then holds until the probe.
func (s *Service) hold(ctx context.Context, tenantID shared.ID, capability string, streak int) error {
	fp, err := s.planner.FleetFingerprint(ctx, tenantID)
	if err != nil {
		s.logger.Warn("coverage hold: fleet fingerprint not read", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		fp = ""
	}
	retry := covdom.NotClaimedRetry(streak)
	n, err := s.planner.HoldCapability(ctx, tenantID, capability, fp, s.now().Add(retry))
	if err != nil {
		return err
	}
	s.logger.Info("coverage paused: no sensor took its runs", "tenant_id", tenantID.String(), "capability", capability,
		"unclaimed_runs", streak, "probe_in", retry.String(), "pairs", n)
	return nil
}

// heldResume decides, for a capability on hold with no live readiness
// reason, whether it runs this pass: the fleet changed since the pause, or
// the probe time has come. Either way the hold moves its probe time on, so
// the run that follows is the only one until it settles. When it does not
// run, pairs that came due join the pause.
func (s *Service) heldResume(ctx context.Context, tenantID shared.ID, h covdom.Hold) (bool, error) {
	fp, err := s.planner.FleetFingerprint(ctx, tenantID)
	if err != nil {
		s.logger.Warn("coverage hold: fleet fingerprint not read", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		fp = h.Fingerprint
	}
	why := ""
	switch {
	case h.Fingerprint != "" && fp != h.Fingerprint:
		why = "sensors changed"
	case h.ProbeAt == nil || !s.now().Before(*h.ProbeAt):
		why = "probe"
	}
	if why == "" {
		until := s.now().Add(covdom.NotClaimedProbe)
		if h.ProbeAt != nil {
			until = *h.ProbeAt
		}
		if h.Fingerprint == "" && fp != "" {
			// First fingerprint read after a failed one: record it.
			_, err := s.planner.HoldCapability(ctx, tenantID, h.Capability, fp, until)
			return false, err
		}
		_, err := s.planner.PauseForReadiness(ctx, tenantID, h.Capability, covdom.ReadyNotClaimed, until.Sub(s.now()))
		return false, err
	}
	if _, err := s.planner.HoldCapability(ctx, tenantID, h.Capability, fp, s.now().Add(covdom.NotClaimedRetry(h.Streak))); err != nil {
		return false, err
	}
	n, err := s.planner.ResumeNow(ctx, tenantID, h.Capability)
	if err != nil {
		return false, err
	}
	s.logger.Info("coverage resumed: "+why, "tenant_id", tenantID.String(), "capability", h.Capability, "pairs", n)
	return true, nil
}

// ReasonRepositoryCodeOnly blocks a pair of a repository and a capability
// that takes network kinds: a repository is scanned by code tools only, a
// network tool would probe the code host.
const ReasonRepositoryCodeOnly = "repository_code_only"

// blockRepositories takes out of a due batch every repository (by its
// stored type, or a name in the path form) when the capability's stage
// takes network kinds, and blocks those pairs with the reason. The policy
// gives repositories no network capability; this keeps a stray ledger row
// from ever sending one to a network tool.
func (s *Service) blockRepositories(ctx context.Context, tenantID shared.ID, capability string, due []covdom.DueTarget) ([]covdom.DueTarget, error) {
	st, ok := stage.Lookup(stage.Key(capability))
	if !ok || !st.TakesNetworkKinds() || len(due) == 0 {
		return due, nil
	}
	kept := make([]covdom.DueTarget, 0, len(due))
	blocked := map[shared.ID]string{}
	for _, d := range due {
		if stage.IsRepositoryType(asset.TypeRef{Type: d.Type, SubType: d.SubType}) || stage.ClassifyTarget(d.Target()) == stage.KindPath {
			blocked[d.AssetID] = ReasonRepositoryCodeOnly
			continue
		}
		kept = append(kept, d)
	}
	if len(blocked) == 0 {
		return due, nil
	}
	if err := s.planner.MarkBlocked(ctx, tenantID, capability, blocked, BlockedRecheck); err != nil {
		return nil, err
	}
	s.logger.Warn("SECURITY: repositories left out of a network coverage batch", "tenant_id", tenantID.String(),
		"capability", capability, "count", len(blocked))
	return kept, nil
}

// plan starts every planned capability on its due pairs, within the
// tenant's daily budget. A capability that cannot run for the tenant now
// (readiness) gets no run: its pairs are paused with the reason, and resume
// on the first pass where it is ready again.
func (s *Service) plan(ctx context.Context, tenantID shared.ID) (int, error) {
	used, err := s.planner.AttemptsSince(ctx, tenantID, s.now().Add(-24*time.Hour))
	if err != nil {
		return 0, err
	}
	left := s.cfg.DailyBudget - used
	capabilities := plannedCapabilities(s.rules)
	rd := s.newReadinessPass(tenantID, capabilities)
	holds, err := s.planner.Holds(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, capability := range capabilities {
		if left <= 0 {
			break
		}
		lookahead := covdom.Lookahead(s.ruleOf(capability).Every)
		due, err := s.dueBatch(ctx, tenantID, capability, min(s.cfg.Batch, left), lookahead)
		if err != nil {
			return total, err
		}
		paused, err := rd.paused(ctx, capability)
		if err != nil {
			return total, err
		}
		if len(due) == 0 && paused == "" {
			continue
		}
		reason, err := rd.reason(ctx, capability)
		if err != nil {
			return total, err
		}
		if reason != "" {
			if err := s.pauseCapability(ctx, tenantID, capability, reason, 0); err != nil {
				return total, err
			}
			continue
		}
		if h, ok := holds[capability]; ok && h.Active() {
			// No sensor took its last runs: wait for a fleet change or
			// the probe instead of starting runs that cannot succeed.
			run, err := s.heldResume(ctx, tenantID, h)
			if err != nil {
				return total, err
			}
			if !run {
				continue
			}
			if due, err = s.dueBatch(ctx, tenantID, capability, min(s.cfg.Batch, left), lookahead); err != nil {
				return total, err
			}
		} else if paused != "" {
			n, err := s.planner.ResumeFromReadiness(ctx, tenantID, capability)
			if err != nil {
				return total, err
			}
			if n > 0 {
				s.logger.Info("coverage resumed", "tenant_id", tenantID.String(), "capability", capability,
					"pairs", n, "was", paused)
				if due, err = s.dueBatch(ctx, tenantID, capability, min(s.cfg.Batch, left), lookahead); err != nil {
					return total, err
				}
			}
		}
		if len(due) == 0 || !s.batchReady(capability, due, min(s.cfg.Batch, left)) {
			continue
		}
		batch, depth := onboardingBatch(capability, due)
		n, err := s.startBatch(ctx, tenantID, capability, batch, depth)
		total += n
		left -= n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// batchReady applies the batch rule (covdom.BatchReady) when FillBatches is
// set: the batch fills one task of the capability's tool (at most limit
// pairs: the daily budget may leave fewer), or its oldest pair has waited
// a tenth of the cadence, at most covdom.MaxBatchWait. A batch that is not
// ready stays due and collects the pairs that fall due meanwhile.
func (s *Service) batchReady(capability string, due []covdom.DueTarget, limit int) bool {
	if !s.cfg.FillBatches {
		return true
	}
	var oldest time.Duration
	for _, d := range due {
		oldest = max(oldest, d.Waited)
	}
	minBatch := min(scanapp.CoverageChunkSize(capability), limit)
	return covdom.BatchReady(len(due), minBatch, oldest, s.ruleOf(capability).Every)
}

// dueBatch is the planner's due batch with repositories taken out (and
// blocked) for a capability that takes network kinds.
func (s *Service) dueBatch(ctx context.Context, tenantID shared.ID, capability string, limit int, lookahead time.Duration) ([]covdom.DueTarget, error) {
	due, err := s.planner.DueBatch(ctx, tenantID, capability, limit, lookahead)
	if err != nil {
		return nil, err
	}
	return s.blockRepositories(ctx, tenantID, capability, due)
}

// pauseCapability pauses the capability's pairs whose time has come with a
// readiness reason.
func (s *Service) pauseCapability(ctx context.Context, tenantID shared.ID, capability, reason string, retryAfter time.Duration) error {
	n, err := s.planner.PauseForReadiness(ctx, tenantID, capability, reason, retryAfter)
	if err != nil {
		return err
	}
	if n > 0 {
		s.logger.Info("coverage paused", "tenant_id", tenantID.String(), "capability", capability,
			"reason", reason, "pairs", n)
	}
	return nil
}

// blockNeverOpens handles a refusal that lists targets whose scan windows
// never open: it blocks those pairs and returns the pairs left to run.
// handled is false when err is not that refusal or lists none of the batch's
// targets, so the caller treats it as a refusal of the whole batch. One such
// target must not stall the capability for the others.
func (s *Service) blockNeverOpens(ctx context.Context, tenantID shared.ID, capability string, due []covdom.DueTarget, err error) (rest []covdom.DueTarget, handled bool, ferr error) {
	var never *scanapp.NeverOpensError
	if !errors.As(err, &never) {
		return nil, false, nil
	}
	bad := make(map[string]bool, len(never.Targets))
	for _, t := range never.Targets {
		bad[strings.ToLower(strings.TrimSpace(t))] = true
	}
	blocked := map[shared.ID]string{}
	for _, d := range due {
		if bad[strings.ToLower(strings.TrimSpace(d.Target()))] {
			blocked[d.AssetID] = strings.ToLower(scanapp.CodeWindowNeverOpens)
			continue
		}
		rest = append(rest, d)
	}
	if len(blocked) == 0 {
		return nil, false, nil
	}
	if merr := s.planner.MarkBlocked(ctx, tenantID, capability, blocked, BlockedRecheck); merr != nil {
		return nil, false, merr
	}
	s.logger.Info("coverage targets never open, pairs blocked", "tenant_id", tenantID.String(),
		"capability", logger.SanitizeValue(capability), "blocked", len(blocked), "remaining", len(rest))
	return rest, true, nil
}

// startBatch starts one capability on a due batch at a depth and records
// the outcome on its pairs. It returns how many pairs were queued.
func (s *Service) startBatch(ctx context.Context, tenantID shared.ID, capability string, due []covdom.DueTarget, depth scanworkflow.Depth) (int, error) {
	byTarget := make(map[string][]shared.ID, len(due))
	targets := make([]string, 0, len(due))
	for _, d := range due {
		t := d.Target()
		key := strings.ToLower(t)
		if _, dup := byTarget[key]; !dup {
			targets = append(targets, t)
		}
		byTarget[key] = append(byTarget[key], d.AssetID)
	}
	res, err := s.starter.StartCoverage(ctx, scanapp.CoverageInput{TenantID: tenantID, Capability: capability, Targets: targets, Depth: string(depth)})
	if errors.Is(err, scanapp.ErrCoverageBusy) {
		return 0, nil // the previous batch is still running: back-pressure
	}
	if err != nil {
		// A refusal that says the capability cannot run for the tenant now
		// (a sensor went offline between the readiness check and the
		// trigger, a policy the readiness check does not read) pauses the
		// capability with its readiness reason; it is retried after
		// RefusalRetry. No blocked run is recorded.
		if reason := scanapp.CoverageReadinessForRefusal(err); reason != "" {
			return 0, s.pauseCapability(ctx, tenantID, capability, reason, RefusalRetry)
		}
		// Targets whose scan windows never open: block only those pairs
		// and run the rest of the batch (see blockNeverOpens).
		rest, handled, berr := s.blockNeverOpens(ctx, tenantID, capability, due, err)
		if berr != nil {
			return 0, berr
		}
		if handled {
			if len(rest) == 0 {
				return 0, nil
			}
			return s.startBatch(ctx, tenantID, capability, rest, depth)
		}
		// Any other refusal of the whole batch (about its targets) blocks
		// the batch's pairs with the code and rechecks them later; retrying
		// it every pass changes nothing. Any other error (the database)
		// leaves them due.
		var de *shared.DomainError
		if errors.As(err, &de) && de.Code != "" {
			blocked := make(map[shared.ID]string, len(due))
			for _, d := range due {
				blocked[d.AssetID] = strings.ToLower(de.Code)
			}
			if err := s.planner.MarkBlocked(ctx, tenantID, capability, blocked, BlockedRecheck); err != nil {
				return 0, err
			}
			s.logger.Info("coverage batch refused, pairs blocked", "tenant_id", tenantID.String(),
				"capability", logger.SanitizeValue(capability), "targets", len(targets), "code", logger.SanitizeValue(de.Code))
			return 0, nil
		}
		s.logger.Warn("coverage run not started", "tenant_id", tenantID.String(), "capability", capability,
			"targets", len(targets), "error", logger.SanitizeError(err))
		return 0, nil
	}
	blocked := map[shared.ID]string{}
	for _, r := range res.Refused {
		code := r.Code
		if code == "" {
			code = "refused"
		}
		for _, id := range byTarget[strings.ToLower(strings.TrimSpace(r.Target))] {
			blocked[id] = code
		}
	}
	if err := s.planner.MarkBlocked(ctx, tenantID, capability, blocked, BlockedRecheck); err != nil {
		return 0, err
	}
	if res.RunID == nil {
		return 0, nil
	}
	if depth == scanworkflow.DepthDeep {
		s.logger.Info("coverage: deep onboarding pass of new roots started", "tenant_id", tenantID.String(),
			"capability", capability, "roots", len(res.Kept), "depth", res.Depth)
	}
	kept := make([]shared.ID, 0, len(res.Kept))
	for _, t := range res.Kept {
		kept = append(kept, byTarget[strings.ToLower(t)]...)
	}
	if err := s.planner.MarkQueued(ctx, tenantID, capability, kept, *res.RunID, res.Tool); err != nil {
		return 0, fmt.Errorf("record queued coverage: %w", err)
	}
	return len(kept), nil
}
