package command

// Scan windows at the claim (RFC-067, docs/architecture/scan-windows.md).
// Poll, Claim and Acknowledge (claim by id) run every pending probing job
// through the scan window evaluator before a sensor gets it:
//
//   - every target inside its windows: the job goes, carrying the smallest
//     rate cap of the governing allow sources; a concurrency cap that is
//     reached defers it one minute;
//   - no target inside: the job is deferred (scheduled_at) to its next
//     opening, at most an hour ahead, with window_hold saying why;
//   - some inside: a job of a run step is split, the open targets go and a
//     sibling job of the same step waits with the others; any other job
//     waits whole;
//   - targets that never open: deferred an hour at a time, flagged
//     (never), without extending the job's expiry;
//   - a lookup that cannot decide withholds the job for this poll (fail
//     closed).
//
// A deferred job is not a candidate before its scheduled_at, so waiting jobs
// never fill the claim window.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	swapp "github.com/openctemio/openctem/api/internal/app/scanwindow"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// WindowSource loads what governs targets (*scanwindow.Resolver).
type WindowSource interface {
	Load(ctx context.Context, tenantID shared.ID, targets []string, now time.Time) (*swapp.Snapshot, error)
}

// WithScanWindows makes Poll, Claim and Acknowledge apply scan windows.
func WithScanWindows(src WindowSource) Option {
	return func(s *Service) { s.windows = src }
}

// Deferral bounds.
const (
	// windowRecheck is the longest a job is deferred at once: policy,
	// override and asset changes are picked up at least this often.
	windowRecheck = time.Hour
	// windowCapRetry is how long a job waits for a concurrency cap.
	windowCapRetry = time.Minute
)

// ErrOutsideWindow: the job claimed by id may not run now (scan windows);
// it was deferred. It reads as "claimed", so the sensor drops it.
var ErrOutsideWindow = fmt.Errorf("%w (%w): this job's scan window is closed; it waits for the next opening",
	ErrCommandClaimed, shared.ErrConflict)

// probingCommand reports whether scan windows govern the command type.
func probingCommand(c *commanddom.Command) bool {
	switch c.Type {
	case commanddom.CommandTypeScan, commanddom.CommandTypeValidate,
		commanddom.CommandTypeRetest, commanddom.CommandTypeConnectorScan:
		return true
	}
	return false
}

// commandTier is the probe tier a job is judged at: the higher of its
// tool's tier (an unknown or missing tool is active) and the tier its
// dispatch gate recorded.
func commandTier(c *commanddom.Command) int {
	t := swdom.TierActive
	if tool := commanddom.PayloadTool(c.Payload); tool != "" {
		t = int(stage.ProbeTier(tool))
	}
	if c.DispatchGate != nil && c.DispatchGate.Tier > t {
		t = c.DispatchGate.Tier
	}
	return t
}

// windowTargets are the targets a job is judged on; a job whose targets
// cannot be read is judged as one unnamed target (only policies that
// select by nothing, or by zone, apply to it).
func windowTargets(c *commanddom.Command) []string {
	if ts := payloadTargets(c.Payload); len(ts) > 0 {
		return ts
	}
	return []string{""}
}

// windowVerdict is the hold's answer for one job.
type windowVerdict struct {
	keep *commanddom.Command // the job to hand out (maybe narrowed); nil: not now
	rate int                 // rate cap to deliver (0: none)
}

// windowHold decides each candidate. It returns the jobs to hand out (some
// narrowed) and the rate caps they carry.
func (s *Service) windowHold(ctx context.Context, tenantID shared.ID, cmds []*commanddom.Command) ([]*commanddom.Command, map[shared.ID]int) {
	if s.windows == nil || len(cmds) == 0 {
		return cmds, nil
	}
	var targets []string
	for _, c := range cmds {
		if c.TenantID.Equals(tenantID) && probingCommand(c) {
			targets = append(targets, windowTargets(c)...)
		}
	}
	if len(targets) == 0 {
		return cmds, nil
	}
	snap, err := s.windows.Load(ctx, tenantID, targets, s.clock())
	if err != nil {
		s.logger.Warn("scan windows could not be read; withholding probing jobs",
			"tenant_id", tenantID.String(), "error", err)
		out := cmds[:0:0]
		for _, c := range cmds {
			if !probingCommand(c) {
				out = append(out, c)
			}
		}
		return out, nil
	}
	if snap.Empty() {
		return cmds, nil
	}
	caps := &capTracker{tenantID: tenantID}
	out := cmds[:0:0]
	rates := map[shared.ID]int{}
	for _, c := range cmds {
		if !c.TenantID.Equals(tenantID) || !probingCommand(c) {
			out = append(out, c) // never decided across tenants; the poll is tenant-scoped
			continue
		}
		v := s.windowDecide(ctx, snap, caps, c)
		if v.keep == nil {
			continue
		}
		if v.rate > 0 {
			rates[v.keep.ID] = v.rate
		}
		out = append(out, v.keep)
	}
	return out, rates
}

// windowHoldOne decides one job a sensor claims by id: the job to hand out
// (maybe narrowed) and its rate cap, or ErrOutsideWindow /
// ErrScopeRecheckUnavailable.
func (s *Service) windowHoldOne(ctx context.Context, cmd *commanddom.Command) (*commanddom.Command, int, error) {
	if s.windows == nil || !probingCommand(cmd) {
		return cmd, 0, nil
	}
	snap, err := s.windows.Load(ctx, cmd.TenantID, windowTargets(cmd), s.clock())
	if err != nil {
		s.logger.Warn("scan windows could not be read; withholding the job", "command_id", cmd.ID.String(), "error", err)
		return nil, 0, ErrScopeRecheckUnavailable
	}
	if snap.Empty() {
		return cmd, 0, nil
	}
	v := s.windowDecide(ctx, snap, &capTracker{tenantID: cmd.TenantID}, cmd)
	if v.keep == nil {
		return nil, 0, ErrOutsideWindow
	}
	return v.keep, v.rate, nil
}

// windowDecide applies the windows to one job of the snapshot's tenant.
func (s *Service) windowDecide(ctx context.Context, snap *swapp.Snapshot, caps *capTracker, c *commanddom.Command) windowVerdict {
	now := snap.Now()
	tier := commandTier(c)
	targets := windowTargets(c)
	var all []swdom.Source
	var open, closed []string
	var closedSources []swdom.Source
	for _, t := range targets {
		src := snap.SourcesFor(t, c.ScanZoneID)
		all = append(all, src...)
		if swdom.Decide(src, tier, now).Open {
			open = append(open, t)
		} else {
			closed = append(closed, t)
			closedSources = append(closedSources, src...)
		}
	}
	d := swdom.Decide(all, tier, now)
	log := s.logger.With("tenant_id", c.TenantID.String(), "command_id", c.ID.String())
	if d.Open {
		return s.windowAdmit(ctx, caps, c, d, log)
	}
	if len(open) > 0 && len(closed) > 0 && splittable(c) {
		return s.windowSplit(ctx, snap, caps, c, tier, open, closed, closedSources, log)
	}
	s.windowDefer(ctx, c, d, now, log)
	return windowVerdict{}
}

// splittable reports whether a job may be split per target: a scan job of a
// run step (the step counts its jobs), not a platform job.
func splittable(c *commanddom.Command) bool {
	return c.Type == commanddom.CommandTypeScan && c.StepRunID != nil && !c.IsPlatformJob
}

// windowAdmit hands out an open job, unless a concurrency cap of a
// governing allow source is reached (deferred one minute).
func (s *Service) windowAdmit(ctx context.Context, caps *capTracker, c *commanddom.Command, d swdom.Decision, log *logger.Logger) windowVerdict {
	if len(d.Caps) == 0 {
		return windowVerdict{keep: c, rate: d.RateLimitRPS}
	}
	store, ok := s.repo.(commanddom.WindowHoldStore)
	if !ok {
		log.Warn("command repository cannot record scan window caps; withholding the job")
		return windowVerdict{}
	}
	full, ids, err := caps.reserve(ctx, store, d.Caps)
	if err != nil {
		log.Warn("scan window caps could not be read; withholding the job", "error", err)
		return windowVerdict{}
	}
	now := s.clock()
	if full != "" {
		hold := swdom.Hold{Reason: swdom.HoldConcurrency, CheckedAt: now,
			Blocking: []swdom.Block{{Ref: refOf(d, full)}}}
		s.writeDeferral(ctx, c, commanddom.WindowDeferral{Until: now.Add(windowCapRetry), Hold: holdJSON(hold), ExtendExpiry: true}, log)
		return windowVerdict{}
	}
	// Not applied when already recorded (an earlier poll) or when the job
	// changed meanwhile; a changed job fails the claim's own checks.
	if _, err := store.RecordWindowPolicies(ctx, c, ids); err != nil {
		log.Warn("scan window policies could not be recorded; withholding the job", "error", err)
		caps.release(ids)
		return windowVerdict{}
	}
	return windowVerdict{keep: c, rate: d.RateLimitRPS}
}

func refOf(d swdom.Decision, sourceID string) swdom.Ref {
	for _, r := range d.Governing {
		if r.SourceID == sourceID {
			return r
		}
	}
	return swdom.Ref{SourceID: sourceID}
}

// windowSplit keeps the open targets in the job and moves the others to a
// deferred sibling of the same step.
func (s *Service) windowSplit(ctx context.Context, snap *swapp.Snapshot, caps *capTracker, c *commanddom.Command, tier int,
	open, closed []string, closedSources []swdom.Source, log *logger.Logger) windowVerdict {
	store, ok := s.repo.(commanddom.WindowHoldStore)
	if !ok {
		log.Warn("command repository cannot split a job for scan windows; withholding it")
		return windowVerdict{}
	}
	keep, err1 := narrowPayload(c.Payload, open)
	wait, err2 := narrowPayload(c.Payload, closed)
	if err1 != nil || err2 != nil {
		log.Warn("cannot split a job for scan windows; withholding it", "error", errors.Join(err1, err2))
		return windowVerdict{}
	}
	now := snap.Now()
	d := swdom.Decide(closedSources, tier, now)
	sibling, won, err := store.SplitPending(ctx, c, keep, wait, deferralOf(d, now))
	if err != nil || !won {
		if err != nil {
			log.Warn("cannot split a job for scan windows; withholding it", "error", err)
		}
		return windowVerdict{}
	}
	log.Warn("job split for scan windows: targets outside their window wait in a new job",
		"open", len(open), "waiting", len(closed), "waiting_job", sibling.String(), "next_open", d.NextOpen)
	cp := *c
	cp.Payload = keep
	var openSources []swdom.Source
	for _, t := range open {
		openSources = append(openSources, snap.SourcesFor(t, c.ScanZoneID)...)
	}
	return s.windowAdmit(ctx, caps, &cp, swdom.Decide(openSources, tier, now), log)
}

// windowDefer defers a whole job to its next opening.
func (s *Service) windowDefer(ctx context.Context, c *commanddom.Command, d swdom.Decision, now time.Time, log *logger.Logger) {
	s.writeDeferral(ctx, c, deferralOf(d, now), log)
}

func (s *Service) writeDeferral(ctx context.Context, c *commanddom.Command, def commanddom.WindowDeferral, log *logger.Logger) {
	store, ok := s.repo.(commanddom.WindowHoldStore)
	if !ok {
		log.Warn("command repository cannot defer a job for scan windows; withholding it")
		return
	}
	if _, err := store.DeferPending(ctx, c, def); err != nil {
		log.Warn("cannot defer a job for scan windows; withholding it", "error", err)
	}
}

// deferralOf is how a job closed by d waits: until its next opening, at
// most windowRecheck ahead; a job that never opens is re-checked hourly and
// its expiry is not extended.
func deferralOf(d swdom.Decision, now time.Time) commanddom.WindowDeferral {
	until := now.Add(windowRecheck)
	if d.NextOpen != nil && d.NextOpen.Before(until) {
		until = *d.NextOpen
	}
	hold := swdom.Hold{Reason: swdom.HoldWindow, NextOpenAt: d.NextOpen, Never: d.Never, Blocking: d.Blocking, CheckedAt: now}
	def := commanddom.WindowDeferral{Until: until, Hold: holdJSON(hold), ExtendExpiry: !d.Never}
	if !d.Never && d.NextOpen != nil {
		opens := *d.NextOpen
		def.RunOpensAt = &opens
	}
	return def
}

func holdJSON(h swdom.Hold) json.RawMessage {
	b, err := json.Marshal(h)
	if err != nil {
		return json.RawMessage(`{"reason":"window"}`)
	}
	return b
}

// capTracker counts jobs under capped policies for one poll: what runs
// (read once) plus what this poll handed out.
type capTracker struct {
	tenantID shared.ID
	counts   map[string]int
}

// reserve takes one slot of every cap, or names the first full one.
func (t *capTracker) reserve(ctx context.Context, store commanddom.WindowHoldStore, caps []swdom.Cap) (string, []string, error) {
	var missing []string
	for _, cp := range caps {
		if _, ok := t.counts[cp.SourceID]; !ok {
			missing = append(missing, cp.SourceID)
		}
	}
	if len(missing) > 0 {
		n, err := store.CountRunningUnderPolicies(ctx, t.tenantID, missing)
		if err != nil {
			return "", nil, err
		}
		if t.counts == nil {
			t.counts = map[string]int{}
		}
		for _, id := range missing {
			t.counts[id] = n[id]
		}
	}
	ids := make([]string, 0, len(caps))
	for _, cp := range caps {
		if t.counts[cp.SourceID] >= cp.MaxConcurrent {
			return cp.SourceID, nil, nil
		}
		ids = append(ids, cp.SourceID)
	}
	for _, id := range ids {
		t.counts[id]++
	}
	return "", ids, nil
}

func (t *capTracker) release(ids []string) {
	for _, id := range ids {
		t.counts[id]--
	}
}

// withWindowRates folds the scan window rate caps into the rules each job
// carries (the smallest rate wins).
func withWindowRates(rules map[shared.ID]*bp.JobRules, rates map[shared.ID]int) map[shared.ID]*bp.JobRules {
	if len(rates) == 0 {
		return rules
	}
	if rules == nil {
		rules = map[shared.ID]*bp.JobRules{}
	}
	for id, rate := range rates {
		r, ok := rules[id]
		if !ok || r == nil {
			rules[id] = &bp.JobRules{RateLimit: rate, Programs: []string{"scan window"}}
			continue
		}
		if r.RateLimit == 0 || rate < r.RateLimit {
			r.RateLimit = rate
		}
	}
	return rules
}

// WithClock replaces the service clock (tests).
func WithClock(now func() time.Time) Option {
	return func(s *Service) { s.now = now }
}
