// Package retest runs continuous retests (RFC-039,
// docs/rfcs/RFC-039-continuous-retest.md): it re-runs the nuclei template that
// produced a finding against the finding's own target, probes the same target's
// reachability, and settles the finding — fixed, still present (regression
// reopen) or unknown. It serves "Retest now" and the auto-retest scheduler.
//
// Transport: the two checks are ordinary `validate` commands (the RFC-011
// validation transport: queue, poll, lease, capability routing, expiry). Their
// evidence is recorded advisory-only; this service, not the validation verdict
// rule, decides what the result means for the finding.
package retest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Limits (RFC-039 §8.1). Server-side; a client cannot raise them.
const (
	// Cooldown is the minimum time between two retest requests of one finding.
	Cooldown = 10 * time.Minute
	// MaxPendingPerAsset bounds retests in flight against one asset.
	MaxPendingPerAsset = 3
	// MaxPendingManual / MaxPendingAuto bound a tenant's retests in flight.
	MaxPendingManual = 20
	MaxPendingAuto   = 50
	// Deadline is how long a retest may wait for its sensor results before it
	// is settled as unknown.
	Deadline = 30 * time.Minute
	// ResolvedLookback: an auto retest re-checks a resolved finding only when
	// it was resolved within this window.
	ResolvedLookback = 90 * 24 * time.Hour
	// checkTimeoutSeconds bounds one check on the sensor.
	checkTimeoutSeconds = 120
)

// Store is the persistence the service needs (*postgres.FindingRetestRepository).
type Store interface {
	Create(ctx context.Context, rt *retestdom.Retest) error
	SetCommands(ctx context.Context, tenantID, id shared.ID, check, reach *shared.ID) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*retestdom.Retest, error)
	FindPendingByCommand(ctx context.Context, tenantID, commandID shared.ID) (*retestdom.Retest, error)
	ListByFinding(ctx context.Context, tenantID, findingID shared.ID, limit int) ([]*retestdom.Retest, error)
	LastRequestedAt(ctx context.Context, tenantID, findingID shared.ID) (*time.Time, error)
	CountPending(ctx context.Context, tenantID shared.ID, trigger retestdom.Trigger) (int, error)
	CountPendingForAsset(ctx context.Context, tenantID, assetID shared.ID) (int, error)
	ListSettleCandidates(ctx context.Context, now time.Time, limit int) ([]*retestdom.Retest, error)
	Settle(ctx context.Context, in retestdom.SettleInput) (retestdom.SettleResult, error)
	RecordRequested(ctx context.Context, rt *retestdom.Retest, source vulnerability.ActivitySource) error
}

// FindingReader reads one finding of a tenant.
type FindingReader interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error)
}

// AssetReader reads one asset of a tenant.
type AssetReader interface {
	GetByID(ctx context.Context, tenantID, assetID shared.ID) (*asset.Asset, error)
}

// CommandReader reads a command of a tenant (its status and result).
type CommandReader interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*commanddom.Command, error)
}

// SensorAvailability answers "can a sensor of this tenant re-run a nuclei
// template right now?" (validate:nuclei, online, with capacity).
type SensorAvailability interface {
	HasNucleiValidationSensor(ctx context.Context, tenantID shared.ID) (bool, error)
}

// TargetGate decides whether an active check may touch an asset. It must fail
// closed: an error refuses the retest. The scope-exclusion gate is wired today;
// the EASM attribution gate (#835: only confirmed assets) plugs in here too.
type TargetGate interface {
	AllowActiveCheck(ctx context.Context, tenantID shared.ID, a *asset.Asset) (bool, string, error)
}

// AuditLogger writes audit-log events.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Service runs retests.
type Service struct {
	store      Store
	findings   FindingReader
	assets     AssetReader
	commands   CommandReader
	dispatcher validation.JobDispatcher
	sensors    SensorAvailability
	gates      []TargetGate
	audit      AuditLogger
	// regressionSLA and announcer run after a retest moved a finding.
	regressionSLA RegressionSLA
	announcer     Announcer
	now           func() time.Time
	logger        *logger.Logger
}

// NewService wires the service. gates are applied in order; any refusal or
// error refuses the retest.
func NewService(store Store, findings FindingReader, assets AssetReader, commands CommandReader,
	dispatcher validation.JobDispatcher, sensors SensorAvailability, log *logger.Logger, gates ...TargetGate,
) *Service {
	return &Service{
		store: store, findings: findings, assets: assets, commands: commands,
		dispatcher: dispatcher, sensors: sensors, gates: gates,
		now: time.Now, logger: log.With("service", "retest"),
	}
}

// SetRegressionSLA wires the fresh-SLA-on-regression restart (RFC-039 D2).
func (s *Service) SetRegressionSLA(r RegressionSLA) { s.regressionSLA = r }

// SetAnnouncer wires the ticket comment + notification on a fix or regression.
func (s *Service) SetAnnouncer(a Announcer) { s.announcer = a }

// SetAuditLogger wires the audit log for "Retest now" requests.
func (s *Service) SetAuditLogger(a AuditLogger) { s.audit = a }

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// RequestInput is one retest request.
type RequestInput struct {
	TenantID    shared.ID
	FindingID   shared.ID
	Trigger     retestdom.Trigger
	RequestedBy *shared.ID            // the user, for a manual retest
	Audit       auditapp.AuditContext // request context, for a manual retest
}

// Request validates and queues one retest. The tenant comes from the caller's
// authenticated context; a finding id of another tenant is "not found".
func (s *Service) Request(ctx context.Context, in RequestInput) (*retestdom.Retest, error) {
	if in.TenantID.IsZero() || in.FindingID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and finding are required", shared.ErrValidation)
	}
	if in.Trigger != retestdom.TriggerManual && !in.Trigger.IsSystem() {
		return nil, fmt.Errorf("%w: unknown retest trigger", shared.ErrValidation)
	}

	f, a, templateID, target, err := s.eligible(ctx, in.TenantID, in.FindingID)
	if err != nil {
		return nil, err
	}

	if err := s.checkLimits(ctx, in.TenantID, f.ID(), a.ID(), in.Trigger); err != nil {
		return nil, err
	}
	if s.sensors != nil {
		ok, err := s.sensors.HasNucleiValidationSensor(ctx, in.TenantID)
		if err != nil {
			return nil, fmt.Errorf("sensor availability: %w", err)
		}
		if !ok {
			return nil, retestdom.ErrNoSensor
		}
	}

	now := s.now().UTC()
	rt := &retestdom.Retest{
		ID: shared.NewID(), TenantID: in.TenantID, FindingID: f.ID(), AssetID: a.ID(),
		Trigger: in.Trigger, RequestedBy: in.RequestedBy, Status: retestdom.StatusPending,
		PriorStatus: f.Status(), TemplateID: templateID, Target: target,
		DeadlineAt: now.Add(Deadline), CreatedAt: now,
	}
	if in.Trigger.IsSystem() {
		rt.RequestedBy = nil
	}
	// The pending row claims the finding's single retest slot before anything
	// is sent to a sensor.
	if err := s.store.Create(ctx, rt); err != nil {
		return nil, err
	}

	checkID, reachID, dispatchErr := s.dispatch(ctx, rt, a)
	if checkID != nil || reachID != nil {
		if err := s.store.SetCommands(ctx, rt.TenantID, rt.ID, checkID, reachID); err != nil {
			s.logger.Error("failed to record retest commands", "retest_id", rt.ID.String(), "error", err)
		}
		rt.CheckCommandID, rt.ReachCommandID = checkID, reachID
	}
	if dispatchErr != nil {
		s.logger.Warn("retest dispatch failed; settling as unknown",
			"retest_id", rt.ID.String(), "finding_id", rt.FindingID.String(), "error", dispatchErr)
		if _, err := s.settle(ctx, rt, retestdom.OutcomeUnknown, "dispatch failed: the checks could not be queued"); err != nil {
			s.logger.Error("failed to settle undispatched retest", "retest_id", rt.ID.String(), "error", err)
		}
		return nil, fmt.Errorf("queue retest: %w", dispatchErr)
	}

	if err := s.store.RecordRequested(ctx, rt, activitySource(rt.Trigger)); err != nil {
		s.logger.Warn("failed to record retest request activity", "retest_id", rt.ID.String(), "error", err)
	}
	if in.Trigger == retestdom.TriggerManual {
		s.auditRequest(ctx, in.Audit, rt)
	}
	s.logger.Info("retest queued", "tenant_id", rt.TenantID.String(), "finding_id", rt.FindingID.String(),
		"retest_id", rt.ID.String(), "trigger", string(rt.Trigger), "template_id", templateID)
	return rt, nil
}

// eligible loads the finding and its asset and checks that a deterministic
// re-check can run: an eligible status, a nuclei template, an active,
// network-addressable asset that passes every target gate. Returns the finding,
// the asset, the template id and the re-run target.
func (s *Service) eligible(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.Finding, *asset.Asset, string, string, error) {
	f, err := s.findings.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, nil, "", "", err
	}
	if !retestdom.EligibleStatus(f.Status()) {
		return nil, nil, "", "", fmt.Errorf("%w: a %s finding is not retested", retestdom.ErrNotEligible, f.Status())
	}
	templateID := strings.TrimSpace(f.RuleID())
	if !strings.EqualFold(f.ToolName(), "nuclei") || templateID == "" || !validation.TemplateSignatureAllowed(templateID) {
		return nil, nil, "", "", fmt.Errorf("%w: only findings from a nuclei template can be retested", retestdom.ErrNotEligible)
	}
	if f.AssetID().IsZero() {
		return nil, nil, "", "", fmt.Errorf("%w: the finding has no asset", retestdom.ErrNotEligible)
	}
	a, err := s.assets.GetByID(ctx, tenantID, f.AssetID())
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("asset lookup: %w", err)
	}
	if a.Status() != asset.StatusActive {
		return nil, nil, "", "", fmt.Errorf("%w: the asset is %s", retestdom.ErrNotEligible, a.Status())
	}
	if !validation.IsNetworkAddressable(a.Type()) {
		return nil, nil, "", "", fmt.Errorf("%w: a %s asset has no network address to retest", retestdom.ErrNotEligible, a.Type())
	}
	for _, g := range s.gates {
		ok, reason, err := g.AllowActiveCheck(ctx, tenantID, a)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("target gate: %w", err)
		}
		if !ok {
			return nil, nil, "", "", fmt.Errorf("%w: %s", retestdom.ErrNotEligible, reason)
		}
	}
	target := ResolveTarget(f.FilePath(), a.Name())
	if target == "" {
		return nil, nil, "", "", fmt.Errorf("%w: the asset has no address", retestdom.ErrNotEligible)
	}

	return f, a, templateID, target, nil
}

// checkLimits applies the per-finding cooldown and the in-flight caps.
func (s *Service) checkLimits(ctx context.Context, tenantID, findingID, assetID shared.ID, trigger retestdom.Trigger) error {
	last, err := s.store.LastRequestedAt(ctx, tenantID, findingID)
	if err != nil {
		return err
	}
	if last != nil && s.now().Sub(*last) < Cooldown {
		return fmt.Errorf("%w: this finding was retested less than %d minutes ago", retestdom.ErrRateLimited, int(Cooldown.Minutes()))
	}
	n, err := s.store.CountPendingForAsset(ctx, tenantID, assetID)
	if err != nil {
		return err
	}
	if n >= MaxPendingPerAsset {
		return fmt.Errorf("%w: %d retests of this asset are already running", retestdom.ErrRateLimited, n)
	}
	limit := MaxPendingManual
	if trigger.IsSystem() {
		limit = MaxPendingAuto
	}
	n, err = s.store.CountPending(ctx, tenantID, trigger)
	if err != nil {
		return err
	}
	if n >= limit {
		return fmt.Errorf("%w: %d %s retests are already running for this organization", retestdom.ErrRateLimited, n, trigger)
	}
	return nil
}

// dispatch queues the template re-run and the reachability probe.
func (s *Service) dispatch(ctx context.Context, rt *retestdom.Retest, a *asset.Asset) (*shared.ID, *shared.ID, error) {
	target := validation.Target{AssetID: a.ID(), Type: a.Type().String(), Address: rt.Target}
	check := validation.ValidationJob{
		JobID: shared.NewID(), TenantID: rt.TenantID, FindingID: rt.FindingID,
		ExecutorKind: validation.KindNuclei, Technique: validation.NucleiTechnique,
		Target: target, TimeoutSeconds: checkTimeoutSeconds, TemplateID: rt.TemplateID, RetestID: rt.ID,
	}
	checkID, err := s.dispatcher.Dispatch(ctx, check)
	if err != nil {
		return nil, nil, err
	}
	reach := validation.ValidationJob{
		JobID: shared.NewID(), TenantID: rt.TenantID, FindingID: rt.FindingID,
		ExecutorKind: validation.KindSafeCheck, Technique: validation.SafeCheckTechnique,
		Target: target, TimeoutSeconds: checkTimeoutSeconds, RetestID: rt.ID,
	}
	reachID, err := s.dispatcher.Dispatch(ctx, reach)
	if err != nil {
		return &checkID, nil, err
	}
	return &checkID, &reachID, nil
}

func (s *Service) auditRequest(ctx context.Context, actx auditapp.AuditContext, rt *retestdom.Retest) {
	if s.audit == nil {
		return
	}
	actx.TenantID = rt.TenantID.String()
	event := auditapp.NewSuccessEvent(auditdom.ActionFindingRetestRequested, auditdom.ResourceTypeFinding, rt.FindingID.String()).
		WithMessage("Retest requested").
		WithMetadata("retest_id", rt.ID.String()).
		WithMetadata("template_id", rt.TemplateID).
		WithMetadata("target", rt.Target).
		WithMetadata("status", string(rt.PriorStatus))
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("failed to audit retest request", "retest_id", rt.ID.String(), "error", err)
	}
}

// List returns a finding's retests, newest first.
func (s *Service) List(ctx context.Context, tenantID, findingID shared.ID, limit int) ([]*retestdom.Retest, error) {
	if _, err := s.findings.GetByID(ctx, tenantID, findingID); err != nil {
		return nil, err
	}
	return s.store.ListByFinding(ctx, tenantID, findingID, limit)
}

// OnCommandFinished is called when a sensor completes or fails a command. When
// the command is one of a pending retest's checks and both checks are now
// terminal, the retest is settled. The tenant is the command's own.
func (s *Service) OnCommandFinished(ctx context.Context, tenantID, commandID shared.ID) {
	rt, err := s.store.FindPendingByCommand(ctx, tenantID, commandID)
	if err != nil {
		s.logger.Warn("retest lookup by command failed", "command_id", commandID.String(), "error", err)
		return
	}
	if rt == nil {
		return
	}
	if _, err := s.trySettle(ctx, rt, false); err != nil {
		s.logger.Error("failed to settle retest", "retest_id", rt.ID.String(), "error", err)
	}
}

// Sweep settles pending retests whose checks all ended (failed, expired,
// canceled) or whose deadline passed. Returns how many it settled.
func (s *Service) Sweep(ctx context.Context, limit int) (int, error) {
	now := s.now().UTC()
	list, err := s.store.ListSettleCandidates(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	settled := 0
	for _, rt := range list {
		ok, err := s.trySettle(ctx, rt, !now.Before(rt.DeadlineAt))
		if err != nil {
			s.logger.Error("failed to settle retest", "retest_id", rt.ID.String(), "error", err)
			continue
		}
		if ok {
			settled++
		}
	}
	return settled, nil
}

// trySettle reads both checks; when both are terminal (or force — the deadline
// passed), it decides and settles. Returns whether it settled.
func (s *Service) trySettle(ctx context.Context, rt *retestdom.Retest, force bool) (bool, error) {
	check, checkDone := s.readCheck(ctx, rt.TenantID, rt.CheckCommandID)
	reach, reachDone := s.readCheck(ctx, rt.TenantID, rt.ReachCommandID)
	if !(checkDone && reachDone) && !force {
		return false, nil
	}
	outcome, reason := retestdom.Decide(check, reach)
	if !(checkDone && reachDone) && outcome == retestdom.OutcomeUnknown {
		reason = "no sensor result before the deadline"
	}
	return s.settle(ctx, rt, outcome, reason)
}

// readCheck returns a command's result and whether the command is terminal. A
// missing, failed, expired or canceled command (or one with no outcome) is a
// Missing result; a command still queued or running is not terminal.
func (s *Service) readCheck(ctx context.Context, tenantID shared.ID, id *shared.ID) (retestdom.CheckResult, bool) {
	if id == nil {
		return retestdom.CheckResult{Missing: true}, true
	}
	cmd, err := s.commands.GetByTenantAndID(ctx, tenantID, *id)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return retestdom.CheckResult{Missing: true}, true
		}
		s.logger.Warn("retest command lookup failed", "command_id", id.String(), "error", err)
		return retestdom.CheckResult{Missing: true}, false
	}
	switch cmd.Status {
	case commanddom.CommandStatusCompleted:
		outcome, summary := commandOutcome(cmd.Result)
		if outcome == "" {
			return retestdom.CheckResult{Missing: true}, true
		}
		return retestdom.CheckResult{Outcome: outcome, Summary: summary}, true
	case commanddom.CommandStatusFailed, commanddom.CommandStatusExpired, commanddom.CommandStatusCanceled:
		return retestdom.CheckResult{Missing: true, Summary: cmd.ErrorMessage}, true
	default:
		return retestdom.CheckResult{Missing: true}, false
	}
}

// commandOutcome extracts outcome/summary from a validate command's result. The
// SDK poller nests an executor's metadata under "metadata"; a client completing
// the command directly may put it at the top level. Same rule as the
// validation completion hook.
func commandOutcome(raw json.RawMessage) (string, string) {
	if len(raw) == 0 {
		return "", ""
	}
	var result struct {
		validation.ValidateResultPayload
		Metadata validation.ValidateResultPayload `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", ""
	}
	v := result.ValidateResultPayload
	if v.Outcome == "" {
		v = result.Metadata
	}
	return v.Outcome, v.Summary
}

// settle completes the retest: the finding moves per the outcome (decided under
// the row lock from its current status) and the completion is written with the
// actor "system: retest".
func (s *Service) settle(ctx context.Context, rt *retestdom.Retest, outcome retestdom.Outcome, reason string) (bool, error) {
	var resolvedBy *shared.ID
	if rt.Trigger == retestdom.TriggerManual {
		resolvedBy = rt.RequestedBy
	}
	changes := map[string]any{
		"retest_id":   rt.ID.String(),
		"trigger":     string(rt.Trigger),
		"outcome":     string(outcome),
		"reason":      reason,
		"template_id": rt.TemplateID,
		"target":      rt.Target,
		"actor":       retestdom.ActorName,
	}
	if rt.RequestedBy != nil {
		changes["requested_by"] = rt.RequestedBy.String()
	}
	if rt.CheckCommandID != nil {
		changes["check_command_id"] = rt.CheckCommandID.String()
	}
	if rt.ReachCommandID != nil {
		changes["reach_command_id"] = rt.ReachCommandID.String()
	}
	source := activitySource(rt.Trigger)
	var regression bool
	res, err := s.store.Settle(ctx, retestdom.SettleInput{
		TenantID: rt.TenantID, RetestID: rt.ID, FindingID: rt.FindingID,
		Outcome: outcome, Reason: reason, ResolvedBy: resolvedBy, TemplateID: rt.TemplateID,
		Decide: func(current vulnerability.FindingStatus) retestdom.SettleDecision {
			next, change := retestdom.NextStatus(current, outcome)
			regression = change && retestdom.IsRegression(current, next)
			if regression {
				changes["regression"] = true
			}
			return retestdom.SettleDecision{Next: next, Change: change}
		},
		Activity: changes,
		Source:   source,
	})
	if err != nil {
		return false, err
	}
	if res.Applied {
		s.logger.Info("retest settled", "tenant_id", rt.TenantID.String(), "finding_id", rt.FindingID.String(),
			"retest_id", rt.ID.String(), "outcome", string(outcome), "from", string(res.PriorStatus),
			"to", string(res.ResultStatus), "regression", regression)
		if res.Moved {
			s.followUp(ctx, rt, res, regression, reason)
		}
	}
	return res.Applied, nil
}

// followUp runs after a retest moved a finding: a regression gets a fresh SLA
// deadline (D2), and a fix, a regression or a rejected fix is announced on the
// linked ticket and through notifications. Best-effort.
func (s *Service) followUp(ctx context.Context, rt *retestdom.Retest, res retestdom.SettleResult, regression bool, reason string) {
	if regression && s.regressionSLA != nil {
		if _, err := s.regressionSLA.RestartForRegression(ctx, rt.TenantID, []shared.ID{rt.FindingID}, "retest"); err != nil {
			s.logger.Warn("retest: SLA restart failed", "finding_id", rt.FindingID.String(), "error", err)
		}
	}
	if s.announcer == nil {
		return
	}
	kind := ChangeKind("")
	switch {
	case res.ResultStatus == vulnerability.FindingStatusResolved:
		kind = ChangeFixed
	case regression:
		kind = ChangeRegression
	case res.PriorStatus == vulnerability.FindingStatusFixApplied:
		kind = ChangeFixRejected
	default:
		return // a refuted validation downgrade: no one closed it, nothing to announce
	}
	s.announcer.Announce(ctx, Change{
		TenantID: rt.TenantID, FindingID: rt.FindingID, Kind: kind, Source: "retest",
		Detail: fmt.Sprintf("Retest of template %s against %s: %s.", rt.TemplateID, rt.Target, reason),
	})
}

// activitySource is the activity source a retest's entries are written with.
func activitySource(t retestdom.Trigger) vulnerability.ActivitySource {
	switch t {
	case retestdom.TriggerManual:
		return vulnerability.SourceAPI
	case retestdom.TriggerProofOfFix:
		return vulnerability.SourceAuto
	default:
		return vulnerability.SourceScheduled
	}
}

// ResolveTarget picks what the template re-run targets: the finding's recorded
// matched-at URL when its host is the asset's own host, else the asset's name.
// A finding can never point a retest at a host that is not its asset.
func ResolveTarget(matchedAt, assetName string) string {
	assetName = strings.TrimSpace(assetName)
	matchedAt = strings.TrimSpace(matchedAt)
	if matchedAt == "" || !strings.Contains(matchedAt, "://") {
		return assetName
	}
	u, err := url.Parse(matchedAt)
	if err != nil || u.Hostname() == "" {
		return assetName
	}
	if !strings.EqualFold(u.Hostname(), hostOf(assetName)) {
		return assetName
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return assetName
	}
	return matchedAt
}

// hostOf returns the host part of an asset name (a bare host, host:port or URL).
func hostOf(name string) string {
	if strings.Contains(name, "://") {
		if u, err := url.Parse(name); err == nil {
			return u.Hostname()
		}
	}
	if h, _, ok := strings.Cut(name, "/"); ok {
		name = h
	}
	if strings.Count(name, ":") == 1 {
		name, _, _ = strings.Cut(name, ":")
	}
	return strings.Trim(name, "[]")
}
