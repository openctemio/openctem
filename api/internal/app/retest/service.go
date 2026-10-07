// Package retest runs continuous retests (RFC-039,
// docs/rfcs/RFC-039-continuous-retest.md): it re-checks a finding against the
// finding's own target and settles the finding — fixed, still present
// (regression reopen) or unknown. It serves "Retest now", proof of fix and the
// auto-retest scheduler.
//
// Two methods:
//   - tool: when a sensor of the tenant reports "retest:<tool>" for the
//     finding's tool, one `retest` command asks that tool's retest handler for
//     a verdict on the finding (still present, fixed, unverifiable);
//   - validate: for nuclei findings otherwise, two ordinary `validate`
//     commands (the RFC-011 transport) re-run the template and probe the
//     target's reachability; their evidence is recorded advisory-only.
//
// Both ride the same queue, poll, lease, capability routing, expiry and
// active-probe gate; this service, not a validation verdict rule, decides what
// the result means for the finding.
package retest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	evidenceapp "github.com/openctemio/openctem/api/internal/app/evidence"
	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/evidence"
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

// RunRecorder records a retest as a scan run (kind retest) so it shows up in
// Runs with its tasks and logs (research/62 P0-3). Implemented by the scan
// run service.
type RunRecorder interface {
	StartRetestRun(ctx context.Context, rt *retestdom.Retest) (runID, stepRunID shared.ID, err error)
	FinishRetestRun(ctx context.Context, tenantID, runID shared.ID, succeeded bool, message, code string) error
}

// runLinker stores a retest's run id (*postgres.FindingRetestRepository).
type runLinker interface {
	SetRun(ctx context.Context, tenantID, id, runID shared.ID) error
}

// runRef is the run a retest's commands are tagged with (zero when no run
// recorder is wired).
type runRef struct{ run, step shared.ID }

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

// SensorAvailability answers "can a sensor of this tenant re-check this
// finding right now?" (online, with capacity): with the retest handler of the
// finding's tool (retest:<tool>), or by re-running a nuclei template
// (validate:nuclei).
type SensorAvailability interface {
	HasNucleiValidationSensor(ctx context.Context, tenantID shared.ID) (bool, error)
	HasRetestSensor(ctx context.Context, tenantID shared.ID, tool string) (bool, error)
}

// Dispatcher queues the two checks (*validation.CommandDispatcher). Dispatch
// passes every job through the active-probe gate (scope exclusions, the
// private-range policy, attribution, scan zones); Preflight runs the same
// gate before the retest row exists, so a refused target never claims the
// finding's retest slot.
type Dispatcher interface {
	validation.JobDispatcher
	Preflight(ctx context.Context, tenantID shared.ID, t validation.Target) error
	// DispatchToolRetest queues one retest command for the finding's tool,
	// through the same gate.
	DispatchToolRetest(ctx context.Context, job validation.ToolRetestJob) (shared.ID, error)
}

// Policy answers the tenant's retest policy: whether a confirmed fix
// resolves a finding (true) or moves it to validated_fixed for a person to
// confirm (false, the default).
type Policy interface {
	AutoResolve(ctx context.Context, tenantID shared.ID) bool
}

// EvidenceStore keeps a retest attempt's proof (internal/app/evidence).
type EvidenceStore interface {
	StoreRetest(ctx context.Context, tenantID, findingID, retestID shared.ID, items []evidence.Item, meta evidenceapp.Meta)
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
	dispatcher Dispatcher
	sensors    SensorAvailability
	audit      AuditLogger
	// regressionSLA and announcer run after a retest moved a finding.
	regressionSLA RegressionSLA
	announcer     Announcer
	policy        Policy
	evidence      EvidenceStore
	runs          RunRecorder
	now           func() time.Time
	logger        *logger.Logger
}

// NewService wires the service.
func NewService(store Store, findings FindingReader, assets AssetReader, commands CommandReader,
	dispatcher Dispatcher, sensors SensorAvailability, log *logger.Logger,
) *Service {
	return &Service{
		store: store, findings: findings, assets: assets, commands: commands,
		dispatcher: dispatcher, sensors: sensors,
		now: time.Now, logger: log.With("service", "retest"),
	}
}

// SetRunRecorder wires the scan run service: each retest then gets a run.
func (s *Service) SetRunRecorder(r RunRecorder) { s.runs = r }

// SetRegressionSLA wires the fresh-SLA-on-regression restart (RFC-039 D2).
func (s *Service) SetRegressionSLA(r RegressionSLA) { s.regressionSLA = r }

// SetAnnouncer wires the ticket comment + notification on a fix or regression.
func (s *Service) SetAnnouncer(a Announcer) { s.announcer = a }

// SetPolicy wires the tenant retest policy. Nil: a confirmed fix never
// resolves on its own.
func (s *Service) SetPolicy(p Policy) { s.policy = p }

// SetEvidenceStore wires storage of each attempt's proof. Nil: none is kept.
func (s *Service) SetEvidenceStore(e EvidenceStore) { s.evidence = e }

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
	method, err := s.chooseMethod(ctx, in.TenantID, findingTool(f))
	if err != nil {
		return nil, err
	}

	now := s.now().UTC()
	rt := &retestdom.Retest{
		ID: shared.NewID(), TenantID: in.TenantID, FindingID: f.ID(), AssetID: a.ID(),
		Trigger: in.Trigger, RequestedBy: in.RequestedBy, Status: retestdom.StatusPending,
		PriorStatus: f.Status(), TemplateID: templateID, Target: target, Method: method,
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

	ref := s.startRun(ctx, rt)

	var checkID, reachID *shared.ID
	var dispatchErr error
	if method == retestdom.MethodTool {
		checkID, dispatchErr = s.dispatchTool(ctx, rt, a, findingTool(f), f.Fingerprint(), ref)
	} else {
		checkID, reachID, dispatchErr = s.dispatch(ctx, rt, a, ref)
	}
	if checkID != nil || reachID != nil {
		if err := s.store.SetCommands(ctx, rt.TenantID, rt.ID, checkID, reachID); err != nil {
			s.logger.Error("failed to record retest commands", "retest_id", rt.ID.String(), "error", err)
		}
		rt.CheckCommandID, rt.ReachCommandID = checkID, reachID
	}
	if dispatchErr != nil {
		s.logger.Warn("retest dispatch failed; settling as unknown",
			"retest_id", rt.ID.String(), "finding_id", rt.FindingID.String(), "error", dispatchErr)
		if _, err := s.settle(ctx, rt, retestdom.Inconclusive(retestdom.ReasonError, "dispatch failed: the checks could not be queued")); err != nil {
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
		"retest_id", rt.ID.String(), "trigger", string(rt.Trigger), "template_id", templateID, "method", method)
	return rt, nil
}

// maxRuleIDLen bounds the rule id sent to a sensor (the column is 255).
const maxRuleIDLen = 255

// findingTool is the finding's tool name as sensors register it.
func findingTool(f *vulnerability.Finding) string {
	return strings.ToLower(strings.TrimSpace(f.ToolName()))
}

// validRuleID: non-empty, bounded, printable, no whitespace inside.
func validRuleID(id string) bool {
	if id == "" || len(id) > maxRuleIDLen {
		return false
	}
	for _, r := range id {
		if r <= ' ' || r == 0x7f || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// chooseMethod picks how a finding of tool is re-checked: the tool's own
// retest handler when a tenant sensor offers it, else (nuclei only) the
// template re-run plus reachability probe. Without a sensor for either the
// request is refused (ErrNoSensor) before any state is recorded.
func (s *Service) chooseMethod(ctx context.Context, tenantID shared.ID, tool string) (string, error) {
	if s.sensors == nil {
		if tool == nucleiTool {
			return retestdom.MethodValidate, nil
		}
		return retestdom.MethodTool, nil
	}
	ok, err := s.sensors.HasRetestSensor(ctx, tenantID, tool)
	if err != nil {
		return "", fmt.Errorf("sensor availability: %w", err)
	}
	if ok {
		return retestdom.MethodTool, nil
	}
	if tool == nucleiTool {
		ok, err := s.sensors.HasNucleiValidationSensor(ctx, tenantID)
		if err != nil {
			return "", fmt.Errorf("sensor availability: %w", err)
		}
		if ok {
			return retestdom.MethodValidate, nil
		}
	}
	return "", retestdom.ErrNoSensor
}

// nucleiTool is the tool name of nuclei findings.
const nucleiTool = "nuclei"

// eligible loads the finding and its asset and checks that a deterministic
// re-check can run: an eligible status, a rule of the finding's tool (for
// nuclei, a template that passes the template guard), an active,
// network-addressable asset that passes every target gate. Returns the
// finding, the asset, the rule (template) id and the re-run target.
func (s *Service) eligible(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.Finding, *asset.Asset, string, string, error) {
	f, err := s.findings.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, nil, "", "", err
	}
	if !retestdom.EligibleStatus(f.Status()) {
		return nil, nil, "", "", fmt.Errorf("%w: a %s finding is not retested", retestdom.ErrNotEligible, f.Status())
	}
	templateID := strings.TrimSpace(f.RuleID())
	tool := findingTool(f)
	if !validation.ValidRetestTool(tool) || !validRuleID(templateID) {
		return nil, nil, "", "", fmt.Errorf("%w: only findings with a tool and a rule id can be retested", retestdom.ErrNotEligible)
	}
	if tool == nucleiTool && !validation.TemplateSignatureAllowed(templateID) {
		return nil, nil, "", "", fmt.Errorf("%w: this nuclei template is not re-run by a retest", retestdom.ErrNotEligible)
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
	target := ResolveTarget(f.FilePath(), a.Name())
	if target == "" {
		return nil, nil, "", "", fmt.Errorf("%w: the asset has no address", retestdom.ErrNotEligible)
	}
	// A gate refusal is policy, not ineligibility: it wraps
	// validation.ErrTargetRefused (never ErrNotEligible), so proof-of-fix
	// stops instead of falling back to another probe of the same target.
	if err := s.dispatcher.Preflight(ctx, tenantID, probeTarget(a, target)); err != nil {
		return nil, nil, "", "", err
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

// probeTarget is what both checks probe: the re-run address on the asset.
func probeTarget(a *asset.Asset, address string) validation.Target {
	return validation.Target{AssetID: a.ID(), Type: a.Type().String(), Address: address, AssetName: a.Name()}
}

// dispatch queues the template re-run and the reachability probe.
func (s *Service) dispatch(ctx context.Context, rt *retestdom.Retest, a *asset.Asset, ref runRef) (*shared.ID, *shared.ID, error) {
	target := probeTarget(a, rt.Target)
	check := validation.ValidationJob{
		JobID: shared.NewID(), TenantID: rt.TenantID, FindingID: rt.FindingID,
		ExecutorKind: validation.KindNuclei, Technique: validation.NucleiTechnique,
		Target: target, TimeoutSeconds: checkTimeoutSeconds, TemplateID: rt.TemplateID, RetestID: rt.ID,
		ScanRunID: ref.run, ScanRunStepID: ref.step,
	}
	checkID, err := s.dispatcher.Dispatch(ctx, check)
	if err != nil {
		return nil, nil, err
	}
	reach := validation.ValidationJob{
		JobID: shared.NewID(), TenantID: rt.TenantID, FindingID: rt.FindingID,
		ExecutorKind: validation.KindSafeCheck, Technique: validation.SafeCheckTechnique,
		Target: target, TimeoutSeconds: checkTimeoutSeconds, RetestID: rt.ID,
		ScanRunID: ref.run, ScanRunStepID: ref.step,
	}
	reachID, err := s.dispatcher.Dispatch(ctx, reach)
	if err != nil {
		return &checkID, nil, err
	}
	return &checkID, &reachID, nil
}

// dispatchTool queues the one retest command for the finding's own tool.
func (s *Service) dispatchTool(ctx context.Context, rt *retestdom.Retest, a *asset.Asset, tool, fingerprint string, ref runRef) (*shared.ID, error) {
	id, err := s.dispatcher.DispatchToolRetest(ctx, validation.ToolRetestJob{
		TenantID: rt.TenantID, FindingID: rt.FindingID, RetestID: rt.ID, Tool: tool,
		Target: probeTarget(a, rt.Target), RuleID: rt.TemplateID, Fingerprint: fingerprint,
		TimeoutSeconds: checkTimeoutSeconds,
		ScanRunID:      ref.run, ScanRunStepID: ref.step,
	})
	if err != nil {
		return nil, err
	}
	return &id, nil
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
	matchedAt := s.matchedAt(ctx, rt)
	if cmd, done, ok := s.readToolRetest(ctx, rt); ok {
		rt.Method = retestdom.MethodTool
		if !done && !force {
			return false, nil
		}
		v := retestdom.Inconclusive(retestdom.ReasonNoResult, "no sensor result before the deadline")
		var tr retestdom.ToolResult
		switch {
		case cmd == nil:
			v = retestdom.Inconclusive(retestdom.ReasonNoResult, "no result from the tool's retest")
		case cmd.Status == commanddom.CommandStatusCompleted:
			tr = retestdom.DecideToolVerdict(cmd.Result, rt.FindingID.String(), matchedAt)
			v = tr.Verdict
		case done:
			v = retestdom.Inconclusive(retestdom.ReasonError, "the tool's retest did not complete: "+
				nonEmptyStr(evidence.RedactText(retestdom.CleanDetail(cmd.ErrorMessage)), string(cmd.Status)))
		}
		v = s.applyDrift(ctx, rt, v, tr.TemplateDigest, false)
		s.storeAttempt(ctx, rt, tr.Evidence, tr.TemplateDigest)
		if cmd != nil {
			rt.SensorID = cmd.SensorID
		}
		return s.settle(ctx, rt, v)
	}
	rt.Method = retestdom.MethodValidate
	check, checkDone := s.readCheck(ctx, rt.TenantID, rt.CheckCommandID)
	reach, reachDone := s.readCheck(ctx, rt.TenantID, rt.ReachCommandID)
	if !(checkDone && reachDone) && !force {
		return false, nil
	}
	v := retestdom.Decide(check, reach, matchedAt)
	if !(checkDone && reachDone) && v.Outcome == retestdom.OutcomeInconclusive && v.Code == retestdom.ReasonNoResult {
		v.Reason = "no sensor result before the deadline"
	}
	v = s.applyDrift(ctx, rt, v, check.TemplateDigest, true)
	s.storeAttempt(ctx, rt, check.Evidence, check.TemplateDigest)
	rt.SensorID = s.checkSensor(ctx, rt)
	return s.settle(ctx, rt, v)
}

// checkSensor is the sensor that claimed the retest's check command (nil when
// none did, or it cannot be read).
func (s *Service) checkSensor(ctx context.Context, rt *retestdom.Retest) *shared.ID {
	if rt.CheckCommandID == nil {
		return nil
	}
	c, err := s.commands.GetByTenantAndID(ctx, rt.TenantID, *rt.CheckCommandID)
	if err != nil || c == nil {
		return nil
	}
	return c.SensorID
}

// applyDrift makes a conclusive verdict inconclusive when the re-run cannot
// be tied to the template the finding was last seen with. A baseline that
// cannot be read fails closed.
func (s *Service) applyDrift(ctx context.Context, rt *retestdom.Retest, v retestdom.Verdict, digest string, requireDigest bool) retestdom.Verdict {
	if !v.Outcome.Conclusive() {
		return v
	}
	baseline, err := s.templateBaseline(ctx, rt)
	if err != nil {
		return retestdom.Inconclusive(retestdom.ReasonTemplateChanged, "the finding's template baseline could not be read")
	}
	return retestdom.ApplyTemplateDrift(v, baseline, digest, requireDigest)
}

// matchedAt is the finding's recorded endpoint (its matched-at URL), "" when
// it has none or cannot be read: then no attempt can prove the endpoint.
func (s *Service) matchedAt(ctx context.Context, rt *retestdom.Retest) string {
	f, err := s.findings.GetByID(ctx, rt.TenantID, rt.FindingID)
	if err != nil || f == nil {
		return ""
	}
	return f.FilePath()
}

// storeAttempt keeps what the re-run reported it sent and received.
func (s *Service) storeAttempt(ctx context.Context, rt *retestdom.Retest, items []evidence.Item, digest string) {
	if s.evidence == nil || len(items) == 0 {
		return
	}
	tool := "nuclei"
	if rt.Method == retestdom.MethodTool {
		tool = ""
		if f, err := s.findings.GetByID(ctx, rt.TenantID, rt.FindingID); err == nil && f != nil {
			tool = f.ToolName()
		}
	}
	s.evidence.StoreRetest(ctx, rt.TenantID, rt.FindingID, rt.ID, items, evidenceapp.Meta{
		ToolName: tool, RuleID: rt.TemplateID, TemplateDigest: digest,
	})
}

// readToolRetest reads a retest's check command when it is a tool retest (ok;
// a retest command of the retest's tenant). It returns the command (nil when
// it is gone) and whether it is terminal. ok is false for a validate retest,
// and when the command cannot be read (the validate path then treats it as a
// missing result).
func (s *Service) readToolRetest(ctx context.Context, rt *retestdom.Retest) (cmd *commanddom.Command, done, ok bool) {
	if rt.CheckCommandID == nil {
		return nil, true, rt.Method == retestdom.MethodTool
	}
	c, err := s.commands.GetByTenantAndID(ctx, rt.TenantID, *rt.CheckCommandID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) && rt.ReachCommandID == nil && rt.Method == retestdom.MethodTool {
			return nil, true, true
		}
		return nil, false, false
	}
	if c.Type != commanddom.CommandTypeRetest {
		return nil, false, false
	}
	switch c.Status {
	case commanddom.CommandStatusCompleted, commanddom.CommandStatusFailed,
		commanddom.CommandStatusExpired, commanddom.CommandStatusCanceled:
		return c, true, true
	default:
		return c, false, true
	}
}

func nonEmptyStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
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
		outcome, summary, digest, items := commandOutcome(cmd.Result)
		if outcome == "" {
			return retestdom.CheckResult{Missing: true}, true
		}
		return retestdom.CheckResult{Outcome: outcome, Summary: summary, TemplateDigest: digest, Evidence: items}, true
	case commanddom.CommandStatusFailed, commanddom.CommandStatusExpired, commanddom.CommandStatusCanceled:
		return retestdom.CheckResult{Missing: true, Summary: cmd.ErrorMessage}, true
	default:
		return retestdom.CheckResult{Missing: true}, false
	}
}

// commandOutcome extracts outcome/summary from a validate command's result. The
// SDK poller nests an executor's metadata under "metadata"; a client completing
// the command directly may put it at the top level. Same rule as the
// validation completion hook. The attempt's proof is evidence.evidence_items
// (CTIS 1.6 items), normalized.
func commandOutcome(raw json.RawMessage) (outcome, summary, templateDigest string, items []evidence.Item) {
	if len(raw) == 0 {
		return "", "", "", nil
	}
	var result struct {
		validation.ValidateResultPayload
		Metadata validation.ValidateResultPayload `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", "", "", nil
	}
	v := result.ValidateResultPayload
	if v.Outcome == "" {
		v = result.Metadata
	}
	// The template the re-run used (sensor#134, research/18 O6); sanitized:
	// anything that is not a sha256 digest counts as not reported.
	if d, ok := v.Evidence["template_digest"].(string); ok {
		templateDigest = vulnerability.SanitizeTemplateDigest(d)
	}
	if rawItems, ok := v.Evidence["evidence_items"]; ok {
		if b, err := json.Marshal(rawItems); err == nil {
			for _, it := range evidence.DecodeList(b, evidence.MaxItemsPerRetest) {
				if n, ok := evidence.Normalize(it); ok {
					items = append(items, n)
				}
			}
		}
	}
	return v.Outcome, v.Summary, templateDigest, items
}

// templateBaseline is the template digest recorded at the finding's last
// sighting ("" when none was recorded, or the finding store records no
// provenance). A read error is returned: the caller fails closed.
func (s *Service) templateBaseline(ctx context.Context, rt *retestdom.Retest) (string, error) {
	store, ok := s.findings.(vulnerability.TemplateProvenanceStore)
	if !ok {
		return "", nil
	}
	p, err := store.TemplateBaseline(ctx, rt.TenantID, rt.FindingID)
	if err != nil {
		s.logger.Warn("retest: cannot read the finding's template baseline", "finding_id", rt.FindingID.String(), "error", err)
		return "", err
	}
	return vulnerability.SanitizeTemplateDigest(p.TemplateDigest), nil
}

// settle completes the retest: the finding moves per the outcome (decided under
// the row lock from its current status) and the completion is written with the
// actor "system: retest".
func (s *Service) settle(ctx context.Context, rt *retestdom.Retest, v retestdom.Verdict) (bool, error) {
	outcome, reason := v.Outcome, evidence.RedactText(v.Reason)
	autoResolve := s.policy != nil && s.policy.AutoResolve(ctx, rt.TenantID)
	var resolvedBy *shared.ID
	if rt.Trigger == retestdom.TriggerManual {
		resolvedBy = rt.RequestedBy
	}
	changes := map[string]any{
		"retest_id":   rt.ID.String(),
		"trigger":     string(rt.Trigger),
		"outcome":     string(outcome),
		"reason_code": string(v.Code),
		"reason":      reason,
		"template_id": rt.TemplateID,
		"target":      rt.Target,
		"actor":       retestdom.ActorName,
	}
	if rt.Method != "" {
		changes["method"] = rt.Method
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
	if rt.SensorID != nil {
		changes["sensor_id"] = rt.SensorID.String()
	}
	source := activitySource(rt.Trigger)
	var regression bool
	res, err := s.store.Settle(ctx, retestdom.SettleInput{
		TenantID: rt.TenantID, RetestID: rt.ID, FindingID: rt.FindingID,
		Outcome: outcome, ReasonCode: v.Code, Reason: reason, SensorID: rt.SensorID, ResolvedBy: resolvedBy, TemplateID: rt.TemplateID,
		Decide: func(current vulnerability.FindingStatus) retestdom.SettleDecision {
			next, change := retestdom.NextStatus(current, outcome, autoResolve)
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
		s.finishRun(ctx, rt, v)
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
	detail := fmt.Sprintf("Retest of template %s against %s: %s.", rt.TemplateID, rt.Target, reason)
	if rt.Method == retestdom.MethodTool {
		detail = fmt.Sprintf("Retest of rule %s by its tool against %s: %s.", rt.TemplateID, rt.Target, reason)
	}
	s.announcer.Announce(ctx, Change{
		TenantID: rt.TenantID, FindingID: rt.FindingID, Kind: kind, Source: "retest",
		Detail: detail,
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

// ResolveTarget picks what the template re-run targets: the origin
// (scheme://host[:port]) of the finding's recorded matched-at URL when its
// host is the asset's own host, else the asset's name. A finding can never
// point a retest at a host that is not its asset.
//
// It is the origin, never the matched-at URL itself: a template builds its
// request from the input ({{BaseURL}}/wp-admin/js/theme.js), so re-running it
// with the matched-at URL as the input requests the path twice
// (/wp-admin/js/theme.js/wp-admin/js/theme.js), gets a 404 and reads as
// "did not match" whether or not the issue is fixed. The origin keeps the
// scheme and port the detection used.
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
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return assetName
	}
	return scheme + "://" + strings.ToLower(u.Host)
}

// hostOf returns the host part of an asset name (a bare host, host:port or URL).
func hostOf(name string) string { return asset.HostOf(name) }

// startRun records the retest's run (kind retest) and links it to the
// retest. Best-effort: a retest whose run could not be recorded still runs,
// it is only missing from Runs.
func (s *Service) startRun(ctx context.Context, rt *retestdom.Retest) runRef {
	if s.runs == nil {
		return runRef{}
	}
	runID, stepID, err := s.runs.StartRetestRun(ctx, rt)
	if err != nil {
		s.logger.Warn("failed to record the retest run", "retest_id", rt.ID.String(), "error", err)
		return runRef{}
	}
	rt.RunID = &runID
	if l, ok := s.store.(runLinker); ok {
		if err := l.SetRun(ctx, rt.TenantID, rt.ID, runID); err != nil {
			s.logger.Warn("failed to link the retest to its run", "retest_id", rt.ID.String(), "error", err)
		}
	}
	return runRef{run: runID, step: stepID}
}

// finishRun settles the retest's run with the verdict: a verdict (fixed,
// not reproduced, still vulnerable) completes it; an inconclusive retest
// fails it with the reason.
func (s *Service) finishRun(ctx context.Context, rt *retestdom.Retest, v retestdom.Verdict) {
	if s.runs == nil || rt.RunID == nil {
		return
	}
	succeeded := v.Outcome != retestdom.OutcomeInconclusive
	if err := s.runs.FinishRetestRun(ctx, rt.TenantID, *rt.RunID, succeeded, evidence.RedactText(v.Reason), strings.ToUpper(string(v.Code))); err != nil {
		s.logger.Warn("failed to settle the retest run", "retest_id", rt.ID.String(), "run_id", rt.RunID.String(), "error", err)
	}
}
