package command

// The claim-time scope re-check (docs/architecture/active-probe-gate.md,
// "Re-check at claim"): a probing job (scan, validate, retest, connector
// scan) can wait in the queue while its scope
// changes (an exclusion added, a scope entry removed or its tier lowered, an
// asset's ownership rejected, a scan zone deleted or shrunk, the actor's act
// scope revoked). Before a sensor gets such a command, its targets pass the
// dispatch gate again with the inputs recorded when it was created
// (commanddom.DispatchGate). Targets the gate now refuses are taken out of
// the job; a job left with none is failed with SCOPE_CHANGED, and what
// waits on it (step, validation run, retest) hears about it. A gate that cannot decide withholds the job (fail closed):
// it stays pending for a later claim, and the command TTL is the backstop.
//
// One enforcement point: Poll, Claim and Acknowledge (claim by id) all call
// recheckScope; protocol v2 and v3 reach the command service only through
// them.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// FailureScopeChanged is the step failure code of a job whose every target
// the claim-time re-check refused (scanrun failure class "scope").
const FailureScopeChanged = scanrundom.FailureScopeChanged

// ScopeGate is the dispatch gate (scan.Service.ResolveDispatchTargets).
type ScopeGate interface {
	ResolveDispatchTargets(ctx context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error)
}

// FailureObserver is told about a command the re-check failed, to settle
// what waits on it as a sensor's failure would: the scan step, the
// validation run, the retest (the command handler, OnCommandFailed).
type FailureObserver interface {
	OnCommandFailed(ctx context.Context, cmd *commanddom.Command, message, code string)
}

// ScopeRecheckStore writes the re-check's outcome (the command repository).
// Both writes apply only while the command is still pending as read.
type ScopeRecheckStore interface {
	NarrowPendingPayload(ctx context.Context, cmd *commanddom.Command, payload json.RawMessage) (bool, error)
	FailPending(ctx context.Context, cmd *commanddom.Command, message string) (bool, error)
}

// WithScopeRecheck makes Poll, Claim and Acknowledge re-check the targets of
// every command that records a dispatch gate (and every scan command) with
// g before a sensor gets it. Without it no command
// is re-checked.
func WithScopeRecheck(g ScopeGate) Option {
	return func(s *Service) { s.scopeGate = g }
}

// SetFailureObserver wires who hears about a command the re-check failed
// (the command handler is built after the command service).
func (s *Service) SetFailureObserver(o FailureObserver) { s.failures = o }

// maxRecheckTargets bounds one gate call (the gate's per-run limit); a
// larger batch of commands is split.
const maxRecheckTargets = 10000

// ErrScopeChanged: every target of the command was refused when it was
// claimed. It reads as "claimed" (command-claimed), so the sensor drops it;
// the command is failed with SCOPE_CHANGED.
var ErrScopeChanged = fmt.Errorf("%w (%w): the scope of this job changed and none of its targets may be scanned",
	ErrCommandClaimed, shared.ErrConflict)

// ErrScopeRecheckUnavailable: the re-check could not decide. It reads as
// "claimed"; the command stays pending for a later claim.
var ErrScopeRecheckUnavailable = fmt.Errorf("%w (%w): the job's scope could not be checked; try later",
	ErrCommandClaimed, shared.ErrConflict)

// recheckOutcome is the re-check's decision for one command.
type recheckOutcome int

const (
	recheckKeep     recheckOutcome = iota // hand out (maybe narrowed)
	recheckFailed                         // failed with SCOPE_CHANGED
	recheckWithheld                       // not decided, or changed meanwhile: stays pending
)

// recheckJob is one command under re-check.
type recheckJob struct {
	cmd     *commanddom.Command
	targets []string
	gate    commanddom.DispatchGate
}

// recheckScope re-checks cmds for sensorID and returns those to hand out, in
// order: unchanged, or with a narrowed payload. Commands it failed or
// withheld are left out.
func (s *Service) recheckScope(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, cmds []*commanddom.Command) []*commanddom.Command {
	if s.scopeGate == nil || len(cmds) == 0 {
		return cmds
	}
	out, _ := s.recheck(ctx, tenantID, sensorID, cmds)
	return out
}

// recheckOne re-checks one command a sensor claims by id. It returns the
// command to hand out (maybe narrowed) or ErrScopeChanged /
// ErrScopeRecheckUnavailable.
func (s *Service) recheckOne(ctx context.Context, sensorID shared.ID, cmd *commanddom.Command) (*commanddom.Command, error) {
	if s.scopeGate == nil {
		return cmd, nil
	}
	out, outcomes := s.recheck(ctx, cmd.TenantID, &sensorID, []*commanddom.Command{cmd})
	if len(out) == 1 {
		return out[0], nil
	}
	if outcomes[cmd.ID] == recheckFailed {
		return nil, ErrScopeChanged
	}
	return nil, ErrScopeRecheckUnavailable
}

func (s *Service) recheck(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, cmds []*commanddom.Command) ([]*commanddom.Command, map[shared.ID]recheckOutcome) {
	outcomes := make(map[shared.ID]recheckOutcome, len(cmds))
	replaced := map[shared.ID]*commanddom.Command{}
	jobs := make([]recheckJob, 0, len(cmds))
	for _, c := range cmds {
		if !c.TenantID.Equals(tenantID) {
			// Never another tenant's command (the poll is tenant-scoped;
			// this keeps the re-check from ever acting across tenants).
			outcomes[c.ID] = recheckWithheld
			continue
		}
		gate, ok := recheckGateOf(c)
		if !ok {
			continue
		}
		targets := payloadTargets(c.Payload)
		if len(targets) == 0 {
			continue
		}
		jobs = append(jobs, recheckJob{cmd: c, targets: targets, gate: gate})
	}
	for _, batch := range recheckBatches(jobs) {
		s.recheckBatch(ctx, tenantID, sensorID, batch, outcomes, replaced)
	}
	out := cmds[:0:0]
	for _, c := range cmds {
		if outcomes[c.ID] != recheckKeep {
			continue
		}
		if r, ok := replaced[c.ID]; ok {
			c = r
		}
		out = append(out, c)
	}
	return out, outcomes
}

// recheckGateOf is the gate a command is re-checked with: its record, or
// the baseline for a scan command created without one. Other commands
// without a record are not re-checked.
func recheckGateOf(c *commanddom.Command) (commanddom.DispatchGate, bool) {
	if c.DispatchGate != nil {
		return *c.DispatchGate, true
	}
	if c.Type == commanddom.CommandTypeScan {
		return commanddom.BaselineDispatchGate, true
	}
	return commanddom.DispatchGate{}, false
}

// recheckBatches groups the jobs that share a gate record, so the gate runs
// once per group (a step's chunks share one), split at maxRecheckTargets.
func recheckBatches(jobs []recheckJob) [][]recheckJob {
	index := map[commanddom.DispatchGate]int{}
	var groups [][]recheckJob
	sizes := []int{}
	for _, j := range jobs {
		i, ok := index[j.gate]
		if !ok || sizes[i]+len(j.targets) > maxRecheckTargets {
			groups = append(groups, nil)
			sizes = append(sizes, 0)
			i = len(groups) - 1
			index[j.gate] = i
		}
		groups[i] = append(groups[i], j)
		sizes[i] += len(j.targets)
	}
	return groups
}

// recheckBatch runs the gate once for jobs (same record) and settles each.
func (s *Service) recheckBatch(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, jobs []recheckJob,
	outcomes map[shared.ID]recheckOutcome, replaced map[shared.ID]*commanddom.Command,
) {
	g := jobs[0].gate
	tier := scopedom.Tier(g.Tier)
	in := scanapp.DispatchTargetsInput{
		TenantID: tenantID, SensorID: sensorID, Path: "claim_recheck",
		AllowNonNetworkTargets: !g.Validated, SkipZoneRouting: g.NoZoneRouting,
		Tier: &tier, PassiveOnly: g.Passive, ActScope: g.ActScope,
	}
	if g.ActScope && g.Actor != "" {
		actor, err := shared.IDFromString(g.Actor)
		if err != nil || actor.IsZero() {
			s.withholdAll(jobs, outcomes, "the recorded actor is not a user id", nil)
			return
		}
		in.FallbackUser = &actor
	}
	for _, j := range jobs {
		in.Targets = append(in.Targets, j.targets...)
	}
	d, err := s.scopeGate.ResolveDispatchTargets(ctx, in)
	if err != nil || d == nil {
		s.withholdAll(jobs, outcomes, "the dispatch gate could not decide", err)
		return
	}
	verdict := newTargetVerdict(d)
	for _, j := range jobs {
		s.settle(ctx, j, verdict, outcomes, replaced)
	}
}

func (s *Service) withholdAll(jobs []recheckJob, outcomes map[shared.ID]recheckOutcome, why string, err error) {
	for _, j := range jobs {
		outcomes[j.cmd.ID] = recheckWithheld
	}
	s.logger.Warn("SECURITY: claim-time scope re-check failed; withholding the jobs",
		"tenant_id", jobs[0].cmd.TenantID.String(), "commands", len(jobs), "reason", why, "error", err)
}

// targetVerdict is the gate's answer by lower-cased target.
type targetVerdict struct {
	allowed map[string]*shared.ID // allowed target -> its zone (nil: unzoned)
	refused map[string]string     // refused target -> refusal code
}

func newTargetVerdict(d *scanapp.DispatchTargets) targetVerdict {
	v := targetVerdict{allowed: make(map[string]*shared.ID, len(d.Allowed)), refused: map[string]string{}}
	for _, t := range d.Allowed {
		var zone *shared.ID
		if z := d.Zone(t); z != nil {
			id := z.ID
			zone = &id
		}
		v.allowed[strings.ToLower(t)] = zone
	}
	for _, t := range d.Excluded {
		v.refused[strings.ToLower(t)] = scopedom.RefusalExcluded
	}
	for _, r := range d.Refused {
		v.refused[strings.ToLower(r.Target)] = r.Code
	}
	return v
}

// codeZoneChanged: the target now routes to another scan zone than the one
// the job was routed to (or into or out of every zone).
const codeZoneChanged = "zone_changed"

// split divides a job's targets into the ones it may still scan and the
// refused ones (target -> code).
func (v targetVerdict) split(j recheckJob) ([]string, map[string]string) {
	kept := make([]string, 0, len(j.targets))
	refused := map[string]string{}
	for _, t := range j.targets {
		key := strings.ToLower(strings.TrimSpace(t))
		zone, ok := v.allowed[key]
		switch {
		case !ok:
			code := v.refused[key]
			if code == "" {
				code = scopedom.RefusalInvalidTarget
			}
			refused[t] = code
		case !sameZone(j.cmd.ScanZoneID, zone):
			refused[t] = codeZoneChanged
		default:
			kept = append(kept, t)
		}
	}
	return kept, refused
}

func sameZone(a, b *shared.ID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equals(*b)
}

// settle applies the verdict to one job: hand it out as is, narrowed, or
// fail it.
func (s *Service) settle(ctx context.Context, j recheckJob, v targetVerdict,
	outcomes map[shared.ID]recheckOutcome, replaced map[shared.ID]*commanddom.Command,
) {
	kept, refused := v.split(j)
	if len(refused) == 0 {
		outcomes[j.cmd.ID] = recheckKeep
		return
	}
	store, ok := s.repo.(ScopeRecheckStore)
	if !ok {
		outcomes[j.cmd.ID] = recheckWithheld
		s.logger.Error("command repository cannot record a scope re-check; withholding the job",
			"command_id", j.cmd.ID.String())
		return
	}
	log := s.logger.With("tenant_id", j.cmd.TenantID.String(), "command_id", j.cmd.ID.String())
	if len(kept) == 0 {
		msg := scopeChangedMessage(refused)
		won, err := store.FailPending(ctx, j.cmd, msg)
		if err != nil || !won {
			outcomes[j.cmd.ID] = recheckWithheld
			if err != nil {
				log.Warn("cannot fail a job whose scope changed; withholding it", "error", err)
			}
			return
		}
		outcomes[j.cmd.ID] = recheckFailed
		log.Warn("SECURITY: scan job failed at claim: its scope changed and no target may be scanned",
			"refused", len(refused), "codes", refusalCodes(refused))
		s.reportScopeChanged(ctx, j.cmd, msg)
		return
	}
	payload, err := narrowPayload(j.cmd.Payload, kept)
	if err != nil {
		outcomes[j.cmd.ID] = recheckWithheld
		log.Warn("cannot narrow a job whose scope changed; withholding it", "error", err)
		return
	}
	won, err := store.NarrowPendingPayload(ctx, j.cmd, payload)
	if err != nil || !won {
		// Changed by another claim meanwhile: the next poll reads it anew.
		outcomes[j.cmd.ID] = recheckWithheld
		if err != nil {
			log.Warn("cannot narrow a job whose scope changed; withholding it", "error", err)
		}
		return
	}
	cp := *j.cmd
	cp.Payload = payload
	replaced[j.cmd.ID] = &cp
	outcomes[j.cmd.ID] = recheckKeep
	log.Warn("SECURITY: targets left out of a scan job at claim: its scope changed",
		"refused", len(refused), "kept", len(kept), "codes", refusalCodes(refused))
}

// reportScopeChanged hands a command the re-check failed to the failure
// observer, which settles its step, validation run or retest.
func (s *Service) reportScopeChanged(ctx context.Context, cmd *commanddom.Command, msg string) {
	if s.failures == nil {
		return
	}
	failed := *cmd
	failed.Fail(msg)
	s.failures.OnCommandFailed(context.WithoutCancel(ctx), &failed, msg, FailureScopeChanged)
}

// maxListedRefused bounds the targets a SCOPE_CHANGED message names.
const maxListedRefused = 10

// scopeChangedMessage is the error recorded on a failed command and its
// step: the refused targets with their refusal code.
func scopeChangedMessage(refused map[string]string) string {
	targets := make([]string, 0, len(refused))
	for t := range refused {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	parts := make([]string, 0, min(len(targets), maxListedRefused))
	for i, t := range targets {
		if i == maxListedRefused {
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", t, refused[t]))
	}
	msg := FailureScopeChanged + ": the scope changed while the job was queued and none of its targets may be scanned now: " +
		strings.Join(parts, "; ")
	if n := len(targets) - len(parts); n > 0 {
		msg += fmt.Sprintf("; and %d more", n)
	}
	return truncateUTF8(msg, MaxFailErrorMessageBytes)
}

// refusalCodes counts the refusal codes (for the log).
func refusalCodes(refused map[string]string) map[string]int {
	out := map[string]int{}
	for _, c := range refused {
		out[c]++
	}
	return out
}

// payloadTargets are the targets a command payload names: "targets" and
// "target", the keys sensors read, trimmed and de-duplicated.
func payloadTargets(payload json.RawMessage) []string {
	if len(payload) == 0 {
		return nil
	}
	var p struct {
		Targets []any `json:"targets"`
		Target  any   `json:"target"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(v any) {
		if obj, ok := v.(map[string]any); ok {
			// A validate command names its probe target as an object.
			v = obj["address"]
		}
		str, ok := v.(string)
		if !ok {
			return
		}
		str = strings.TrimSpace(str)
		if str != "" && !seen[strings.ToLower(str)] {
			seen[strings.ToLower(str)] = true
			out = append(out, str)
		}
	}
	for _, t := range p.Targets {
		add(t)
	}
	add(p.Target)
	return out
}

// narrowPayload keeps only the kept targets in a payload: in "targets" and
// "target" at the top level and in "context" (the run context a step
// carries). "target" stays only when it is kept, or becomes the one target
// left. Everything else is unchanged (numbers keep their exact text).
func narrowPayload(payload json.RawMessage, kept []string) (json.RawMessage, error) {
	keep := make(map[string]bool, len(kept))
	for _, t := range kept {
		keep[strings.ToLower(strings.TrimSpace(t))] = true
	}
	var fields map[string]any
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil || fields == nil {
		return nil, fmt.Errorf("decode command payload: %w", err)
	}
	narrowTargets(fields, keep)
	if ctxFields, ok := fields["context"].(map[string]any); ok {
		narrowTargets(ctxFields, keep)
	}
	return json.Marshal(fields)
}

func narrowTargets(fields map[string]any, keep map[string]bool) {
	kept := func(v any) bool {
		str, ok := v.(string)
		return ok && keep[strings.ToLower(strings.TrimSpace(str))]
	}
	var left []any
	if list, ok := fields["targets"].([]any); ok {
		left = make([]any, 0, len(list))
		for _, v := range list {
			if kept(v) {
				left = append(left, v)
			}
		}
		fields["targets"] = left
	}
	if t, ok := fields["target"]; ok && !kept(t) {
		if len(left) == 1 {
			fields["target"] = left[0]
		} else {
			delete(fields, "target")
		}
	}
}
