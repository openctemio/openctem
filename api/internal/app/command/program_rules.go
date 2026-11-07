package command

// Bug-bounty program rules at delivery (RFC-065 §12). Before a sensor gets
// a job whose targets a program covers (outside a program's testing windows
// the scan window hold already kept it back, window_hold.go):
//
//   - when the covering programs' rules conflict (two values for one header,
//     two User-Agents), the job is failed with PROGRAM_RULES_CONFLICT;
//   - otherwise the delivered copy carries the programs' identification
//     headers and User-Agent in http_policy, and its rate_limit is capped at
//     the smallest program rate. The stored command is never changed.
//
// A lookup that cannot decide withholds the job (fail closed).
//
// Required identification is decided at the same point, for every scan,
// retest and validate job, with or without programs: when the platform, the
// organization or a program requires it, a job whose identity has no header
// and no query parameter is failed (IDENTIFICATION_REQUIRED_MISSING), and a
// sensor that does not report http.identity.required@1 never gets it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanident"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ProgramRuleSource answers the rules a job on targets carries
// (*bountyprogram.Service).
type ProgramRuleSource interface {
	JobRules(ctx context.Context, tenantID shared.ID, targets []string, now time.Time) (*bp.JobRules, error)
}

// WithProgramRules makes Poll, Claim and Acknowledge apply the rules of the
// programs a job's targets belong to.
func WithProgramRules(src ProgramRuleSource) Option {
	return func(s *Service) { s.programRules = src }
}

// FailureProgramRules is the failure code of a job whose programs' rules
// conflict.
const FailureProgramRules = "PROGRAM_RULES_CONFLICT"

// FailureProgramForbids is the failure code of an enumeration job on
// targets a program forbids brute force or automated scanning on.
const FailureProgramForbids = "PROGRAM_FORBIDS_ENUMERATION"

// ErrProgramForbidsEnumeration: the job enumerates and a program covering
// its targets forbids it; the job is failed with the reason.
var ErrProgramForbidsEnumeration = shared.NewDomainError(FailureProgramForbids,
	"a bug bounty program covering these targets forbids brute force or automated scanning", shared.ErrValidation)

// jsonNull is a JSON null value.
const jsonNull = "null"

// ErrSensorCannotHonorProgram: the job carries a program's headers or
// User-Agent and the sensor does not report that it sends them
// (sensor.CapabilityHTTPIdentity); it waits for one that does.
var ErrSensorCannotHonorProgram = shared.NewDomainError("PROGRAM_RULES_UNSUPPORTED",
	"this sensor cannot send the program's identification headers (update the sensor)", shared.ErrValidation)

// FailureIdentificationRequiredMissing is the failure code of a job that
// requires identification but carries no identification header and no query
// parameter: it could never run, since the sensor would refuse every task.
const FailureIdentificationRequiredMissing = "IDENTIFICATION_REQUIRED_MISSING"

// ErrIdentificationRequiredMissing: see FailureIdentificationRequiredMissing.
var ErrIdentificationRequiredMissing = shared.NewDomainError(FailureIdentificationRequiredMissing,
	"identification is required but no identification header or query parameter is set; add a header or query parameter "+
		"in the platform's, the organization's or the program's scan identification", shared.ErrValidation)

// ErrSensorCannotRequireIdentification: the job requires identification and
// the sensor does not report sensor.CapabilityHTTPIdentityRequired (it would
// drop the requirement); it waits for one that does.
var ErrSensorCannotRequireIdentification = shared.NewDomainError("IDENTIFICATION_REQUIRED_UNSUPPORTED",
	"this sensor cannot enforce required identification (update the sensor)", shared.ErrValidation)

// identityWired reports whether a layer of scan identification is read at
// delivery (the platform's or the organization's).
func (s *Service) identityWired() bool {
	return s.httpPolicy != nil || s.platformIdentity != nil
}

// programHold decides each command before it is claimed: kept (with the
// rules it carries, if any), withheld (a sensor that cannot honor the
// rules, or rules that could not be read) or failed (conflicting rules).
func (s *Service) programHold(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, cmds []*commanddom.Command) ([]*commanddom.Command, map[shared.ID]*bp.JobRules) {
	if (s.programRules == nil && !s.identityWired()) || len(cmds) == 0 {
		return cmds, nil
	}
	rules := map[shared.ID]*bp.JobRules{}
	out := cmds[:0:0]
	now := s.clock()
	honors := s.sensorReports(ctx, tenantID, sensorID)
	ident := s.identityOnce(ctx, tenantID)
	for _, c := range cmds {
		if !c.TenantID.Equals(tenantID) {
			out = append(out, c) // never decided across tenants; the poll is tenant-scoped
			continue
		}
		r, err := s.programDecide(ctx, c, now, honors, ident)
		if err != nil {
			continue
		}
		if r != nil {
			rules[c.ID] = r
		}
		out = append(out, c)
	}
	return out, rules
}

// programDecide answers the rules one command carries (nil: none), or why it
// does not leave now: bp.ErrRulesConflict (the command is failed),
// ErrSensorCannotHonorProgram, ErrScopeRecheckUnavailable when the rules
// could not be read (fail closed), or a required identification error
// (identityDecide).
func (s *Service) programDecide(ctx context.Context, c *commanddom.Command, now time.Time, reports func(string) bool,
	ident func() (scanident.Effective, error),
) (*bp.JobRules, error) {
	r, err := s.programRulesFor(ctx, c, now, reports)
	if err != nil {
		return nil, err
	}
	if err := s.identityDecide(ctx, c, r, reports, ident); err != nil {
		return nil, err
	}
	return r, nil
}

// programRulesFor answers the program rules of one command (nil: none).
func (s *Service) programRulesFor(ctx context.Context, c *commanddom.Command, now time.Time, reports func(string) bool) (*bp.JobRules, error) {
	if s.programRules == nil {
		return nil, nil
	}
	targets := payloadTargets(c.Payload)
	if len(targets) == 0 {
		return nil, nil
	}
	r, err := s.programRules.JobRules(ctx, c.TenantID, targets, now)
	switch {
	case errors.Is(err, bp.ErrRulesConflict):
		s.failAtClaim(ctx, c, FailureProgramRules+": "+err.Error(), FailureProgramRules)
		return nil, err
	case err != nil:
		s.logger.Warn("program rules could not be read; withholding the job",
			"command_id", c.ID.String(), "error", err)
		return nil, ErrScopeRecheckUnavailable
	}
	if why := r.EnumerationRefusal(); why != "" && commanddom.PayloadEnumerates(c.Payload) {
		// A program forbids brute force or automated scanning: an
		// enumeration job never runs on its targets.
		s.failAtClaim(ctx, c, FailureProgramForbids+": "+why, FailureProgramForbids)
		return nil, ErrProgramForbidsEnumeration
	}
	if r.SetsIdentity() && !reports(sensordom.CapabilityHTTPIdentity) {
		s.logger.Warn("the sensor does not report "+sensordom.CapabilityHTTPIdentity+" (it cannot send the program's headers); withholding the job",
			"command_id", c.ID.String(), "programs", r.Programs)
		return nil, ErrSensorCannotHonorProgram
	}
	if err := s.programFits(ctx, c, r); err != nil {
		return nil, err
	}
	return r, nil
}

// programFits fails a job whose program headers, with the platform's and the
// organization's, would exceed what a sensor accepts (the job could never
// run as the program requires). A layer that cannot be read withholds it.
func (s *Service) programFits(ctx context.Context, c *commanddom.Command, r *bp.JobRules) error {
	if r == nil || len(r.Headers) == 0 || (s.httpPolicy == nil && s.platformIdentity == nil) {
		return nil
	}
	eff, _, err := s.jobIdentity(ctx, c.TenantID)
	if err != nil {
		s.logger.Warn("scan identification could not be read; withholding the job", "command_id", c.ID.String(), "error", err)
		return ErrScopeRecheckUnavailable
	}
	if _, err := eff.Overlay(programLayer(r), scanident.SourceProgram); err != nil {
		s.failAtClaim(ctx, c, fmt.Sprintf("%s: the program's identification headers with the platform's and the organization's exceed %d",
			FailureProgramRules, scanident.MaxHeaders), FailureProgramRules)
		return err
	}
	return nil
}

// programLayer is a program's rules as a scan identification layer.
func programLayer(r *bp.JobRules) scanident.OverlayLayer {
	if r == nil {
		return scanident.OverlayLayer{}
	}
	return scanident.OverlayLayer{Headers: r.Headers, UserAgents: r.UserAgentConfig(), IdentificationRequired: r.IdentificationRequired}
}

// identityDecide applies required identification to a scan, retest or
// validate job (the jobs that carry http_policy): when any layer (platform,
// organization, the job's programs) requires it, a job without an
// identification header or query parameter is failed with
// IDENTIFICATION_REQUIRED_MISSING, and a sensor that does not report
// sensor.CapabilityHTTPIdentityRequired does not get it (withheld). A layer
// that cannot be read withholds the job.
func (s *Service) identityDecide(ctx context.Context, c *commanddom.Command, r *bp.JobRules, reports func(string) bool,
	ident func() (scanident.Effective, error),
) error {
	if !egressBound(c.Type) || (!s.identityWired() && (r == nil || !r.IdentificationRequired)) {
		return nil
	}
	eff, err := ident()
	if err != nil {
		s.logger.Warn("scan identification could not be read; withholding the job", "command_id", c.ID.String(), "error", err)
		return ErrScopeRecheckUnavailable
	}
	if eff, err = eff.Overlay(programLayer(r), scanident.SourceProgram); err != nil {
		return ErrScopeRecheckUnavailable // programFits already failed it
	}
	if !eff.IdentificationRequired {
		return nil
	}
	if !eff.HasIdentification() {
		s.failAtClaim(ctx, c, ErrIdentificationRequiredMissing.Error(), FailureIdentificationRequiredMissing)
		return ErrIdentificationRequiredMissing
	}
	if !reports(sensordom.CapabilityHTTPIdentityRequired) {
		s.logger.Warn("the sensor does not report "+sensordom.CapabilityHTTPIdentityRequired+
			" (it cannot enforce required identification); withholding the job",
			"command_id", c.ID.String(), "required_by", strings.Join(eff.RequiredBy, ","))
		return ErrSensorCannotRequireIdentification
	}
	return nil
}

// programHoldOne decides one command a sensor acknowledges by id: the rules
// it carries (nil: none), or the error the claim answers.
func (s *Service) programHoldOne(ctx context.Context, sensorID shared.ID, cmd *commanddom.Command) (*bp.JobRules, error) {
	if s.programRules == nil && !s.identityWired() {
		return nil, nil
	}
	return s.programDecide(ctx, cmd, s.clock(), s.sensorReports(ctx, cmd.TenantID, &sensorID), s.identityOnce(ctx, cmd.TenantID))
}

// identityOnce reads tenantID's merged scan identification once, when first
// asked (one decision pass reads the layers once, not per job).
func (s *Service) identityOnce(ctx context.Context, tenantID shared.ID) func() (scanident.Effective, error) {
	var done bool
	var eff scanident.Effective
	var err error
	return func() (scanident.Effective, error) {
		if !done {
			done = true
			eff, _, err = s.jobIdentity(ctx, tenantID)
		}
		return eff, err
	}
}

// sensorReports answers whether the sensor reports a capability
// (sensor.CapabilityHTTPIdentity: its tools send the job's http_policy
// headers and User-Agent; sensor.CapabilityHTTPIdentityRequired: it enforces
// required identification). The sensor is read once, when first asked,
// tenant-scoped. It is decided by what the sensor reports, never by its SDK
// name or version. Unknown sensor or no lookup: no.
func (s *Service) sensorReports(ctx context.Context, tenantID shared.ID, sensorID *shared.ID) func(string) bool {
	var done bool
	var caps []string
	return func(capability string) bool {
		if !done {
			done = true
			if s.sensors != nil && sensorID != nil {
				if sen, err := s.sensors.GetByTenantAndID(ctx, tenantID, *sensorID); err == nil && sen != nil {
					caps = sen.Reported.Capabilities
				}
			}
		}
		return slices.Contains(caps, capability)
	}
}

func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// withProgramRules returns the commands to hand out, each carrying its
// programs' rules on a copy of its payload. A payload that cannot be
// rewritten is withheld (a job never leaves without its program's rules).
func (s *Service) withProgramRules(cmds []*commanddom.Command, rules map[shared.ID]*bp.JobRules) []*commanddom.Command {
	if len(rules) == 0 {
		return cmds
	}
	out := cmds[:0:0]
	for _, c := range cmds {
		r, ok := rules[c.ID]
		if !ok {
			out = append(out, c)
			continue
		}
		payload, err := applyJobRules(c.Payload, r, userAgentKey(c))
		if err != nil {
			s.logger.Warn("program rules could not be applied; withholding the job", "command_id", c.ID.String(), "error", err)
			continue
		}
		cp := *c
		cp.Payload = payload
		out = append(out, &cp)
	}
	return out
}

// applyJobRules writes the rules into a payload: http_policy headers,
// User-Agent setting and requirement (merged with what is there: the
// program's win, except over an enforced platform header or User-Agent, and
// the program's names and list become locked; the requirement only adds),
// and the rate cap in config and scanner_config. key is the job's rotation
// key (userAgentKey).
func applyJobRules(payload json.RawMessage, r *bp.JobRules, key string) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if len(payload) == 0 || string(payload) == jsonNull {
		fields = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("command payload: %w", err)
	}
	if r.SetsIdentity() || r.IdentificationRequired {
		pol := map[string]any{}
		if raw, ok := fields["http_policy"]; ok && string(raw) != jsonNull {
			if err := json.Unmarshal(raw, &pol); err != nil {
				return nil, fmt.Errorf("http_policy: %w", err)
			}
		}
		eff, err := policyIdentity(pol).Overlay(programLayer(r), scanident.SourceProgram)
		if err != nil {
			return nil, err
		}
		if m := eff.HeaderMap(); m != nil {
			pol["headers"] = m
		}
		if locked := eff.LockedNames(); len(locked) > 0 {
			pol["locked_headers"] = locked
		}
		if eff.UserAgent != "" {
			pol["user_agent"] = eff.UserAgent
		}
		// The list in force travels only when it rotates; a program's single
		// value removes the organization's list.
		delete(pol, "user_agents")
		delete(pol, "user_agent_key")
		if len(eff.UserAgents) > 1 {
			pol["user_agents"] = eff.UserAgents
			pol["user_agent_key"] = key
		}
		if eff.UserAgentLocked {
			pol["user_agent_locked"] = true
		}
		if eff.IdentificationRequired {
			pol["identification_required"] = true
		}
		b, err := json.Marshal(pol)
		if err != nil {
			return nil, err
		}
		fields["http_policy"] = b
	}
	if r.RateLimit > 0 {
		for _, key := range []string{"config", "scanner_config"} {
			cfg := map[string]any{}
			if raw, ok := fields[key]; ok && string(raw) != jsonNull {
				if err := json.Unmarshal(raw, &cfg); err != nil {
					return nil, fmt.Errorf("%s: %w", key, err)
				}
			} else if key == "scanner_config" {
				continue
			}
			if cur, ok := cfg["rate_limit"].(float64); !ok || cur <= 0 || int(cur) > r.RateLimit {
				cfg["rate_limit"] = r.RateLimit
			}
			b, err := json.Marshal(cfg)
			if err != nil {
				return nil, err
			}
			fields[key] = b
		}
	}
	return json.Marshal(fields)
}

// policyIdentity reads the identity of a delivered http_policy: its headers,
// the names locked by the platform (enforced) and its User-Agent.
func policyIdentity(pol map[string]any) scanident.Effective {
	var e scanident.Effective
	locked := map[string]bool{}
	if ls, ok := pol["locked_headers"].([]any); ok {
		for _, l := range ls {
			if n, ok := l.(string); ok {
				locked[strings.ToLower(n)] = true
			}
		}
	}
	if hs, ok := pol["headers"].(map[string]any); ok {
		names := make([]string, 0, len(hs))
		for n := range hs {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			v, _ := hs[n].(string)
			m := scanident.Marker{Name: n, Value: v, Source: scanident.SourceOrganization}
			if locked[strings.ToLower(n)] {
				m.Source, m.Locked = scanident.SourcePlatformEnforced, true
			}
			e.Headers = append(e.Headers, m)
		}
	}
	e.UserAgent, _ = pol["user_agent"].(string)
	if uas, ok := pol["user_agents"].([]any); ok {
		for _, v := range uas {
			if ua, ok := v.(string); ok {
				e.UserAgents = append(e.UserAgents, ua)
			}
		}
	}
	if len(e.UserAgents) == 0 && e.UserAgent != "" {
		e.UserAgents = []string{e.UserAgent}
	}
	e.UserAgentLocked, _ = pol["user_agent_locked"].(bool)
	if req, _ := pol["identification_required"].(bool); req {
		e.IdentificationRequired = true
	}
	return e
}
