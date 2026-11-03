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

// jsonNull is a JSON null value.
const jsonNull = "null"

// ErrSensorCannotHonorProgram: the job carries a program's headers or
// User-Agent and the sensor does not report that it sends them
// (sensor.CapabilityHTTPIdentity); it waits for one that does.
var ErrSensorCannotHonorProgram = shared.NewDomainError("PROGRAM_RULES_UNSUPPORTED",
	"this sensor cannot send the program's identification headers (update the sensor)", shared.ErrValidation)

// programHold decides each command before it is claimed: kept (with the
// rules it carries, if any), withheld (a sensor that cannot honor the
// rules, or rules that could not be read) or failed (conflicting rules).
func (s *Service) programHold(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, cmds []*commanddom.Command) ([]*commanddom.Command, map[shared.ID]*bp.JobRules) {
	if s.programRules == nil || len(cmds) == 0 {
		return cmds, nil
	}
	rules := map[shared.ID]*bp.JobRules{}
	out := cmds[:0:0]
	now := s.clock()
	honors := s.honorsHTTPRules(ctx, tenantID, sensorID)
	for _, c := range cmds {
		if !c.TenantID.Equals(tenantID) {
			out = append(out, c) // never decided across tenants; the poll is tenant-scoped
			continue
		}
		r, err := s.programDecide(ctx, c, now, honors)
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
// ErrSensorCannotHonorProgram, or ErrScopeRecheckUnavailable when the rules
// could not be read (fail closed).
func (s *Service) programDecide(ctx context.Context, c *commanddom.Command, now time.Time, honors func() bool) (*bp.JobRules, error) {
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
	if r != nil && (len(r.Headers) > 0 || r.UserAgent != "") && !honors() {
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
	if _, err := eff.Overlay(r.Headers, r.UserAgent, scanident.SourceProgram); err != nil {
		s.failAtClaim(ctx, c, fmt.Sprintf("%s: the program's identification headers with the platform's and the organization's exceed %d",
			FailureProgramRules, scanident.MaxHeaders), FailureProgramRules)
		return err
	}
	return nil
}

// programHoldOne decides one command a sensor acknowledges by id: the rules
// it carries (nil: none), or the error the claim answers.
func (s *Service) programHoldOne(ctx context.Context, sensorID shared.ID, cmd *commanddom.Command) (*bp.JobRules, error) {
	if s.programRules == nil {
		return nil, nil
	}
	return s.programDecide(ctx, cmd, s.clock(), s.honorsHTTPRules(ctx, cmd.TenantID, &sensorID))
}

// honorsHTTPRules answers (once, when first asked) whether the sensor reports
// that its tools send the job's http_policy headers and User-Agent
// (sensor.CapabilityHTTPIdentity). It is decided by what the sensor reports,
// never by its SDK name or version. Unknown sensor or no lookup: no.
func (s *Service) honorsHTTPRules(ctx context.Context, tenantID shared.ID, sensorID *shared.ID) func() bool {
	var done, ok bool
	return func() bool {
		if done {
			return ok
		}
		done = true
		if s.sensors == nil || sensorID == nil {
			return false
		}
		sen, err := s.sensors.GetByTenantAndID(ctx, tenantID, *sensorID)
		if err != nil || sen == nil {
			return false
		}
		ok = slices.Contains(sen.Reported.Capabilities, sensordom.CapabilityHTTPIdentity)
		return ok
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
		payload, err := applyJobRules(c.Payload, r)
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

// applyJobRules writes the rules into a payload: http_policy headers and
// User-Agent (merged with what is there: the program's win, except over an
// enforced platform header or User-Agent, and the program's names become
// locked), and the rate cap in config and scanner_config.
func applyJobRules(payload json.RawMessage, r *bp.JobRules) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if len(payload) == 0 || string(payload) == jsonNull {
		fields = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("command payload: %w", err)
	}
	if len(r.Headers) > 0 || r.UserAgent != "" {
		pol := map[string]any{}
		if raw, ok := fields["http_policy"]; ok && string(raw) != jsonNull {
			if err := json.Unmarshal(raw, &pol); err != nil {
				return nil, fmt.Errorf("http_policy: %w", err)
			}
		}
		eff, err := policyIdentity(pol).Overlay(r.Headers, r.UserAgent, scanident.SourceProgram)
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
		if eff.UserAgentLocked {
			pol["user_agent_locked"] = true
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
	e.UserAgentLocked, _ = pol["user_agent_locked"].(bool)
	return e
}
