package command

// Bug-bounty program rules at delivery (RFC-065 §12). Before a sensor gets
// a job whose targets a program covers:
//
//   - outside the program's testing windows, the job is not handed out; it
//     stays pending and leaves when a window opens;
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
	"time"

	"golang.org/x/mod/semver"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
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

// MinSDKForProgramHTTPRules is the first SDK release whose tool host applies
// http_policy headers and User-Agent (sdk-go #227, #228). A job carrying
// them goes only to a sensor built with it: an older sensor would ignore
// the fields and probe without the program's identification.
const MinSDKForProgramHTTPRules = "v0.19.0"

// FailureProgramRules is the failure code of a job whose programs' rules
// conflict.
const FailureProgramRules = "PROGRAM_RULES_CONFLICT"

// jsonNull is a JSON null value.
const jsonNull = "null"

// ErrSensorCannotHonorProgram: the job carries a program's headers or
// User-Agent and the sensor's SDK predates them; it waits for one that can.
var ErrSensorCannotHonorProgram = shared.NewDomainError("PROGRAM_RULES_UNSUPPORTED",
	"this sensor cannot send the program's identification headers (update the sensor)", shared.ErrValidation)

// programHold decides each command before it is claimed: kept (with the
// rules it carries, if any), withheld (outside a testing window, a sensor
// that cannot honor the rules, or rules that could not be read) or failed
// (conflicting rules).
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
// does not leave now: bp.ErrOutsideWindow, bp.ErrRulesConflict (the command
// is failed), ErrSensorCannotHonorProgram, or ErrScopeRecheckUnavailable
// when the rules could not be read (fail closed).
func (s *Service) programDecide(ctx context.Context, c *commanddom.Command, now time.Time, honors func() bool) (*bp.JobRules, error) {
	targets := payloadTargets(c.Payload)
	if len(targets) == 0 {
		return nil, nil
	}
	r, err := s.programRules.JobRules(ctx, c.TenantID, targets, now)
	switch {
	case errors.Is(err, bp.ErrOutsideWindow):
		return nil, err // stays pending until a window opens
	case errors.Is(err, bp.ErrRulesConflict):
		s.failAtClaim(ctx, c, FailureProgramRules+": "+err.Error(), FailureProgramRules)
		return nil, err
	case err != nil:
		s.logger.Warn("program rules could not be read; withholding the job",
			"command_id", c.ID.String(), "error", err)
		return nil, ErrScopeRecheckUnavailable
	}
	if r != nil && (len(r.Headers) > 0 || r.UserAgent != "") && !honors() {
		s.logger.Warn("the sensor cannot send the program's headers (SDK older than "+MinSDKForProgramHTTPRules+"); withholding the job",
			"command_id", c.ID.String(), "programs", r.Programs)
		return nil, ErrSensorCannotHonorProgram
	}
	return r, nil
}

// programHoldOne decides one command a sensor acknowledges by id: the rules
// it carries (nil: none), or the error the claim answers.
func (s *Service) programHoldOne(ctx context.Context, sensorID shared.ID, cmd *commanddom.Command) (*bp.JobRules, error) {
	if s.programRules == nil {
		return nil, nil
	}
	return s.programDecide(ctx, cmd, s.clock(), s.honorsHTTPRules(ctx, cmd.TenantID, &sensorID))
}

// honorsHTTPRules answers (once, when first asked) whether the sensor's SDK
// applies http_policy headers and User-Agent. Unknown sensor, no lookup or a
// build without a release version: no.
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
		v := sen.Build.SDKVersion
		ok = semver.IsValid(v) && semver.Compare(v, MinSDKForProgramHTTPRules) >= 0
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
// User-Agent (merged with what is there: the program's win), and the rate
// cap in config and scanner_config.
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
		if len(r.Headers) > 0 {
			headers := map[string]any{}
			if h, ok := pol["headers"].(map[string]any); ok {
				headers = h
			}
			for k, v := range r.Headers {
				headers[k] = v
			}
			pol["headers"] = headers
		}
		if r.UserAgent != "" {
			pol["user_agent"] = r.UserAgent
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
