package scan

// A scan's per-step overrides of capability standard params (research/426
// P0.1, docs/architecture/scan-stages.md §1.5). They are the scan-level layer
// of the values chain: workflow step config, then the step's depth overlay,
// then these. They work on system and read-only workflows because the
// workflow is never copied or changed.

import (
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// StepParamsCapabilityPrefix starts a key that applies to every step of one
// capability ("*:vuln.templates").
const StepParamsCapabilityPrefix = "*:"

// Bounds of the map (it is stored on the scan and copied into each run).
const (
	MaxStepParamsEntries   = 50
	MaxStepParamsPerEntry  = 20
	maxStepParamsKeyLength = 128
)

// CodeInvalidStepParams refuses a scan's step_params.
const CodeInvalidStepParams = "INVALID_STEP_PARAMS"

// StepParams are a scan's overrides: key is a step key of the scan's
// workflow, or "*:<capability key>" for every step of that capability; the
// value is that step's standard params. A step-key entry wins over a
// capability entry.
type StepParams map[string]map[string]any

// ParamsFor are the params the scan sets on a step: the capability entry
// under the step-key entry. nil when it sets none.
func (p StepParams) ParamsFor(stepKey, capability string) map[string]any {
	if len(p) == 0 {
		return nil
	}
	var out map[string]any
	if capability != "" {
		for k, v := range p[StepParamsCapabilityPrefix+capability] {
			if out == nil {
				out = map[string]any{}
			}
			out[k] = v
		}
	}
	for k, v := range p[stepKey] {
		if out == nil {
			out = map[string]any{}
		}
		out[k] = v
	}
	return out
}

// CapabilityKey is the capability a "*:<capability>" key names ("" for a
// step key).
func CapabilityKey(key string) string {
	if rest, ok := strings.CutPrefix(key, StepParamsCapabilityPrefix); ok {
		return rest
	}
	return ""
}

// StepParamsFromAny reads step params from a run context value (a map decoded
// from JSON); anything else is no params.
func StepParamsFromAny(raw any) StepParams {
	switch m := raw.(type) {
	case StepParams:
		return m
	case map[string]map[string]any:
		return StepParams(m)
	case map[string]any:
		out := StepParams{}
		for k, v := range m {
			if inner, ok := v.(map[string]any); ok {
				out[k] = inner
			}
		}
		return out
	}
	return nil
}

// CheckShape checks the bounds and key shapes (the app layer then checks each
// entry against the workflow and the capability contract).
func (p StepParams) CheckShape() error {
	if len(p) > MaxStepParamsEntries {
		return stepParamsErr("at most %d entries", MaxStepParamsEntries)
	}
	for k, params := range p {
		if strings.TrimSpace(k) == "" || len(k) > maxStepParamsKeyLength {
			return stepParamsErr("a key must be a step key or *:<capability> (at most %d characters)", maxStepParamsKeyLength)
		}
		if k == StepParamsCapabilityPrefix {
			return stepParamsErr("%q needs a capability key", k)
		}
		if len(params) == 0 {
			return stepParamsErr("%q sets no params", k)
		}
		if len(params) > MaxStepParamsPerEntry {
			return stepParamsErr("%q: at most %d params", k, MaxStepParamsPerEntry)
		}
	}
	return nil
}

func stepParamsErr(format string, args ...any) error {
	return shared.NewDomainError(CodeInvalidStepParams,
		"step_params: "+fmt.Sprintf(format, args...), shared.ErrValidation)
}

// SetStepParams replaces the scan's step params (nil or empty clears them).
// Only the shape is checked here; see the app layer for the contract check.
func (s *Scan) SetStepParams(p StepParams) error {
	if err := p.CheckShape(); err != nil {
		return err
	}
	if len(p) == 0 {
		p = nil
	}
	s.StepParams = p
	s.UpdatedAt = time.Now()
	return nil
}

// cloneStepParams is a deep copy (a cloned scan never shares the maps).
func cloneStepParams(p StepParams) StepParams {
	if len(p) == 0 {
		return nil
	}
	out := make(StepParams, len(p))
	for k, v := range p {
		out[k] = cloneParamMap(v)
	}
	return out
}

func cloneParamMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch t := v.(type) {
		case []any:
			out[k] = append([]any(nil), t...)
		case []string:
			out[k] = append([]string(nil), t...)
		default:
			out[k] = v
		}
	}
	return out
}
