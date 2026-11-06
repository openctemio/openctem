package command

// The isolation level of a job (docs/rfcs/RFC-055-tool-contract-v1.md): a
// tool whose manifest says `isolation: strong` needs a sensor that proved a
// strong isolation backend at start-up. Its job carries the sensor feature
// `isolation.strong@1` in required_features, which the claim SQL matches
// against what the sensor itself reported, so the job waits (placement
// `strong_isolation_missing`) for such a sensor and is never run on the
// process sandbox.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// StrongIsolationTools says whether a tool (lowercase) needs strong
// isolation. nil: none does. No bundled tool needs it yet.
type StrongIsolationTools func(tool string) bool

// JobTool is the tool a scan, retest or validate command runs ("" when its
// payload names none: the sensor then picks the tool and the job is not
// gated here).
func JobTool(cmd *Command) string {
	if cmd == nil || len(cmd.Payload) == 0 {
		return ""
	}
	switch cmd.Type {
	case CommandTypeScan, CommandTypeRetest:
		return strings.ToLower(strings.TrimSpace(PayloadTool(cmd.Payload)))
	case CommandTypeValidate:
		var p struct {
			ExecutorKind string `json:"executor_kind"`
		}
		if json.Unmarshal(cmd.Payload, &p) != nil {
			return ""
		}
		return strings.ToLower(strings.TrimSpace(p.ExecutorKind))
	}
	return ""
}

// RequireFeature adds feature to the command's required_features. It is the
// platform's statement: a value the caller put in the payload stays (the
// list only grows).
func RequireFeature(cmd *Command, feature string) error {
	var fields map[string]any
	// UseNumber keeps the payload's numbers as they were written.
	dec := json.NewDecoder(bytes.NewReader(cmd.Payload))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil || fields == nil {
		return fmt.Errorf("%w: command payload is not an object", shared.ErrValidation)
	}
	var out []string
	if fs, ok := fields[PayloadKeyRequiredFeatures].([]any); ok {
		for _, f := range fs {
			if s, ok := f.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
	}
	for _, f := range out {
		if f == feature {
			return nil
		}
	}
	fields[PayloadKeyRequiredFeatures] = append(out, feature)
	raw, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	cmd.Payload = raw
	return nil
}
