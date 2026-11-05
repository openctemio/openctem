package scan

import (
	"fmt"
	"sort"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CodeTriggerContextRefused refuses a trigger request whose context sets a
// key a caller may not set.
const CodeTriggerContextRefused = "TRIGGER_CONTEXT_REFUSED"

// maxTriggerReasonLen bounds the one free-text key a caller may send.
const maxTriggerReasonLen = 500

// callerTriggerContextKeys are the run-context keys a caller of
// POST /scans/{id}/trigger may set. Every other key of the run context is
// written by the platform (targets, zones, routing, intensity, rule sources,
// skipped or uncovered targets, the acting user) and is read back when the
// run's commands are built and its outcome is decided, so a caller-set value
// could change what a sensor job carries or force a run partial. The list is
// an allow-list: a key added to the run context later stays platform-owned
// unless it is added here.
var callerTriggerContextKeys = map[string]struct{}{
	"reason": {},
}

// ValidateCallerTriggerContext checks the context a caller sent with a
// trigger request: only allow-listed keys, each with a value of its type.
// The error is a validation error naming the refused keys (never values).
func ValidateCallerTriggerContext(c map[string]any) error {
	var refused []string
	for k := range c {
		if _, ok := callerTriggerContextKeys[k]; !ok {
			refused = append(refused, k)
		}
	}
	if len(refused) > 0 {
		sort.Strings(refused)
		if len(refused) > 5 {
			refused = append(refused[:5], "...")
		}
		return shared.NewDomainError(CodeTriggerContextRefused,
			fmt.Sprintf("The trigger context may only set: reason. Refused keys: %v", refused),
			shared.ErrValidation)
	}
	if v, ok := c["reason"]; ok {
		s, isString := v.(string)
		if !isString || utf8.RuneCountInString(s) > maxTriggerReasonLen {
			return shared.NewDomainError(CodeTriggerContextRefused,
				fmt.Sprintf("The trigger context key reason must be text of at most %d characters.", maxTriggerReasonLen),
				shared.ErrValidation)
		}
	}
	return nil
}
