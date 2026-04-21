package module

import (
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ToggleIssue is one blocker or warning raised by module-toggle
// validation. The fields mirror the shape rendered on the Settings →
// Modules page: module ID for programmatic lookup, name for display,
// reason for a tooltip.
type ToggleIssue struct {
	// ModuleID is the dependent module (the one that would be broken
	// by the toggle). For blockers this is the module that stops the
	// toggle; for warnings this is the module that will degrade.
	ModuleID string `json:"module_id"`
	// Name is the human-readable display name from the modules row.
	Name string `json:"name"`
	// Reason is the short sentence from the dependency spec explaining
	// why the edge exists.
	Reason string `json:"reason"`
}

// ToggleError is returned when a module toggle is rejected by the
// dependency gate. It implements error so callers can errors.As() or
// errors.Is() against shared.ErrValidation; the HTTP handler type-
// asserts on ToggleError to render a structured 400 body the UI can
// parse without regex-ing the message.
type ToggleError struct {
	// ModuleID is the one the caller tried to toggle.
	ModuleID string `json:"module_id"`
	// ModuleName is the display name (used in the top-level message).
	ModuleName string `json:"module_name"`
	// Action is "enable" or "disable" — tells the UI which flow the
	// error came from so it can phrase the dialog correctly.
	Action string `json:"action"`
	// Blockers are hard-dependent modules that stop the toggle. Each
	// entry is suitable for a bullet list in the UI.
	Blockers []ToggleIssue `json:"blockers,omitempty"`
	// Required is the inverse — when enabling, these modules must be
	// enabled first.
	Required []ToggleIssue `json:"required,omitempty"`
}

// Error formats a plain-text fallback for log lines / CLI. The HTTP
// handler should NOT rely on this and instead serialise the struct
// itself as JSON.
func (e *ToggleError) Error() string {
	var parts []string
	if len(e.Blockers) > 0 {
		names := make([]string, len(e.Blockers))
		for i, b := range e.Blockers {
			names[i] = b.Name
		}
		parts = append(parts, fmt.Sprintf("cannot disable '%s' while these modules depend on it: [%s]",
			e.ModuleName, strings.Join(names, ", ")))
	}
	if len(e.Required) > 0 {
		names := make([]string, len(e.Required))
		for i, r := range e.Required {
			names[i] = r.Name
		}
		parts = append(parts, fmt.Sprintf("cannot enable '%s' without first enabling: [%s]",
			e.ModuleName, strings.Join(names, ", ")))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("module toggle rejected: %s", e.ModuleID)
	}
	return strings.Join(parts, "; ")
}

// Unwrap lets callers errors.Is(err, shared.ErrValidation) succeed.
func (e *ToggleError) Unwrap() error { return shared.ErrValidation }

// ValidationIssues pairs blockers + warnings so callers that preview
// without applying still get both arrays. Warnings are not fatal —
// the toggle is allowed but the UI should surface them.
type ValidationIssues struct {
	// Blockers — HARD-dependent modules still enabled. Non-empty
	// means the toggle is rejected.
	Blockers []ToggleIssue `json:"blockers,omitempty"`
	// Warnings — SOFT-dependent modules still enabled. Non-empty
	// means the toggle proceeds but the UI should confirm with the
	// user first.
	Warnings []ToggleIssue `json:"warnings,omitempty"`
	// Required — when enabling, modules that must be enabled first.
	Required []ToggleIssue `json:"required,omitempty"`
}
