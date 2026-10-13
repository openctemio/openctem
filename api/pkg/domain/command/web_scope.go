package command

// The web scope of a job (docs/rfcs/RFC-056-web-attack-surface.md §5,
// RFC-055 §6.1): a job whose tool requests web paths carries the paths of
// the tenant's path exclusions on its target hosts (`web_scope`), so the
// sensor refuses every request under them. It is attached where every
// command is created (Repository.Create, through a CreateGuard), so no
// dispatch path can leave it out.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// PayloadKeyWebScope is the payload key of a job's web scope (sdk-go
// ScanCommandPayload.WebScope).
const PayloadKeyWebScope = "web_scope"

// CreateGuard checks and completes a command before it is stored: the web
// scope of a web job. An error refuses the command.
type CreateGuard interface {
	GuardCreate(ctx context.Context, cmd *Command) error
}

// ErrWebScopeUnwired refuses a web job when no web scope guard is wired:
// its path exclusions could not be attached (fail closed).
var ErrWebScopeUnwired = errors.New("web scope is not configured; a web job is not dispatched")

// WebJob is what a command's web requests are.
type WebJob struct {
	// Tool is the web tool the job runs (lowercase).
	Tool string
	// Targets are the job's targets, the hosts its web scope is built for.
	Targets []string
	// Bindable: the sensor binds the tool to the job's web scope (a scan
	// job). A validate or retest job is not bound yet, so it is refused
	// when a path exclusion applies to its target.
	Bindable bool
}

// WebJobOf says whether a command is a web job, and which. A scan job is
// one when its tool implements a web stage, or its capability (or a
// required capability word) names one, so a web tool used outside the
// stage catalog (a quick scan, a step without a stage) is still one. A
// retest job is one when its tool is; a validate job when it runs nuclei.
func WebJobOf(cmd *Command) (WebJob, bool) {
	if cmd == nil || len(cmd.Payload) == 0 {
		return WebJob{}, false
	}
	switch cmd.Type {
	case CommandTypeScan:
		tool := strings.ToLower(strings.TrimSpace(PayloadTool(cmd.Payload)))
		if !stage.WebTool(tool) && !webCapabilityPayload(cmd.Payload) {
			return WebJob{}, false
		}
		return WebJob{Tool: tool, Targets: PayloadTargets(cmd.Payload), Bindable: true}, true
	case CommandTypeRetest:
		tool := strings.ToLower(strings.TrimSpace(PayloadTool(cmd.Payload)))
		if !stage.WebTool(tool) {
			return WebJob{}, false
		}
		return WebJob{Tool: tool, Targets: PayloadTargets(cmd.Payload)}, true
	case CommandTypeValidate:
		var p struct {
			ExecutorKind string `json:"executor_kind"`
			Target       struct {
				Address string `json:"address"`
			} `json:"target"`
		}
		if json.Unmarshal(cmd.Payload, &p) != nil {
			return WebJob{}, false
		}
		tool := strings.ToLower(strings.TrimSpace(p.ExecutorKind))
		if !stage.WebTool(tool) {
			return WebJob{}, false
		}
		var targets []string
		if a := strings.TrimSpace(p.Target.Address); a != "" {
			targets = []string{a}
		}
		return WebJob{Tool: tool, Targets: targets}, true
	}
	return WebJob{}, false
}

// webCapabilityPayload reports whether a scan payload's capability or one
// of its required capability words names a web stage.
func webCapabilityPayload(payload json.RawMessage) bool {
	var p struct {
		Capability           string `json:"capability"`
		RequiredCapabilities []any  `json:"required_capabilities"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return false
	}
	if p.Capability != "" && stage.WebCapability(p.Capability) {
		return true
	}
	for _, c := range p.RequiredCapabilities {
		if w, ok := c.(string); ok && stage.WebCapability(w) {
			return true
		}
	}
	return false
}

// GuardUnwired refuses a web job when no CreateGuard is wired.
func GuardUnwired(cmd *Command) error {
	if _, ok := WebJobOf(cmd); ok {
		return ErrWebScopeUnwired
	}
	return nil
}
