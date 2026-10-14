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
	// Bindable: the sensor binds the tool to the job's web scope: a scan
	// job, or a validate or retest job of a tool whose finding check keeps
	// to one (verifyBindsWebScope). Any other job is refused when a path
	// exclusion applies to its target.
	Bindable bool
	// Verify: a validate or retest job (it re-checks a finding).
	Verify bool
}

// verifyBindsWebScope are the tools whose validate and retest jobs the
// sensor keeps to the job's web scope: the nuclei finding check runs in a
// network-confined task sandbox whose forwarder checks every request (sensor
// v0.19.0, sdk-go v0.25.0). Such a job is offered only to a sensor that
// reported net.confined@1, which the sensor first advertises in the same
// release (the job guard requires it).
var verifyBindsWebScope = map[string]bool{"nuclei": true}

// WebJobOf says whether a command is a web job, and which. A scan job is
// one when its tool implements a web stage, or its capability (or a
// required capability word) names one, so a web tool used outside the
// stage catalog (a quick scan, a step without a stage) is still one. A
// retest job is one when its tool is; a validate job when it runs nuclei.
// Whether a tool implements a web stage is the organization's fact
// (stage.Catalog.WebTool, from its sensors' tool contracts): webTool
// answers it.
func WebJobOf(cmd *Command, webTool func(tool string) bool) (WebJob, bool) {
	if cmd == nil || len(cmd.Payload) == 0 {
		return WebJob{}, false
	}
	switch cmd.Type {
	case CommandTypeScan:
		tool := strings.ToLower(strings.TrimSpace(PayloadTool(cmd.Payload)))
		if !webTool(tool) && !webCapabilityPayload(cmd.Payload) {
			return WebJob{}, false
		}
		return WebJob{Tool: tool, Targets: PayloadTargets(cmd.Payload), Bindable: true}, true
	case CommandTypeRetest:
		tool := strings.ToLower(strings.TrimSpace(PayloadTool(cmd.Payload)))
		if !webTool(tool) {
			return WebJob{}, false
		}
		return WebJob{Tool: tool, Targets: PayloadTargets(cmd.Payload), Bindable: verifyBindsWebScope[tool], Verify: true}, true
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
		if !webTool(tool) {
			return WebJob{}, false
		}
		var targets []string
		if a := strings.TrimSpace(p.Target.Address); a != "" {
			targets = []string{a}
		}
		return WebJob{Tool: tool, Targets: targets, Bindable: verifyBindsWebScope[tool], Verify: true}, true
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

// AnyTool is a webTool for WebJobOf that counts every tool as a web tool:
// where the organization's tool facts cannot be read, a job is treated as
// a web job (fail closed).
func AnyTool(string) bool { return true }

// GuardUnwired refuses a web job when no CreateGuard is wired. Without the
// guard the organization's tool facts are not at hand, so every job that
// names a tool counts as a web job (fail closed).
func GuardUnwired(cmd *Command) error {
	if _, ok := WebJobOf(cmd, AnyTool); ok {
		return ErrWebScopeUnwired
	}
	return nil
}
