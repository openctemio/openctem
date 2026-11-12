package scope

// The web scope of every web job (docs/rfcs/RFC-056-web-attack-surface.md
// §5, RFC-055 §6.1). WebJobGuard is the command repository's create guard
// (command.CreateGuard): every command passes it before it is stored, so a
// quick scan, a workflow step with or without a stage, a scheduled or
// retried scan, a zone batch, an automation's scan, a command created
// through the API, a validation or a retest cannot skip it.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/server/pkg/domain/scanrun"
	sensordom "github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// WebScopeBuilder builds a web job's scope (*Service).
type WebScopeBuilder interface {
	BuildWebScope(ctx context.Context, tenantID shared.ID, targets []string) (*WebScope, error)
	BuildDiscoveryWebScope(ctx context.Context, tenantID shared.ID, targets []string, maxRequestsPerHost int) (*WebScope, error)
}

// DefaultDiscoveryRequestsPerHost is a path discovery job's per-host cap
// when its config names none (the derived list's per-origin budget).
const DefaultDiscoveryRequestsPerHost = 300

// ConfinedSensors says whether the organization has an active sensor that
// reported net.confined@1 (the sensor repository).
type ConfinedSensors interface {
	HasConfinedSensor(ctx context.Context, tenantID shared.ID) (bool, error)
}

// PathDispatchGate is the gate every path discovery job passes before it is
// stored (coverage.PathDiscoveryPolicy): the organization's switch and the
// origin refusals (CheckPathDispatch, which records nothing), and, last, the
// claim in the path discovery ledger (ClaimPathDispatch: all or nothing; it
// returns the request cap the job carries, at most requested, 0 requested
// meaning the platform's per-origin budget). ReleasePathDispatch gives the
// claim back.
type PathDispatchGate interface {
	CheckPathDispatch(ctx context.Context, tenantID shared.ID, targets []string) error
	ClaimPathDispatch(ctx context.Context, tenantID, commandID shared.ID, runID *shared.ID, targets []string, requested int) (int, error)
	ReleasePathDispatch(ctx context.Context, tenantID, commandID shared.ID, origins []string) error
}

// WebJobGuard attaches the web scope to a web job, or refuses the job.
type WebJobGuard struct {
	scope     WebScopeBuilder
	confined  ConfinedSensors
	discovery PathDispatchGate
}

// SetDiscoveryGate wires the dispatch gate of path discovery jobs. Without
// it a path discovery job is refused (fail closed).
func (g *WebJobGuard) SetDiscoveryGate(d PathDispatchGate) { g.discovery = d }

// NewWebJobGuard returns the guard. confined may be nil: a web-scoped job
// that needs a confined sensor then waits for one instead of being refused
// up front.
func NewWebJobGuard(scope WebScopeBuilder, confined ConfinedSensors) *WebJobGuard {
	return &WebJobGuard{scope: scope, confined: confined}
}

// webScopeNeedsConfinement are the tools that keep to a web scope only
// through the task forwarder of a network-confined sandbox: their requests
// cannot be bound by flags (nuclei templates request arbitrary paths), so
// a web-scoped job of theirs requires net.confined@1 and waits for a
// sensor that reported it.
var webScopeNeedsConfinement = map[string]bool{"nuclei": true}

// GuardCreate gives a web job the web scope of its tenant's path
// exclusions on its targets. The platform is the only author of
// `web_scope`: a value the caller put in the payload is replaced. The
// lookup is the command's own tenant's, so one organization's exclusions
// never reach another's job. A failed lookup refuses the job (fail
// closed), as does a scope on a job the sensor cannot bind to one (a
// validate or retest job of a tool whose finding check does not keep to a
// web scope).
//
// A path discovery job requires net.confined@1 too: its candidate paths come
// from a list, and only the confined forwarder holds the tool to the scope and
// to the request cap whatever it does.
//
// A validate or retest job that keeps to its scope (nuclei) requires
// net.confined@1, like a nuclei scan: the finding check keeps to the scope
// only in a confined sandbox, and a sensor that reports the feature (v0.19.0
// or later) is one that honors web_scope on these jobs; an older sensor
// would drop the scope, so it is never offered the job. Without such a
// sensor in the organization the job is refused (NO_CONFINED_SENSOR).
func (g *WebJobGuard) GuardCreate(ctx context.Context, cmd *commanddom.Command) error {
	job, ok := commanddom.WebJobOf(cmd)
	if !ok {
		return nil
	}
	if g == nil || g.scope == nil {
		return commanddom.GuardUnwired(cmd)
	}
	var ws *WebScope
	var err error
	requested := 0
	if job.Discovery {
		// Path discovery: the same gate for every caller. The switch and
		// the origin refusals come first, then the strict scope; the ledger
		// is claimed last (below), once nothing else can refuse the job.
		if g.discovery == nil {
			return commanddom.GuardUnwired(cmd)
		}
		// A discovery job with no origin to probe is refused: nothing
		// would be claimed or capped for it, yet the sensor would be handed
		// the strict scope's request cap with no target to bound it.
		if len(job.Targets) == 0 {
			return shared.NewDomainError("PATH_DISCOVERY_REFUSED",
				"A path discovery job needs at least one origin to probe.", shared.ErrValidation)
		}
		if gerr := g.discovery.CheckPathDispatch(ctx, cmd.TenantID, job.Targets); gerr != nil {
			return gerr
		}
		requested = commanddom.PayloadDiscoveryMaxRequests(cmd.Payload)
		ws, err = g.scope.BuildDiscoveryWebScope(ctx, cmd.TenantID, job.Targets, discoveryLimit(requested))
	} else {
		ws, err = g.scope.BuildWebScope(ctx, cmd.TenantID, job.Targets)
	}
	if err != nil {
		return fmt.Errorf("web scope: %w", err)
	}
	// UseNumber keeps the payload's numbers as they were written.
	var fields map[string]any
	dec := json.NewDecoder(bytes.NewReader(cmd.Payload))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil || fields == nil {
		return fmt.Errorf("%w: web job payload is not an object", shared.ErrValidation)
	}
	_, had := fields[commanddom.PayloadKeyWebScope]
	delete(fields, commanddom.PayloadKeyWebScope)
	if ws == nil {
		if !had {
			return nil
		}
		return setPayload(cmd, fields)
	}
	if !job.Bindable {
		return shared.NewDomainError(scanrundom.FailureWebScopeUnsupported, fmt.Sprintf(
			"a path exclusion applies to the target of this %s job, and a %s job of %s cannot keep to a web scope; it is not dispatched",
			cmd.Type, cmd.Type, job.Tool), shared.ErrValidation)
	}
	fields[commanddom.PayloadKeyWebScope] = ws
	if webScopeNeedsConfinement[job.Tool] || job.Verify || job.Discovery {
		fields[commanddom.PayloadKeyRequiredFeatures] = withFeature(fields[commanddom.PayloadKeyRequiredFeatures], sensordom.CapabilityNetConfined)
		if err := g.requireConfinedSensor(ctx, cmd.TenantID); err != nil {
			return err
		}
	}
	if job.Discovery {
		// The claim comes last: the job the ledger charges for is one that
		// is stored. Anything after it that fails gives the claim back.
		var runID *shared.ID
		if id, perr := shared.IDFromString(commanddom.PayloadScanRunID(cmd.Payload)); perr == nil {
			runID = &id
		}
		limit, gerr := g.discovery.ClaimPathDispatch(ctx, cmd.TenantID, cmd.ID, runID, job.Targets, requested)
		if gerr != nil {
			return gerr
		}
		ws.MaxRequestsPerHost = discoveryLimit(limit)
		if err := setPayload(cmd, fields); err != nil {
			g.ReleaseCreate(ctx, cmd)
			return err
		}
		return nil
	}
	return setPayload(cmd, fields)
}

// ReleaseCreate gives back the ledger claim GuardCreate made for the command
// when the repository could not store it (command.CreateReleaser). It is
// idempotent and releases on a context that survives the caller's.
func (g *WebJobGuard) ReleaseCreate(ctx context.Context, cmd *commanddom.Command) {
	if g == nil || g.discovery == nil || cmd == nil {
		return
	}
	if job, ok := commanddom.WebJobOf(cmd); !ok || !job.Discovery {
		return
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = g.discovery.ReleasePathDispatch(rctx, cmd.TenantID, cmd.ID, nil)
}

// discoveryLimit is the per-host cap of a path discovery job: the default
// when none is asked for, within the platform's bounds.
func discoveryLimit(n int) int {
	if n <= 0 {
		n = DefaultDiscoveryRequestsPerHost
	}
	return min(max(n, MinDiscoveryRequestsPerHost), MaxDiscoveryRequestsPerHost)
}

// requireConfinedSensor refuses a job that needs a confined sensor when the
// organization has none (NO_CONFINED_SENSOR): it could never be taken.
func (g *WebJobGuard) requireConfinedSensor(ctx context.Context, tenantID shared.ID) error {
	if g.confined == nil {
		return nil
	}
	ok, err := g.confined.HasConfinedSensor(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("confined sensor lookup: %w", err)
	}
	if !ok {
		return shared.NewDomainError(scanrundom.FailureNoConfinedSensor,
			"this job has a web scope, and its tool keeps to one only on a sensor whose tool network is confined; "+
				"no sensor of the organization reports that (run the sensor with its seccomp profile)", shared.ErrValidation)
	}
	return nil
}

// withFeature adds feature to a payload's required features list.
func withFeature(v any, feature string) []string {
	var out []string
	switch fs := v.(type) {
	case []string:
		out = append(out, fs...)
	case []any:
		for _, f := range fs {
			if s, ok := f.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
	}
	if !slices.Contains(out, feature) {
		out = append(out, feature)
	}
	return out
}

func setPayload(cmd *commanddom.Command, fields map[string]any) error {
	raw, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("marshal web job payload: %w", err)
	}
	cmd.Payload = raw
	return nil
}
