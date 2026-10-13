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

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// WebScopeBuilder builds a web job's scope (*Service).
type WebScopeBuilder interface {
	BuildWebScope(ctx context.Context, tenantID shared.ID, targets []string) (*WebScope, error)
}

// ConfinedSensors says whether the organization has an active sensor that
// reported net.confined@1 (the sensor repository).
type ConfinedSensors interface {
	HasConfinedSensor(ctx context.Context, tenantID shared.ID) (bool, error)
}

// WebJobGuard attaches the web scope to a web job, or refuses the job.
type WebJobGuard struct {
	scope    WebScopeBuilder
	confined ConfinedSensors
}

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
// closed), as does a scope on a job the sensor cannot bind to one
// (validate, retest).
func (g *WebJobGuard) GuardCreate(ctx context.Context, cmd *commanddom.Command) error {
	job, ok := commanddom.WebJobOf(cmd)
	if !ok {
		return nil
	}
	if g == nil || g.scope == nil {
		return commanddom.GuardUnwired(cmd)
	}
	ws, err := g.scope.BuildWebScope(ctx, cmd.TenantID, job.Targets)
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
			"a path exclusion applies to the target of this %s job, and a %s job cannot keep to a web scope yet; it is not dispatched",
			cmd.Type, cmd.Type), shared.ErrValidation)
	}
	fields[commanddom.PayloadKeyWebScope] = ws
	if webScopeNeedsConfinement[job.Tool] {
		fields[commanddom.PayloadKeyRequiredFeatures] = withFeature(fields[commanddom.PayloadKeyRequiredFeatures], sensordom.CapabilityNetConfined)
		if err := g.requireConfinedSensor(ctx, cmd.TenantID); err != nil {
			return err
		}
	}
	return setPayload(cmd, fields)
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
