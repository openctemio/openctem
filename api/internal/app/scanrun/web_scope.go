package scanrun

// The web scope of a web step's job (docs/rfcs/RFC-056-web-attack-surface.md
// §5, RFC-055 §6.1): a crawl, a template scan or a web application scan on
// a host with a path exclusion in effect carries `web_scope.deny_paths`, so
// the sensor's SDK refuses every request under those paths, redirects
// included. The platform also drops excluded URL targets at dispatch and
// marks excluded endpoints at ingest; this is the layer that binds the tool.

import (
	"context"
	"fmt"
	"slices"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// WebScopeBuilder builds a web job's scope (*scope.Service).
type WebScopeBuilder interface {
	BuildWebScope(ctx context.Context, tenantID shared.ID, targets []string) (*scopeapp.WebScope, error)
}

// WithWebScope wires the web scope of web steps. Without it a web step is
// refused when the tenant could have path exclusions (fail closed).
func WithWebScope(b WebScopeBuilder) Option {
	return func(s *Service) { s.webScope = b }
}

// webStages are the stages whose tools request web paths.
var webStages = map[stage.Key]bool{stage.CrawlWeb: true, stage.VulnTemplates: true, stage.DASTWeb: true}

// applyWebScope adds `web_scope` to a web step's payload when a path
// exclusion applies to its targets. A lookup error refuses the step.
func (s *Service) applyWebScope(ctx context.Context, tenantID shared.ID, key stage.Key, payload map[string]any) error {
	if !webStages[key] {
		return nil
	}
	if s.webScope == nil {
		return fmt.Errorf("web scope is not configured; a web step is not dispatched")
	}
	ws, err := s.webScope.BuildWebScope(ctx, tenantID, payloadTargets(payload))
	if err != nil {
		return fmt.Errorf("web scope: %w", err)
	}
	if ws != nil {
		payload["web_scope"] = ws
		if tool, _ := payload["scanner"].(string); webScopeNeedsConfinement[tool] {
			payload[command.PayloadKeyRequiredFeatures] = []string{sensordom.CapabilityNetConfined}
		}
	}
	return nil
}

// webScopeNeedsConfinement are the tools that keep to a web scope only
// through the task forwarder of a network-confined sandbox: their requests
// cannot be bound by flags (nuclei templates request arbitrary paths), so
// a web-scoped job of theirs requires net.confined@1 and waits for a
// sensor that reported it.
var webScopeNeedsConfinement = map[string]bool{"nuclei": true}

// ConfinedSensors says whether the organization has an active sensor
// that reported net.confined@1 (the sensor repository).
type ConfinedSensors interface {
	HasConfinedSensor(ctx context.Context, tenantID shared.ID) (bool, error)
}

// WithConfinedSensors refuses, when it is queued, a step whose jobs need a
// confined sensor while the organization has none (NO_CONFINED_SENSOR):
// it could never be taken. Without it such a step waits until the run's
// deadline.
func WithConfinedSensors(c ConfinedSensors) Option {
	return func(s *Service) { s.confined = c }
}

// requireConfinedSensor refuses a command that needs a confined sensor
// when the organization has none. A lookup error is returned as is (the
// step fails to queue, and its run may retry).
func (s *Service) requireConfinedSensor(ctx context.Context, tenantID shared.ID, payload map[string]any) error {
	if s.confined == nil {
		return nil
	}
	need, _ := payload[command.PayloadKeyRequiredFeatures].([]string)
	if !slices.Contains(need, sensordom.CapabilityNetConfined) {
		return nil
	}
	ok, err := s.confined.HasConfinedSensor(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("confined sensor lookup: %w", err)
	}
	if !ok {
		return shared.NewDomainError(scanrundom.FailureNoConfinedSensor,
			"this step has a web scope, and its tool keeps to one only on a sensor whose tool network is confined; "+
				"no sensor of the organization reports that (run the sensor with its seccomp profile)", shared.ErrValidation)
	}
	return nil
}

// payloadTargets are the string targets of a command payload.
func payloadTargets(payload map[string]any) []string {
	var out []string
	switch ts := payload["targets"].(type) {
	case []string:
		out = append(out, ts...)
	case []any:
		for _, t := range ts {
			if v, ok := t.(string); ok {
				out = append(out, v)
			}
		}
	}
	return out
}
