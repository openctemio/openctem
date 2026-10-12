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

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
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
