// Package webendpoint is the web surface sub-inventory: the endpoints (a
// method and a path template) and parameters (a location and a name, never a
// value) a web origin serves. An origin is an http_service asset; its
// endpoints hang under it like the ports of a host (asset_services), so a
// crawl of one site writes rows here instead of one asset per URL.
//
// Design: docs/rfcs/RFC-056-web-attack-surface.md.
//
// Every row carries its tenant and inherits the origin asset's data scope:
// an endpoint is visible to a caller exactly when its origin asset is.
// Nothing here stores a parameter value, a query value, user info or a
// fragment; token-like path segments are templated before storage and masked
// in the one example path kept per endpoint.
package webendpoint

import (
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Limits of the sub-inventory.
const (
	// MaxActivePerOrigin bounds the active endpoints of one origin. Beyond
	// it a new template is counted, not stored: that many distinct templates
	// on one origin usually means the templating missed an identifier.
	MaxActivePerOrigin = 5000
	// MaxScriptsPerOrigin bounds the script endpoints (JS files) of one
	// origin, inside MaxActivePerOrigin.
	MaxScriptsPerOrigin = 500
	// MaxParamsPerEndpoint bounds the parameters of one endpoint.
	MaxParamsPerEndpoint = 100
	// MaxPathBytes bounds a path template and an example path.
	MaxPathBytes = 2048
	// MaxParamNameBytes bounds a parameter name.
	MaxParamNameBytes = 128
	// MaxContentTypeBytes bounds a stored content type.
	MaxContentTypeBytes = 100
	// MaxTechnologies bounds the technology names kept per endpoint.
	MaxTechnologies = 20
	// MaxLabels bounds the labels of one endpoint.
	MaxLabels = 20
	// MaxLabelBytes bounds one label.
	MaxLabelBytes = 40
)

// State of an endpoint.
type State string

// Endpoint states.
const (
	StateActive  State = "active"
	StateGone    State = "gone"
	StateIgnored State = "ignored"
)

// ValidState reports whether s is a known state.
func ValidState(s State) bool {
	return s == StateActive || s == StateGone || s == StateIgnored
}

// Endpoint is one stored endpoint of an origin.
type Endpoint struct {
	ID            shared.ID  `json:"id"`
	TenantID      shared.ID  `json:"-"`
	OriginAssetID shared.ID  `json:"origin_asset_id"`
	Origin        string     `json:"origin"`
	Method        string     `json:"method"`
	PathTemplate  string     `json:"path_template"`
	TemplateHash  string     `json:"template_hash"`
	PathHash      string     `json:"path_hash"`
	Kind          string     `json:"kind"`
	Sources       []string   `json:"sources"`
	ExamplePath   string     `json:"example_path,omitempty"`
	LastStatus    int        `json:"last_status,omitempty"`
	ContentType   string     `json:"content_type,omitempty"`
	AuthState     string     `json:"auth_state"`
	Technologies  []string   `json:"technologies"`
	Labels        []string   `json:"labels"`
	State         State      `json:"state"`
	InScope       bool       `json:"in_scope"`
	CatalogKey    string     `json:"catalog_key,omitempty"`
	ParamCount    int        `json:"param_count"`
	FirstSeenAt   time.Time  `json:"first_seen_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	LastChangedAt *time.Time `json:"last_changed_at,omitempty"`
	LastTool      string     `json:"last_tool,omitempty"`
}

// Param is one stored parameter of an endpoint: never a value.
type Param struct {
	Location    string    `json:"location"`
	Name        string    `json:"name"`
	TypeHint    string    `json:"type_hint,omitempty"`
	Required    bool      `json:"required"`
	RiskHints   []string  `json:"risk_hints"`
	Sensitive   string    `json:"sensitive,omitempty"`
	Sources     []string  `json:"sources"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}
