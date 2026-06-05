package scancoverage

import (
	"fmt"
	"strings"
)

// ExecutionMode selects how a Tenable integration reaches the appliance
// (RFC-007 §3.9).
type ExecutionMode string

const (
	// ExecutionModeAgent (default) — a runner on the customer network reaches
	// Nessus/Tenable and pushes results back via polling. The control plane
	// holds NO scanner credentials. This is the recommended, secure default.
	ExecutionModeAgent ExecutionMode = "agent"

	// ExecutionModeDirect — the backend calls Tenable REST itself. Only for
	// Tenable cloud / a reachable .sc where the operator accepts the control
	// plane holding credentials.
	ExecutionModeDirect ExecutionMode = "direct"
)

// Engine identifies the Tenable product.
type Engine string

const (
	EngineNessusPro Engine = "nessus_pro" // unlimited IPs (default)
	EngineTenableSC Engine = "tenable_sc" // active-IP licensed
)

// TenableConfig is the normalized config of a Tenable integration, read from the
// integration's JSONB config map.
type TenableConfig struct {
	ExecutionMode ExecutionMode
	Engine        Engine
}

// ParseTenableConfig reads + normalizes execution_mode/engine from an
// integration config map, applying secure defaults (agent + nessus_pro) and
// rejecting unknown values.
func ParseTenableConfig(config map[string]any) (TenableConfig, error) {
	c := TenableConfig{ExecutionMode: ExecutionModeAgent, Engine: EngineNessusPro}

	if v := strings.ToLower(strings.TrimSpace(stringFromConfig(config, "execution_mode"))); v != "" {
		switch ExecutionMode(v) {
		case ExecutionModeAgent, ExecutionModeDirect:
			c.ExecutionMode = ExecutionMode(v)
		default:
			return c, fmt.Errorf("invalid execution_mode %q (want agent|direct)", v)
		}
	}

	if v := strings.ToLower(strings.TrimSpace(stringFromConfig(config, "engine"))); v != "" {
		switch Engine(v) {
		case EngineNessusPro, EngineTenableSC:
			c.Engine = Engine(v)
		default:
			return c, fmt.Errorf("invalid engine %q (want nessus_pro|tenable_sc)", v)
		}
	}

	return c, nil
}

// ValidateTenableIntegration enforces the correctness + security rules for a
// Tenable integration at create/update time.
//
//   - agent mode MUST NOT store credentials in the control plane — they belong
//     on the runner (RFC-007 §8 R3/R4: the control plane holds minimal authority
//     over the scanner).
//   - direct mode requires credentials + a base URL (the api calls Tenable).
func ValidateTenableIntegration(cfg TenableConfig, hasCredentials bool, baseURL string) error {
	switch cfg.ExecutionMode {
	case ExecutionModeAgent:
		if hasCredentials {
			return fmt.Errorf("agent-mode Tenable integration must not store credentials in the control plane; configure them on the runner")
		}
	case ExecutionModeDirect:
		if !hasCredentials {
			return fmt.Errorf("direct-mode Tenable integration requires credentials")
		}
		if strings.TrimSpace(baseURL) == "" {
			return fmt.Errorf("direct-mode Tenable integration requires base_url")
		}
	}
	return nil
}

// stringFromConfig reads a string value from a config map, tolerating nil.
func stringFromConfig(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
