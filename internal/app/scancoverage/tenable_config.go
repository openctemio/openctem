package scancoverage

import (
	"encoding/json"
	"fmt"
	"strconv"
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

// DefaultCoverageBatch is the per-cycle batch size used when an integration does
// not specify one. It bounds scan duration/load for an unlimited engine and is
// the perf/time window, not a license limit.
const DefaultCoverageBatch = 256

// TenableConfig is the normalized config of a Tenable integration, read from the
// integration's JSONB config map.
type TenableConfig struct {
	ExecutionMode ExecutionMode
	Engine        Engine

	// CoverageEnabled opts this integration into automatic rolling coverage by
	// the scheduler. It defaults to false so connecting an integration never
	// silently starts scanning — coverage is an explicit choice.
	CoverageEnabled bool
	// BatchSize is the per-cycle target batch size (perf/time window). 0 → default.
	BatchSize int
	// LicenseCap is the active-IP cap for a capped engine (.sc only).
	LicenseCap int
	// SafetyMargin keeps the scheduler a few IPs below the cap (.sc only).
	SafetyMargin int
	// AgentID optionally pins a specific runner (C3); empty → capability routing.
	AgentID string
	// TemplateUUID optionally overrides the runner's default Nessus template.
	TemplateUUID string
}

// ParseTenableConfig reads + normalizes a Tenable integration config map,
// applying secure defaults (agent + nessus_pro) and rejecting unknown values.
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

	c.CoverageEnabled = boolFromConfig(config, "coverage_enabled")
	c.BatchSize = intFromConfig(config, "batch_size")
	c.LicenseCap = intFromConfig(config, "license_cap")
	c.SafetyMargin = intFromConfig(config, "safety_margin")
	c.AgentID = strings.TrimSpace(stringFromConfig(config, "agent_id"))
	c.TemplateUUID = strings.TrimSpace(stringFromConfig(config, "template_uuid"))

	if c.BatchSize < 0 || c.LicenseCap < 0 || c.SafetyMargin < 0 {
		return c, fmt.Errorf("batch_size/license_cap/safety_margin must not be negative")
	}

	return c, nil
}

// LicensePolicy derives the engine's licensing rule used to size a coverage
// batch. Nessus Pro is unlimited; Tenable.sc is active-IP capped.
func (c TenableConfig) LicensePolicy() LicensePolicy {
	if c.Engine == EngineTenableSC {
		return LicensePolicy{Mode: LicenseActiveIPCap, Cap: c.LicenseCap, SafetyMargin: c.SafetyMargin}
	}
	return LicensePolicy{Mode: LicenseUnlimited}
}

// EffectiveBatchSize returns the configured batch size or the default.
func (c TenableConfig) EffectiveBatchSize() int {
	if c.BatchSize <= 0 {
		return DefaultCoverageBatch
	}
	return c.BatchSize
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

// boolFromConfig reads a bool from a config map, tolerating nil and the common
// JSON shapes a bool can arrive as (true bool, or the string "true").
func boolFromConfig(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

// intFromConfig reads an int from a config map. JSON numbers decode to float64,
// so that is handled alongside int and a numeric string. Returns 0 when absent
// or unparseable.
func intFromConfig(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n)
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return 0
}
