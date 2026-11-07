package scanrun

// What a step run ran with (research/426 P0.3, docs/architecture/scan-stages.md).
//
//   - EffectiveConfig is the platform's record at dispatch: the capability's
//     standard params the command carries, each with the layer that set it.
//     Standard params only, bounded, never headers or credentials.
//   - SensorSettings is what the sensor reported it ran with (result
//     metadata effective_settings and ignored_config_keys). It is sensor
//     supplied, so it is parsed defensively, bounded and cleaned, and only
//     ever shown: nothing in the platform reads it to widen anything.

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	scandom "github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/safetext"
)

// Sources of a param of the effective config, lowest to highest.
const (
	ParamSourceCapabilityDefault = "capability_default"
	ParamSourceTemplateStep      = "template_step"
	ParamSourceDepthOverlay      = "depth_overlay"
	ParamSourceScanOverride      = "scan_override"
	ParamSourceStageFixed        = "stage_fixed"
	ParamSourceDefaultPortSet    = "default_port_set"
)

// Bounds of the stored documents.
const (
	MaxEffectiveParams     = 32
	maxParamValueBytes     = 2048
	MaxSensorSettings      = 32
	maxSensorKeyRunes      = 64
	maxSensorStringRunes   = 256
	maxSensorListItems     = 32
	maxSensorSourceRunes   = 32
	MaxIgnoredConfigKeys   = 32
	maxIgnoredKeyRunes     = 64
	maxSensorSettingsBytes = 16 * 1024
)

// ParamValue is one standard param with the layer that set it.
type ParamValue struct {
	Value  any    `json:"value"`
	Source string `json:"source"`
}

// EffectiveConfig is the standard params a step's command carries.
type EffectiveConfig struct {
	Params     map[string]ParamValue `json:"params"`
	Tool       string                `json:"tool,omitempty"`
	Capability string                `json:"capability,omitempty"`
	Depth      string                `json:"depth,omitempty"`
}

// Bounded returns c without a param whose value is too large, and at most
// MaxEffectiveParams params (the first by name).
func (c EffectiveConfig) Bounded() EffectiveConfig {
	out := EffectiveConfig{Params: map[string]ParamValue{}, Tool: safetext.Truncate(safetext.Clean(c.Tool), 64),
		Capability: safetext.Truncate(safetext.Clean(c.Capability), 64), Depth: safetext.Truncate(safetext.Clean(c.Depth), 16)}
	names := make([]string, 0, len(c.Params))
	for k := range c.Params {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, k := range names {
		if len(out.Params) >= MaxEffectiveParams {
			break
		}
		pv := c.Params[k]
		b, err := json.Marshal(pv.Value)
		if err != nil || len(b) > maxParamValueBytes {
			continue
		}
		out.Params[safetext.Truncate(safetext.Clean(k), maxSensorKeyRunes)] = pv
	}
	return out
}

// SensorSetting is one setting the sensor reports it ran with.
type SensorSetting struct {
	Value  any    `json:"value"`
	Source string `json:"source,omitempty"`
}

// SensorSettings is what the sensor says it ran a step with.
type SensorSettings struct {
	Effective         map[string]SensorSetting `json:"effective,omitempty"`
	IgnoredConfigKeys []string                 `json:"ignored_config_keys,omitempty"`
	// SentWith is what the step's requests carried (result metadata
	// http_identity, ParseAppliedIdentity): display only.
	SentWith []AppliedIdentity `json:"sent_with,omitempty"`
}

// MaskedSensorValue replaces a reported setting that looks like a credential.
const MaskedSensorValue = "[masked]"

// IsZero reports whether nothing was reported.
func (s SensorSettings) IsZero() bool {
	return len(s.Effective) == 0 && len(s.IgnoredConfigKeys) == 0 && len(s.SentWith) == 0
}

// secretKeyParts mark a setting that may hold a credential: never stored.
var secretKeyParts = []string{"header", "token", "password", "passwd", "secret", "auth", "cookie", "credential", "key", "bearer"}

func secretKey(k string) bool {
	l := strings.ToLower(k)
	for _, p := range secretKeyParts {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

// safeSensorValue keeps a string, bool, number or a short list of strings;
// anything else (objects, nested lists) is dropped.
func safeSensorValue(v any) (any, bool) {
	switch t := v.(type) {
	case string:
		return safetext.SingleLine(t, maxSensorStringRunes), true
	case bool, float64:
		return t, true
	case []any:
		out := make([]string, 0, len(t))
		for _, it := range t {
			s, ok := it.(string)
			if !ok {
				return nil, false
			}
			if len(out) >= maxSensorListItems {
				break
			}
			out = append(out, safetext.SingleLine(s, maxSensorStringRunes))
		}
		return out, true
	}
	return nil, false
}

// ParseSensorSettings reads the result metadata's effective_settings
// ({key: {value, source}}) and ignored_config_keys (a list of strings).
// Malformed input yields what could be read, never an error.
func ParseSensorSettings(effective, ignored json.RawMessage) SensorSettings {
	var out SensorSettings
	var eff map[string]map[string]any
	if len(effective) > 0 && len(effective) <= maxSensorSettingsBytes && json.Unmarshal(effective, &eff) == nil {
		keys := make([]string, 0, len(eff))
		for k := range eff {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if len(out.Effective) >= MaxSensorSettings {
				break
			}
			ck := safetext.Truncate(safetext.SingleLine(k, maxSensorKeyRunes), maxSensorKeyRunes)
			if ck == "" || secretKey(ck) {
				continue
			}
			val, ok := safeSensorValue(eff[k]["value"])
			if !ok {
				continue
			}
			// A value that looks like a credential (a URL with user:pass@, a
			// bearer token, a provider key) is shown masked, never as reported.
			if len(scandom.DetectConfigSecrets(map[string]any{ck: val})) > 0 {
				val = MaskedSensorValue
			}
			src, _ := eff[k]["source"].(string)
			if out.Effective == nil {
				out.Effective = map[string]SensorSetting{}
			}
			out.Effective[ck] = SensorSetting{Value: val, Source: safetext.Truncate(safetext.SingleLine(src, maxSensorSourceRunes), maxSensorSourceRunes)}
		}
	}
	var keys []any
	if len(ignored) > 0 && len(ignored) <= maxSensorSettingsBytes && json.Unmarshal(ignored, &keys) == nil {
		for _, kv := range keys {
			k, isStr := kv.(string)
			if !isStr {
				continue // one malformed entry does not hide the rest
			}
			if len(out.IgnoredConfigKeys) >= MaxIgnoredConfigKeys {
				break
			}
			ck := safetext.SingleLine(k, maxIgnoredKeyRunes)
			if ck != "" && !secretKey(ck) {
				out.IgnoredConfigKeys = append(out.IgnoredConfigKeys, ck)
			}
		}
	}
	return out
}

// StepRunConfigRecorder stores what a step run ran with. Both writes are
// scoped to tenantID through the step run's scan run: another tenant's step
// run is never touched (ErrNotFound).
type StepRunConfigRecorder interface {
	SetEffectiveConfig(ctx context.Context, tenantID, stepRunID shared.ID, cfg EffectiveConfig) error
	SetSensorSettings(ctx context.Context, tenantID, stepRunID shared.ID, s SensorSettings) error
}
