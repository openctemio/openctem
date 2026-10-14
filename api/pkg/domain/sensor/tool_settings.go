package sensor

// Per-sensor tool settings (docs/architecture/sensors.md, "Tool settings"):
// what an owner or administrator configured for one tool of one of the
// organization's own sensors. The schema is the "config" object of the tool
// descriptor the sensor reported in its current manifest (Tool Contract v1),
// parsed and enforced with the CTIS settings contract (ctis/settings), the
// same code the sensor validates with. The values travel to the sensor only
// inside a signed job's payload (settings_layers.sensor).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/ctis/settings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxToolSettingsBytes bounds one stored values document (the schema
// already bounds each value; this bounds the request body).
const MaxToolSettingsBytes = 64 << 10

// RedactedSettingValue replaces the value of a sensitive key in an audit
// diff.
const RedactedSettingValue = "[redacted]"

// TierDangerous is the safety class whose non-default values need the
// organization's explicit enablement.
const TierDangerous = "T2"

// ToolSettings is one tool's stored settings on one sensor.
type ToolSettings struct {
	TenantID shared.ID
	SensorID shared.ID
	Tool     string
	// Values are the keys the administrator set (numbers as json.Number);
	// keys left out take the tool's defaults.
	Values map[string]any
	// SchemaDigest is the digest (settings.Schema.Digest) of the schema the
	// values were validated against.
	SchemaDigest string
	UpdatedBy    *shared.ID
	UpdatedAt    time.Time
}

// ToolSettingsStore keeps tool settings. Every method is scoped by tenant.
type ToolSettingsStore interface {
	// ListToolSettings returns the sensor's stored settings, by tool.
	ListToolSettings(ctx context.Context, tenantID, sensorID shared.ID) ([]ToolSettings, error)
	// GetToolSettings returns one tool's settings, or shared.ErrNotFound.
	GetToolSettings(ctx context.Context, tenantID, sensorID shared.ID, tool string) (*ToolSettings, error)
	// SaveToolSettings inserts or replaces one tool's settings.
	SaveToolSettings(ctx context.Context, ts ToolSettings) error
	// DeleteToolSettings removes one tool's settings; false when there
	// were none.
	DeleteToolSettings(ctx context.Context, tenantID, sensorID shared.ID, tool string) (bool, error)
}

// ErrToolHasNoSettings: the tool is not in the sensor's current manifest,
// or its descriptor declares no settings schema.
var ErrToolHasNoSettings = fmt.Errorf("%w: the tool declares no settings on this sensor", shared.ErrNotFound)

// ErrToolSettingsSchema: the descriptor's settings schema does not parse
// (the sensor reported a schema the contract refuses).
var ErrToolSettingsSchema = errors.New("tool settings schema is invalid")

// ErrToolSettingsInvalid: a sensor's stored settings of a tool no longer
// validate against the settings schema of its current manifest (a sensor
// upgrade removed or narrowed a key); its jobs of that tool fail at claim
// until the settings are saved again or reset.
var ErrToolSettingsInvalid = errors.New("the sensor's tool settings no longer match the tool's settings schema; save or reset them")

// NormalizeToolName returns the stored form of a tool name, or "" when it
// is not a valid tool name.
func NormalizeToolName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if !validToolName(n) {
		return ""
	}
	return n
}

// ToolSettingsSchema returns the settings schema of a tool descriptor: its
// "config" member parsed with the CTIS settings contract. nil, nil when the
// descriptor has no config (the tool has no settings).
func ToolSettingsSchema(descriptor json.RawMessage) (*settings.Schema, error) {
	if len(descriptor) == 0 {
		return nil, nil
	}
	var d struct {
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(descriptor, &d); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrToolSettingsSchema, err)
	}
	raw := bytes.TrimSpace(d.Config)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	s, err := settings.ParseSchema(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrToolSettingsSchema, err)
	}
	return s, nil
}

// DecodeToolSettingsValues decodes a values document (numbers kept as
// json.Number). An empty document is an empty object.
func DecodeToolSettingsValues(raw []byte) (map[string]any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return map[string]any{}, nil
	}
	if len(raw) > MaxToolSettingsBytes {
		return nil, settings.Errors{{Path: "", Message: fmt.Sprintf("larger than %d bytes", MaxToolSettingsBytes)}}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return nil, settings.Errors{{Path: "", Message: "not a JSON object"}}
	}
	if v == nil {
		v = map[string]any{}
	}
	return v, nil
}

// ValidateToolSettings checks values as a sensor layer of schema: every
// key known and within its constraints, sensitive keys absent, required
// keys given or defaulted, and no non-default value of a dangerous (T2) key
// (the organization's enablement of dangerous options is not available
// yet). The error is settings.Errors, by JSON pointer.
func ValidateToolSettings(schema *settings.Schema, values map[string]any) error {
	if err := schema.Validate(values); err != nil {
		return err
	}
	if _, err := schema.Resolve(settings.Layer{Source: settings.SourceSensor, Values: values}); err != nil {
		return err
	}
	var errs settings.Errors
	for _, key := range flatKeys(values) {
		p := schema.Property(key)
		if p == nil || p.Tier != TierDangerous {
			continue
		}
		v := lookupFlat(values, key)
		if p.HasDefault && jsonEqual(v, p.Default) {
			continue
		}
		errs = append(errs, settings.Error{
			Path:    "/" + strings.ReplaceAll(key, ".", "/"),
			Message: "a dangerous (T2) option: a non-default value needs the organization's enablement of dangerous options, which is not available yet",
		})
	}
	if len(errs) > 0 {
		sort.SliceStable(errs, func(i, j int) bool { return errs[i].Path < errs[j].Path })
		return errs
	}
	return nil
}

// ToolSettingsDiff returns the keys whose value changed between before and
// after (flattened as "group.key"), each with its old and new value; a key
// absent on one side is nil there. The value of a sensitive key is
// RedactedSettingValue, never the value.
func ToolSettingsDiff(schema *settings.Schema, before, after map[string]any) (old, updated map[string]any) {
	old, updated = map[string]any{}, map[string]any{}
	keys := map[string]bool{}
	for _, k := range flatKeys(before) {
		keys[k] = true
	}
	for _, k := range flatKeys(after) {
		keys[k] = true
	}
	for k := range keys {
		b, a := lookupFlat(before, k), lookupFlat(after, k)
		if jsonEqual(b, a) {
			continue
		}
		if p := schema.Property(k); p == nil || p.Sensitive || p.WriteOnly {
			// Unknown keys (a schema that changed) are redacted too: the
			// audit never carries a value it cannot classify.
			if b != nil {
				b = RedactedSettingValue
			}
			if a != nil {
				a = RedactedSettingValue
			}
		}
		old[k], updated[k] = b, a
	}
	return old, updated
}

// EffectiveToolSetting is one key of a tool's effective settings.
type EffectiveToolSetting struct {
	Key    string
	Value  any
	Source settings.Source
	Flag   string
	Common string
	Scope  settings.Scope
	Tier   string
}

// EffectiveToolSettings resolves values over the schema's defaults and
// returns every key of the schema (in key order) with its value (nil when
// it has none), where it came from ("default", "sensor" or "" for none),
// its native flag, common option, scope and tier. A sensitive key never
// shows its value.
func EffectiveToolSettings(schema *settings.Schema, values map[string]any) ([]EffectiveToolSetting, error) {
	if schema == nil {
		return []EffectiveToolSetting{}, nil
	}
	resolved, err := schema.Resolve(settings.Layer{Source: settings.SourceSensor, Values: values})
	if err != nil {
		return nil, err
	}
	all := resolved.Values()
	var out []EffectiveToolSetting
	add := func(key string, p *settings.Property) {
		e := EffectiveToolSetting{Key: key, Source: resolved.Source(key), Flag: p.Flag,
			Common: p.Common, Scope: p.Scope, Tier: p.Tier}
		if v, ok := all[key]; ok {
			e.Value = v
			if p.Sensitive || p.WriteOnly {
				e.Value = RedactedSettingValue
			}
		}
		out = append(out, e)
	}
	for _, p := range schema.Properties {
		if p.Type == "object" {
			for _, c := range p.Properties {
				add(p.Name+"."+c.Name, c)
			}
			continue
		}
		add(p.Name, p)
	}
	if out == nil {
		out = []EffectiveToolSetting{}
	}
	return out, nil
}

// flatKeys returns the keys of a values document, a group's keys as
// "group.key", sorted.
func flatKeys(values map[string]any) []string {
	out := make([]string, 0, len(values))
	for k, v := range values {
		if m, ok := v.(map[string]any); ok {
			for c := range m {
				out = append(out, k+"."+c)
			}
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lookupFlat returns the value of a flattened key, or nil.
func lookupFlat(values map[string]any, key string) any {
	name, rest, nested := strings.Cut(key, ".")
	v, ok := values[name]
	if !ok {
		return nil
	}
	if !nested {
		return v
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return m[rest]
}
