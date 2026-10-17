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

// TenantToolSettings is one tool's organization defaults: the values every
// one of the organization's own sensors runs the tool with unless the
// sensor overrides a key. Shared platform sensors never receive them.
type TenantToolSettings struct {
	TenantID shared.ID
	Tool     string
	// Values are the keys the administrator set (numbers as json.Number).
	Values map[string]any
	// SchemaDigest is the digest of the reference schema (the newest
	// manifest's) the values were saved against; they were checked against
	// every schema the organization's sensors reported for the tool.
	SchemaDigest string
	UpdatedBy    *shared.ID
	UpdatedAt    time.Time
}

// TenantToolSettingsStore keeps organization tool defaults. Every method is
// scoped by tenant.
type TenantToolSettingsStore interface {
	// ListTenantToolSettings returns the organization's defaults, by tool.
	ListTenantToolSettings(ctx context.Context, tenantID shared.ID) ([]TenantToolSettings, error)
	// GetTenantToolSettings returns one tool's defaults, or shared.ErrNotFound.
	GetTenantToolSettings(ctx context.Context, tenantID shared.ID, tool string) (*TenantToolSettings, error)
	// SaveTenantToolSettings inserts or replaces one tool's defaults.
	SaveTenantToolSettings(ctx context.Context, ts TenantToolSettings) error
	// DeleteTenantToolSettings removes one tool's defaults; false when there
	// were none.
	DeleteTenantToolSettings(ctx context.Context, tenantID shared.ID, tool string) (bool, error)
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
	return validateAdminLayer(schema, settings.SourceSensor, values)
}

// ValidateTenantToolSettings is ValidateToolSettings for the organization's
// defaults (the tenant layer): any key, raising or lowering the tool's
// default, no non-default dangerous value.
func ValidateTenantToolSettings(schema *settings.Schema, values map[string]any) error {
	return validateAdminLayer(schema, settings.SourceTenant, values)
}

func validateAdminLayer(schema *settings.Schema, src settings.Source, values map[string]any) error {
	if err := schema.Validate(values); err != nil {
		return err
	}
	if _, err := schema.Resolve(settings.Layer{Source: src, Values: values}); err != nil {
		return err
	}
	return refuseDangerous(schema, values)
}

// TierImpact is the safety class whose changes raise the load or reach of
// each scan; changing one needs the acting user's recent re-authentication.
const TierImpact = "T1"

// ImpactChanges returns the Impact (T1) keys whose value after differs from
// before and is set (a key removed, back to its default or inherited value,
// is not a raise), flattened and sorted.
func ImpactChanges(schema *settings.Schema, before, after map[string]any) []string {
	if schema == nil {
		return nil
	}
	var out []string
	for _, k := range flatKeys(after) {
		p := schema.Property(k)
		if p == nil || p.Tier != TierImpact {
			continue
		}
		if a := lookupFlat(after, k); a != nil && !jsonEqual(lookupFlat(before, k), a) {
			out = append(out, k)
		}
	}
	return out
}

// refuseDangerous refuses a non-default value of a dangerous (T2) key: the
// organization's enablement of dangerous options is not available yet.
func refuseDangerous(schema *settings.Schema, values map[string]any) error {
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
	// Chain is every layer that sets the key, lowest first (the tool's
	// default, the organization, the sensor, the scan); the last one is in
	// force. An organization value the sensor overrides is listed too.
	Chain []LayerValue
}

// LayerValue is the value one layer sets for a key.
type LayerValue struct {
	Source settings.Source
	Value  any
}

// AdminValues are the administrators' values of one tool for one sensor:
// the organization's defaults (every one of its own sensors) and the
// sensor's own overrides. The organization layer is a default, not a cap:
// a key the sensor sets replaces the organization's value, in either
// direction (InheritedValues).
type AdminValues struct {
	Organization map[string]any
	Sensor       map[string]any
}

// InheritedValues is the organization layer as one sensor receives it: the
// organization's values without the keys the sensor overrides (a group's
// keys one by one), so the two layers never set the same key and the
// tenant layer never caps the sensor's. nil when nothing is left.
func InheritedValues(org, sensor map[string]any) map[string]any {
	if len(org) == 0 {
		return nil
	}
	out := map[string]any{}
	for k, v := range org {
		group, isGroup := v.(map[string]any)
		if !isGroup {
			if _, overridden := sensor[k]; !overridden {
				out[k] = v
			}
			continue
		}
		sg, _ := sensor[k].(map[string]any)
		kept := map[string]any{}
		for ck, cv := range group {
			if _, overridden := sg[ck]; !overridden {
				kept[ck] = cv
			}
		}
		if len(kept) > 0 {
			out[k] = kept
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// layers returns the tenant layer (inherited values, when any) then the
// sensor layer (when any).
func (a AdminValues) layers() []settings.Layer {
	var out []settings.Layer
	if inh := InheritedValues(a.Organization, a.Sensor); len(inh) > 0 {
		out = append(out, settings.Layer{Source: settings.SourceTenant, Values: inh})
	}
	if len(a.Sensor) > 0 {
		out = append(out, settings.Layer{Source: settings.SourceSensor, Values: a.Sensor})
	}
	return out
}

// EffectiveToolSettings resolves the administrators' values over the
// schema's defaults and returns every key of the schema (in key order) with
// its value (nil when it has none), where it came from ("default",
// "tenant", "sensor" or "" for none), the chain of layers that set it, its
// native flag, common option, scope and tier. A sensitive key never shows
// its value.
func EffectiveToolSettings(schema *settings.Schema, admin AdminValues) ([]EffectiveToolSetting, error) {
	return EffectiveToolSettingsWithScan(schema, admin, nil)
}

// scanExecutorKeys are the scan-config keys the sensor's command executor
// reads itself (sdk-go core: the job's limits rate_limit, bulk_size and
// concurrency, which only ever lower the value in force, and the run
// switches allow_interactsh and exclude); they never form the scan layer.
var scanExecutorKeys = map[string]bool{
	"allow_interactsh": true, "exclude": true,
	"rate_limit": true, "bulk_size": true, "concurrency": true,
}

// ScanSettingsLayer returns the scan layer a sensor builds from a scan's
// config, as the sensor builds it: the keys the tool's schema declares,
// without the executor's own keys. ignored lists the other keys (the
// sensor ignores them too), sorted; a key that is not a setting name is
// not echoed.
func ScanSettingsLayer(schema *settings.Schema, config map[string]any) (layer map[string]any, ignored []string) {
	layer = map[string]any{}
	for k, v := range config {
		switch {
		case scanExecutorKeys[k]:
		case schema != nil && settings.ValidName(k) && schema.Property(k) != nil:
			layer[k] = v
		case settings.ValidName(k):
			ignored = append(ignored, k)
		default:
			ignored = append(ignored, "<invalid key>")
		}
	}
	sort.Strings(ignored)
	return layer, ignored
}

// ValidateScanSettings checks a scan layer over the administrators' values
// the way the sensor resolves a job: only scan-scope keys, within their
// constraints, never raising a common option above the value in force (the
// sensor's, the organization's, or the default), and no non-default value
// of a dangerous (T2) key. The error is settings.Errors, by JSON pointer.
func ValidateScanSettings(schema *settings.Schema, admin AdminValues, scanLayer map[string]any) error {
	if schema == nil || len(scanLayer) == 0 {
		return nil
	}
	if _, err := schema.Resolve(scanLayers(admin, scanLayer)...); err != nil {
		return err
	}
	return refuseDangerous(schema, scanLayer)
}

// scanLayers is the administrators' layers (when any) then the scan layer.
func scanLayers(admin AdminValues, scanLayer map[string]any) []settings.Layer {
	layers := admin.layers()
	if len(scanLayer) > 0 {
		layers = append(layers, settings.Layer{Source: settings.SourceScan, Values: scanLayer})
	}
	return layers
}

// EffectiveToolSettingsWithScan is EffectiveToolSettings with a scan layer
// (ScanSettingsLayer) over the administrators' values: what a job of that
// scan runs with on that sensor, before the job's own limits and the
// sensor's local policy, which only lower values. Sources include "scan".
func EffectiveToolSettingsWithScan(schema *settings.Schema, admin AdminValues, scanLayer map[string]any) ([]EffectiveToolSetting, error) {
	if schema == nil {
		return []EffectiveToolSetting{}, nil
	}
	resolved, err := schema.Resolve(scanLayers(admin, scanLayer)...)
	if err != nil {
		return nil, err
	}
	all := resolved.Values()
	defaults := flattenValues(schema.Defaults())
	var out []EffectiveToolSetting
	add := func(key string, p *settings.Property) {
		e := EffectiveToolSetting{Key: key, Source: resolved.Source(key), Flag: p.Flag,
			Common: p.Common, Scope: p.Scope, Tier: p.Tier, Chain: []LayerValue{}}
		redact := p.Sensitive || p.WriteOnly
		if v, ok := all[key]; ok {
			e.Value = v
			if redact {
				e.Value = RedactedSettingValue
			}
		}
		for _, l := range []struct {
			src    settings.Source
			values map[string]any
		}{
			{settings.SourceDefault, defaults}, {settings.SourceTenant, admin.Organization},
			{settings.SourceSensor, admin.Sensor}, {settings.SourceScan, scanLayer},
		} {
			v := lookupFlat(l.values, key)
			if l.src == settings.SourceDefault {
				v = l.values[key]
			}
			if v == nil {
				continue
			}
			if redact {
				v = RedactedSettingValue
			}
			e.Chain = append(e.Chain, LayerValue{Source: l.src, Value: v})
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

// flattenValues flattens a values document: a group's keys as "group.key".
func flattenValues(values map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range flatKeys(values) {
		out[k] = lookupFlat(values, k)
	}
	return out
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
