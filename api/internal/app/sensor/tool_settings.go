package sensor

// Per-sensor tool settings (docs/architecture/sensors.md, "Tool settings"):
// an owner or administrator configures a tool of one of the organization's
// own sensors from the settings schema the tool's descriptor declares in the
// sensor's current manifest. The values are validated with the CTIS
// settings contract, audited with a redacted diff, and delivered to the
// sensor inside each signed job's payload (SensorToolSettingsLayer).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/ctis/settings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ToolSettingsView is one tool's settings on a sensor: its schema as the
// sensor's current manifest declares it, and the stored values (empty when
// none are stored: every key takes its default).
type ToolSettingsView struct {
	Tool         string
	SchemaDigest string
	Schema       json.RawMessage
	Values       map[string]any
	// Stored is false when nothing is stored for the tool.
	Stored bool
	// StoredDigest is the digest of the schema the values were saved
	// against; it differs from SchemaDigest after a sensor upgrade.
	StoredDigest string
	// Problems are why the stored values no longer validate against the
	// current schema (empty when they do); such values fail the jobs of
	// the tool on this sensor until they are saved again or reset.
	Problems  settings.Errors
	UpdatedAt *time.Time
	UpdatedBy *shared.ID
}

// UpdateToolSettingsInput replaces one tool's settings.
type UpdateToolSettingsInput struct {
	TenantID     string
	SensorID     string
	Tool         string
	Values       map[string]any
	AuditContext *auditapp.AuditContext
}

// toolSchema is a tool of the current manifest that declares settings.
type toolSchema struct {
	tool   string
	schema *settings.Schema
}

func (s *SensorService) toolSettingsStore() (sensordom.ToolSettingsStore, bool) {
	store, ok := s.repo.(sensordom.ToolSettingsStore)
	return store, ok
}

// toolSchemas returns the tools of the sensor's current manifest that
// declare a settings schema, in manifest order. A schema the contract
// refuses is left out (and logged): the tool then has no settings here.
func (s *SensorService) toolSchemas(ctx context.Context, a *sensordom.Sensor) ([]toolSchema, error) {
	store, ok := s.manifestStore()
	if !ok {
		return nil, nil
	}
	mv, err := store.CurrentManifest(ctx, a.TenantID, a.ID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []toolSchema
	for _, t := range mv.Manifest.Tools {
		if t.Contract == nil || len(t.Contract.Descriptor) == 0 {
			continue
		}
		schema, err := sensordom.ToolSettingsSchema(t.Contract.Descriptor)
		if err != nil {
			s.logger.Warn("tool settings schema refused", "sensor_id", a.ID.String(), "tool", t.Name, "error", err)
			continue
		}
		if schema != nil {
			out = append(out, toolSchema{tool: t.Name, schema: schema})
		}
	}
	return out, nil
}

// toolSettingsSensor resolves the tenant's own sensor and the tool's schema.
func (s *SensorService) toolSettingsSensor(ctx context.Context, tenantID, sensorID, tool string) (*sensordom.Sensor, sensordom.ToolSettingsStore, *toolSchema, error) {
	store, ok := s.toolSettingsStore()
	if !ok {
		return nil, nil, nil, shared.ErrNotFound
	}
	a, err := s.GetSensor(ctx, tenantID, sensorID)
	if err != nil {
		return nil, nil, nil, err
	}
	if a.TenantID == nil || a.IsPlatformSensor {
		// Platform sensors are managed from the admin console only.
		return nil, nil, nil, shared.ErrNotFound
	}
	if tool == "" {
		return a, store, nil, nil
	}
	name := sensordom.NormalizeToolName(tool)
	if name == "" {
		return nil, nil, nil, sensordom.ErrToolHasNoSettings
	}
	schemas, err := s.toolSchemas(ctx, a)
	if err != nil {
		return nil, nil, nil, err
	}
	for i := range schemas {
		if schemas[i].tool == name {
			return a, store, &schemas[i], nil
		}
	}
	return a, store, &toolSchema{tool: name}, nil
}

// ListToolSettings returns every tool of the sensor's current manifest that
// declares settings, with its schema and stored values.
func (s *SensorService) ListToolSettings(ctx context.Context, tenantID, sensorID string) ([]ToolSettingsView, error) {
	a, store, _, err := s.toolSettingsSensor(ctx, tenantID, sensorID, "")
	if err != nil {
		return nil, err
	}
	schemas, err := s.toolSchemas(ctx, a)
	if err != nil {
		return nil, err
	}
	rows, err := store.ListToolSettings(ctx, *a.TenantID, a.ID)
	if err != nil {
		return nil, err
	}
	byTool := make(map[string]*sensordom.ToolSettings, len(rows))
	for i := range rows {
		byTool[rows[i].Tool] = &rows[i]
	}
	out := make([]ToolSettingsView, 0, len(schemas))
	for _, ts := range schemas {
		out = append(out, toolSettingsView(ts, byTool[ts.tool]))
	}
	return out, nil
}

func toolSettingsView(ts toolSchema, row *sensordom.ToolSettings) ToolSettingsView {
	v := ToolSettingsView{Tool: ts.tool, SchemaDigest: ts.schema.Digest(), Schema: ts.schema.Raw, Values: map[string]any{}}
	if row == nil {
		return v
	}
	v.Stored, v.StoredDigest, v.UpdatedBy = true, row.SchemaDigest, row.UpdatedBy
	at := row.UpdatedAt
	v.UpdatedAt = &at
	if row.Values != nil {
		v.Values = row.Values
	}
	if row.SchemaDigest != v.SchemaDigest {
		var errs settings.Errors
		if err := sensordom.ValidateToolSettings(ts.schema, row.Values); errors.As(err, &errs) {
			v.Problems = errs
		}
	}
	return v
}

// UpdateToolSettings validates and stores one tool's settings and audits
// the change. Validation errors are settings.Errors (by JSON pointer).
func (s *SensorService) UpdateToolSettings(ctx context.Context, in UpdateToolSettingsInput) (*ToolSettingsView, error) {
	a, store, ts, err := s.toolSettingsSensor(ctx, in.TenantID, in.SensorID, in.Tool)
	if err != nil {
		return nil, err
	}
	if ts.schema == nil {
		return nil, sensordom.ErrToolHasNoSettings
	}
	values := in.Values
	if values == nil {
		values = map[string]any{}
	}
	if err := sensordom.ValidateToolSettings(ts.schema, values); err != nil {
		return nil, err
	}
	var before map[string]any
	if prev, err := store.GetToolSettings(ctx, *a.TenantID, a.ID, ts.tool); err == nil {
		before = prev.Values
	} else if !errors.Is(err, shared.ErrNotFound) {
		return nil, err
	}
	row := sensordom.ToolSettings{
		TenantID: *a.TenantID, SensorID: a.ID, Tool: ts.tool, Values: values,
		SchemaDigest: ts.schema.Digest(), UpdatedAt: s.now().UTC(),
	}
	if in.AuditContext != nil {
		if id, err := shared.IDFromString(in.AuditContext.ActorID); err == nil {
			row.UpdatedBy = &id
		}
	}
	if err := store.SaveToolSettings(ctx, row); err != nil {
		return nil, err
	}
	s.auditToolSettings(ctx, a, ts.tool, ts.schema, before, values, in.AuditContext)
	v := toolSettingsView(*ts, &row)
	return &v, nil
}

// ResetToolSettings removes one tool's settings (every key back to its
// default). It works for a tool the current manifest no longer lists, so
// stale settings can always be cleared.
func (s *SensorService) ResetToolSettings(ctx context.Context, tenantID, sensorID, tool string, actx *auditapp.AuditContext) error {
	a, store, ts, err := s.toolSettingsSensor(ctx, tenantID, sensorID, tool)
	if err != nil {
		return err
	}
	prev, err := store.GetToolSettings(ctx, *a.TenantID, a.ID, ts.tool)
	if errors.Is(err, shared.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	deleted, err := store.DeleteToolSettings(ctx, *a.TenantID, a.ID, ts.tool)
	if err != nil || !deleted {
		return err
	}
	s.auditToolSettings(ctx, a, ts.tool, ts.schema, prev.Values, nil, actx)
	return nil
}

// auditToolSettings records the change as a sensor update whose changes
// are the keys that changed ("tool_settings.<tool>.<key>"); the value of a
// sensitive key, or of a key the schema does not know, is redacted.
func (s *SensorService) auditToolSettings(ctx context.Context, a *sensordom.Sensor, tool string, schema *settings.Schema,
	before, after map[string]any, actx *auditapp.AuditContext,
) {
	if s.auditService == nil || actx == nil {
		return
	}
	old, updated := sensordom.ToolSettingsDiff(schema, before, after)
	if len(old) == 0 {
		return
	}
	changes := audit.NewChanges()
	for k := range old {
		changes.Set("tool_settings."+tool+"."+k, old[k], updated[k])
	}
	s.warnAudit(s.auditService.LogSensorUpdated(ctx, *actx, a.ID.String(), a.Name, changes), "LogSensorUpdated", a.ID.String())
}

// EffectiveToolSettings returns every key of the tool's schema with the
// value a job of this sensor runs with (before the scan's own layer), and
// where it comes from.
func (s *SensorService) EffectiveToolSettings(ctx context.Context, tenantID, sensorID, tool string) ([]sensordom.EffectiveToolSetting, *ToolSettingsView, error) {
	a, store, ts, err := s.toolSettingsSensor(ctx, tenantID, sensorID, tool)
	if err != nil {
		return nil, nil, err
	}
	if ts.schema == nil {
		return nil, nil, sensordom.ErrToolHasNoSettings
	}
	row, err := store.GetToolSettings(ctx, *a.TenantID, a.ID, ts.tool)
	if errors.Is(err, shared.ErrNotFound) {
		row = nil
	} else if err != nil {
		return nil, nil, err
	}
	view := toolSettingsView(*ts, row)
	if len(view.Problems) > 0 {
		return nil, &view, view.Problems
	}
	eff, err := sensordom.EffectiveToolSettings(ts.schema, view.Values)
	if err != nil {
		return nil, &view, err
	}
	return eff, &view, nil
}

// SensorToolSettingsLayer is the sensor layer of a job of tool claimed by
// sensorID: the stored values (nil when none), checked against the schema
// of the sensor's current manifest. Values saved against another schema
// digest are validated again; values that no longer validate are an error
// wrapping sensordom.ErrToolSettingsInvalid (the job is failed with it,
// never run without them). Other errors are transient.
func (s *SensorService) SensorToolSettingsLayer(ctx context.Context, tenantID, sensorID shared.ID, tool string) (map[string]any, error) {
	store, ok := s.toolSettingsStore()
	if !ok {
		return nil, nil
	}
	row, err := store.GetToolSettings(ctx, tenantID, sensorID, tool)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(row.Values) == 0 {
		return nil, nil
	}
	mstore, ok := s.manifestStore()
	if !ok {
		return nil, fmt.Errorf("%w: no manifest store", sensordom.ErrToolSettingsInvalid)
	}
	mv, err := mstore.CurrentManifest(ctx, &tenantID, sensorID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("%w: the sensor reports no manifest", sensordom.ErrToolSettingsInvalid)
	}
	if err != nil {
		return nil, err
	}
	schema, err := sensordom.ToolSettingsSchema(mv.Manifest.ToolDescriptor(tool))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", sensordom.ErrToolSettingsInvalid, err)
	}
	if schema == nil {
		return nil, fmt.Errorf("%w: the sensor's %s no longer declares settings", sensordom.ErrToolSettingsInvalid, tool)
	}
	if schema.Digest() != row.SchemaDigest {
		if err := sensordom.ValidateToolSettings(schema, row.Values); err != nil {
			return nil, fmt.Errorf("%w: %w", sensordom.ErrToolSettingsInvalid, err)
		}
	}
	return row.Values, nil
}
