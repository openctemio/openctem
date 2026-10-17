package sensor

// Per-sensor tool settings (docs/architecture/sensors.md, "Tool settings"):
// an owner or administrator overrides, for one of the organization's own
// sensors, the organization's tool defaults (tool_defaults.go), from the
// settings schema the tool's descriptor declares in the sensor's current
// manifest. The values are validated with the CTIS settings contract,
// audited with a redacted diff, and delivered to the sensor inside each
// signed job's payload with the defaults it inherits (ToolSettingsLayers).

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
	Problems settings.Errors
	// Organization are the organization's defaults for the tool (nil when
	// none): the sensor runs with them for every key it does not set.
	Organization map[string]any
	// OrganizationProblems are why the organization's defaults do not
	// validate against this sensor's schema; they fail the tool's jobs on
	// this sensor until the defaults are changed.
	OrganizationProblems settings.Errors
	UpdatedAt            *time.Time
	UpdatedBy            *shared.ID
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
	if a.TenantID == nil || a.IsShared() {
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
	org, err := s.orgToolValues(ctx, *a.TenantID)
	if err != nil {
		return nil, err
	}
	out := make([]ToolSettingsView, 0, len(schemas))
	for _, ts := range schemas {
		out = append(out, toolSettingsView(ts, byTool[ts.tool], org[ts.tool]))
	}
	return out, nil
}

func toolSettingsView(ts toolSchema, row *sensordom.ToolSettings, org map[string]any) ToolSettingsView {
	v := ToolSettingsView{Tool: ts.tool, SchemaDigest: ts.schema.Digest(), Schema: ts.schema.Raw, Values: map[string]any{}}
	if len(org) > 0 {
		v.Organization = org
		var errs settings.Errors
		if err := sensordom.ValidateTenantToolSettings(ts.schema, org); errors.As(err, &errs) {
			v.OrganizationProblems = errs
		}
	}
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
	if err := s.requireImpactStepUp(ctx, ts.schema, before, values, in.AuditContext); err != nil {
		return nil, err
	}
	org, err := s.orgToolValues(ctx, *a.TenantID)
	if err != nil {
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
	v := toolSettingsView(*ts, &row, org[ts.tool])
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
// value a job of this sensor runs with (before the scan's own layer), where
// it comes from (default, the organization, the sensor) and the chain of
// layers that set it.
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
	org, err := s.orgToolValues(ctx, *a.TenantID)
	if err != nil {
		return nil, nil, err
	}
	view := toolSettingsView(*ts, row, org[ts.tool])
	if len(view.Problems) > 0 {
		return nil, &view, view.Problems
	}
	if len(view.OrganizationProblems) > 0 {
		return nil, &view, view.OrganizationProblems
	}
	eff, err := sensordom.EffectiveToolSettings(ts.schema, view.admin())
	if err != nil {
		return nil, &view, err
	}
	return eff, &view, nil
}

// admin is the view's administrators' values: the organization's defaults
// and the sensor's own.
func (v ToolSettingsView) admin() sensordom.AdminValues {
	return sensordom.AdminValues{Organization: v.Organization, Sensor: v.Values}
}

// ToolSettingsLayers are the administrators' layers of a job of tool
// claimed by sensorID: the organization's defaults the sensor inherits
// (without the keys it overrides; only for the tenant's own sensors, never
// a shared platform sensor) and the sensor's own values, each nil when
// empty, checked against the schema of the sensor's current manifest.
// Values that no longer validate are an error wrapping
// sensordom.ErrToolSettingsInvalid (the job is failed with it, never run
// without them). Other errors are transient.
func (s *SensorService) ToolSettingsLayers(ctx context.Context, tenantID, sensorID shared.ID, tool string) (tenant, sensor map[string]any, err error) {
	store, ok := s.toolSettingsStore()
	if !ok {
		return nil, nil, nil
	}
	row, err := store.GetToolSettings(ctx, tenantID, sensorID, tool)
	switch {
	case errors.Is(err, shared.ErrNotFound):
		row = nil
	case err != nil:
		return nil, nil, err
	}
	var org map[string]any
	if own, err := s.ownSensor(ctx, tenantID, sensorID); err != nil {
		return nil, nil, err
	} else if own {
		vals, err := s.orgToolValues(ctx, tenantID)
		if err != nil {
			return nil, nil, err
		}
		org = vals[tool]
	}
	if row != nil && len(row.Values) > 0 {
		sensor = row.Values
	}
	if len(sensor) == 0 && len(org) == 0 {
		return nil, nil, nil
	}
	mstore, ok := s.manifestStore()
	if !ok {
		return nil, nil, fmt.Errorf("%w: no manifest store", sensordom.ErrToolSettingsInvalid)
	}
	mv, err := mstore.CurrentManifest(ctx, &tenantID, sensorID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, nil, fmt.Errorf("%w: the sensor reports no manifest", sensordom.ErrToolSettingsInvalid)
	}
	if err != nil {
		return nil, nil, err
	}
	schema, err := sensordom.ToolSettingsSchema(mv.Manifest.ToolDescriptor(tool))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", sensordom.ErrToolSettingsInvalid, err)
	}
	if schema == nil {
		return nil, nil, fmt.Errorf("%w: the sensor's %s no longer declares settings", sensordom.ErrToolSettingsInvalid, tool)
	}
	if len(sensor) > 0 && schema.Digest() != row.SchemaDigest {
		if err := sensordom.ValidateToolSettings(schema, sensor); err != nil {
			return nil, nil, fmt.Errorf("%w: %w", sensordom.ErrToolSettingsInvalid, err)
		}
	}
	if len(org) > 0 {
		if err := sensordom.ValidateTenantToolSettings(schema, org); err != nil {
			return nil, nil, fmt.Errorf("%w: the organization's %s defaults do not fit this sensor: %w", sensordom.ErrToolSettingsInvalid, tool, err)
		}
	}
	return sensordom.InheritedValues(org, sensor), sensor, nil
}

// ownSensor reports whether sensorID is one of the tenant's own sensors (not
// a shared platform sensor): only those receive the organization's tool
// defaults.
func (s *SensorService) ownSensor(ctx context.Context, tenantID, sensorID shared.ID) (bool, error) {
	a, err := s.repo.GetByTenantAndID(ctx, tenantID, sensorID)
	if errors.Is(err, shared.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return a.TenantID != nil && a.TenantID.Equals(tenantID) && !a.IsShared(), nil
}

// ToolSettingsPreview is what a job of a scan with config runs with on a
// sensor: every key with its value and source (default, sensor or scan),
// before the job's own limits and the sensor's local policy (both only
// lower values). Ignored lists the config keys the sensor would ignore.
type ToolSettingsPreview struct {
	View      ToolSettingsView
	Effective []sensordom.EffectiveToolSetting
	Ignored   []string
}

// PreviewToolSettings resolves a scan's config (its scan layer) over the
// organization's defaults and the sensor's stored settings for tool, as the
// sensor will. A config the
// sensor would refuse (a sensor-scope key, a value out of bounds, a raise
// above the value in force, a dangerous option) is settings.Errors; stored
// values that no longer validate are the view's problems.
func (s *SensorService) PreviewToolSettings(ctx context.Context, tenantID, sensorID, tool string, config map[string]any) (*ToolSettingsPreview, error) {
	_, view, err := s.EffectiveToolSettings(ctx, tenantID, sensorID, tool)
	if err != nil {
		return nil, err
	}
	_, _, ts, err := s.toolSettingsSensor(ctx, tenantID, sensorID, tool)
	if err != nil {
		return nil, err
	}
	layer, ignored := sensordom.ScanSettingsLayer(ts.schema, config)
	if err := sensordom.ValidateScanSettings(ts.schema, view.admin(), layer); err != nil {
		return nil, err
	}
	eff, err := sensordom.EffectiveToolSettingsWithScan(ts.schema, view.admin(), layer)
	if err != nil {
		return nil, err
	}
	return &ToolSettingsPreview{View: *view, Effective: eff, Ignored: ignored}, nil
}

// maxScanConfigSensors bounds how many of the tenant's sensors one scan's
// tool config is checked against.
const maxScanConfigSensors = 50

// CheckScanToolConfig checks the config of a scan (or of a workflow step
// pinned to tool) against the tenant's own sensors whose current manifest
// declares settings for tool: the scan layer over the organization's
// defaults and each sensor's stored values, as that sensor will resolve it. It refuses (shared.ErrValidation
// with the first sensor's problems) only when no such sensor accepts it, so
// one stale sensor does not block a scan the others run. No such sensor
// (the tool runs on platform sensors only, or has no settings): nil.
func (s *SensorService) CheckScanToolConfig(ctx context.Context, tenantID shared.ID, tool string, config map[string]any) error {
	name := sensordom.NormalizeToolName(tool)
	store, ok := s.toolSettingsStore()
	if name == "" || len(config) == 0 || !ok {
		return nil
	}
	mstore, ok := s.manifestStore()
	if !ok {
		return nil
	}
	sensors, err := s.repo.FindByCapabilities(ctx, tenantID, nil, name)
	if err != nil {
		return err
	}
	org, err := s.orgToolValues(ctx, tenantID)
	if err != nil {
		return err
	}
	var first error
	checked := 0
	for _, a := range sensors {
		if a.TenantID == nil || a.IsShared() || !a.TenantID.Equals(tenantID) {
			continue
		}
		if checked == maxScanConfigSensors {
			break
		}
		mv, err := mstore.CurrentManifest(ctx, &tenantID, a.ID)
		if errors.Is(err, shared.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		schema, err := sensordom.ToolSettingsSchema(mv.Manifest.ToolDescriptor(name))
		if err != nil || schema == nil {
			continue
		}
		checked++
		var values map[string]any
		row, err := store.GetToolSettings(ctx, tenantID, a.ID, name)
		switch {
		case err == nil:
			values = row.Values
		case !errors.Is(err, shared.ErrNotFound):
			return err
		}
		layer, _ := sensordom.ScanSettingsLayer(schema, config)
		err = sensordom.ValidateScanSettings(schema, sensordom.AdminValues{Organization: org[name], Sensor: values}, layer)
		if err == nil {
			return nil
		}
		if first == nil {
			first = fmt.Errorf("%w: %s options are not valid on sensor %q: %w", shared.ErrValidation, name, a.Name, err)
		}
	}
	return first
}
