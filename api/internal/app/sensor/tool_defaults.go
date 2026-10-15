package sensor

// Organization tool defaults (docs/architecture/sensors.md, "Tool
// settings"): per tool, the values every one of the organization's own
// sensors runs the tool with unless the sensor overrides a key in its own
// tool settings. The defaults are validated against every settings schema
// the organization's sensors report for the tool (a key one sensor's tool
// version does not know would fail that sensor's jobs), audited, and
// delivered inside each signed job as the tenant layer, without the keys the
// claiming sensor overrides (ToolSettingsLayers). Shared platform sensors
// never receive them.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/ctis/settings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// maxToolDefaultsSensors bounds how many sensors' schemas one tool's
// defaults are checked against.
const maxToolDefaultsSensors = 200

// ToolDefaultsView is one tool's organization defaults: the reference schema
// (from the most recently reported manifest that declares settings for the
// tool), the stored values, how many of the organization's sensors declare
// settings for the tool, and the sensors whose schema refuses the values.
type ToolDefaultsView struct {
	Tool         string
	SchemaDigest string
	// Schema is nil for stored defaults of a tool no sensor reports any
	// more (they can only be reset).
	Schema    json.RawMessage
	Values    map[string]any
	Stored    bool
	Sensors   int
	Problems  []ToolDefaultsProblem
	UpdatedAt *time.Time
	UpdatedBy *shared.ID
}

// ToolDefaultsProblem is why the defaults do not validate against one
// sensor's schema of the tool; that sensor's jobs of the tool fail until
// the defaults change or the sensor overrides nothing that no longer fits.
type ToolDefaultsProblem struct {
	SensorID   shared.ID
	SensorName string
	Errors     settings.Errors
}

// UpdateToolDefaultsInput replaces one tool's organization defaults.
type UpdateToolDefaultsInput struct {
	TenantID     shared.ID
	Tool         string
	Values       map[string]any
	AuditContext *auditapp.AuditContext
}

// sensorSchema is the settings schema one sensor's current manifest
// declares for a tool.
type sensorSchema struct {
	sensorID shared.ID
	schema   *settings.Schema
	since    time.Time
}

type tenantManifests interface {
	CurrentManifestsByTenant(ctx context.Context, tenantID shared.ID) (map[shared.ID]*sensordom.ManifestVersion, error)
}

func (s *SensorService) tenantToolSettingsStore() (sensordom.TenantToolSettingsStore, bool) {
	store, ok := s.repo.(sensordom.TenantToolSettingsStore)
	return store, ok
}

// orgToolValues returns the organization's defaults by tool (empty when it
// has none or no store is wired).
func (s *SensorService) orgToolValues(ctx context.Context, tenantID shared.ID) (map[string]map[string]any, error) {
	store, ok := s.tenantToolSettingsStore()
	if !ok {
		return map[string]map[string]any{}, nil
	}
	rows, err := store.ListTenantToolSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]any, len(rows))
	for _, r := range rows {
		if len(r.Values) > 0 {
			out[r.Tool] = r.Values
		}
	}
	return out, nil
}

// tenantToolSchemas returns, per tool, the settings schema each of the
// tenant's own sensors (never a platform sensor) declares in its current
// manifest, newest manifest first.
func (s *SensorService) tenantToolSchemas(ctx context.Context, tenantID shared.ID) (map[string][]sensorSchema, error) {
	out := map[string][]sensorSchema{}
	store, ok := s.repo.(tenantManifests)
	if !ok {
		return out, nil
	}
	manifests, err := store.CurrentManifestsByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for sid, mv := range manifests {
		for _, t := range mv.Manifest.Tools {
			if t.Contract == nil || len(t.Contract.Descriptor) == 0 {
				continue
			}
			name := sensordom.NormalizeToolName(t.Name)
			if name == "" {
				continue
			}
			schema, err := sensordom.ToolSettingsSchema(t.Contract.Descriptor)
			if err != nil || schema == nil {
				continue
			}
			out[name] = append(out[name], sensorSchema{sensorID: sid, schema: schema, since: mv.CurrentSince})
		}
	}
	for name := range out {
		list := out[name]
		sort.SliceStable(list, func(i, j int) bool {
			if !list[i].since.Equal(list[j].since) {
				return list[i].since.After(list[j].since)
			}
			return list[i].sensorID.String() < list[j].sensorID.String()
		})
		if len(list) > maxToolDefaultsSensors {
			list = list[:maxToolDefaultsSensors]
		}
		out[name] = list
	}
	return out, nil
}

// checkDefaults validates values against each distinct schema of the tool
// (one sensor per schema digest is enough) and returns the problems by
// sensor.
func (s *SensorService) checkDefaults(ctx context.Context, tenantID shared.ID, schemas []sensorSchema, values map[string]any) []ToolDefaultsProblem {
	if len(values) == 0 {
		return nil
	}
	out := make([]ToolDefaultsProblem, 0, len(schemas))
	seen := map[string]bool{}
	for _, ss := range schemas {
		d := ss.schema.Digest()
		if seen[d] {
			continue
		}
		seen[d] = true
		var errs settings.Errors
		if err := sensordom.ValidateTenantToolSettings(ss.schema, values); !errors.As(err, &errs) {
			continue
		}
		p := ToolDefaultsProblem{SensorID: ss.sensorID, Errors: errs}
		if a, err := s.repo.GetByTenantAndID(ctx, tenantID, ss.sensorID); err == nil {
			p.SensorName = a.Name
		}
		out = append(out, p)
	}
	return out
}

// ListToolDefaults returns every tool that a current manifest of the
// organization's own sensors declares settings for, by name, with the
// organization's defaults; stored defaults of a tool no sensor reports any
// more come last, without a schema.
func (s *SensorService) ListToolDefaults(ctx context.Context, tenantID shared.ID) ([]ToolDefaultsView, error) {
	store, ok := s.tenantToolSettingsStore()
	if !ok {
		return nil, shared.ErrNotFound
	}
	schemas, err := s.tenantToolSchemas(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := store.ListTenantToolSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	byTool := make(map[string]*sensordom.TenantToolSettings, len(rows))
	for i := range rows {
		byTool[rows[i].Tool] = &rows[i]
	}
	names := make([]string, 0, len(schemas))
	for name := range schemas {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]ToolDefaultsView, 0, len(names)+len(rows))
	for _, name := range names {
		out = append(out, s.toolDefaultsView(ctx, tenantID, name, schemas[name], byTool[name]))
	}
	for i := range rows {
		if _, ok := schemas[rows[i].Tool]; !ok {
			out = append(out, s.toolDefaultsView(ctx, tenantID, rows[i].Tool, nil, &rows[i]))
		}
	}
	return out, nil
}

func (s *SensorService) toolDefaultsView(ctx context.Context, tenantID shared.ID, tool string, schemas []sensorSchema, row *sensordom.TenantToolSettings) ToolDefaultsView {
	v := ToolDefaultsView{Tool: tool, Values: map[string]any{}, Sensors: len(schemas)}
	if len(schemas) > 0 {
		v.SchemaDigest, v.Schema = schemas[0].schema.Digest(), schemas[0].schema.Raw
	}
	if row == nil {
		return v
	}
	v.Stored, v.UpdatedBy = true, row.UpdatedBy
	at := row.UpdatedAt
	v.UpdatedAt = &at
	if row.Values != nil {
		v.Values = row.Values
	}
	v.Problems = s.checkDefaults(ctx, tenantID, schemas, row.Values)
	return v
}

// UpdateToolDefaults validates and stores one tool's organization defaults
// and audits the change. The values must validate against every schema the
// organization's sensors report for the tool; otherwise the error is
// settings.Errors whose messages name the first sensor that refuses each
// value. Changing an Impact (T1) option needs the acting user's recent
// re-authentication.
func (s *SensorService) UpdateToolDefaults(ctx context.Context, in UpdateToolDefaultsInput) (*ToolDefaultsView, error) {
	store, ok := s.tenantToolSettingsStore()
	if !ok {
		return nil, shared.ErrNotFound
	}
	name := sensordom.NormalizeToolName(in.Tool)
	if name == "" {
		return nil, sensordom.ErrToolHasNoSettings
	}
	all, err := s.tenantToolSchemas(ctx, in.TenantID)
	if err != nil {
		return nil, err
	}
	schemas := all[name]
	if len(schemas) == 0 {
		return nil, sensordom.ErrToolHasNoSettings
	}
	values := in.Values
	if values == nil {
		values = map[string]any{}
	}
	if problems := s.checkDefaults(ctx, in.TenantID, schemas, values); len(problems) > 0 {
		return nil, defaultsErrors(problems)
	}
	var before map[string]any
	if prev, err := store.GetTenantToolSettings(ctx, in.TenantID, name); err == nil {
		before = prev.Values
	} else if !errors.Is(err, shared.ErrNotFound) {
		return nil, err
	}
	ref := schemas[0].schema
	if err := s.requireImpactStepUp(ctx, ref, before, values, in.AuditContext); err != nil {
		return nil, err
	}
	row := sensordom.TenantToolSettings{TenantID: in.TenantID, Tool: name, Values: values,
		SchemaDigest: ref.Digest(), UpdatedAt: s.now().UTC()}
	if in.AuditContext != nil {
		if id, err := shared.IDFromString(in.AuditContext.ActorID); err == nil {
			row.UpdatedBy = &id
		}
	}
	if err := store.SaveTenantToolSettings(ctx, row); err != nil {
		return nil, err
	}
	s.auditToolDefaults(ctx, in.TenantID, name, ref, before, values, in.AuditContext)
	v := s.toolDefaultsView(ctx, in.TenantID, name, schemas, &row)
	return &v, nil
}

// ResetToolDefaults removes one tool's organization defaults (every sensor
// back to the tool's defaults, except what it overrides). It works for a
// tool no sensor reports any more.
func (s *SensorService) ResetToolDefaults(ctx context.Context, tenantID shared.ID, tool string, actx *auditapp.AuditContext) error {
	store, ok := s.tenantToolSettingsStore()
	if !ok {
		return shared.ErrNotFound
	}
	name := sensordom.NormalizeToolName(tool)
	if name == "" {
		return sensordom.ErrToolHasNoSettings
	}
	prev, err := store.GetTenantToolSettings(ctx, tenantID, name)
	if errors.Is(err, shared.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	deleted, err := store.DeleteTenantToolSettings(ctx, tenantID, name)
	if err != nil || !deleted {
		return err
	}
	var ref *settings.Schema
	if all, err := s.tenantToolSchemas(ctx, tenantID); err == nil && len(all[name]) > 0 {
		ref = all[name][0].schema
	}
	s.auditToolDefaults(ctx, tenantID, name, ref, prev.Values, nil, actx)
	return nil
}

// defaultsErrors turns per-sensor problems into settings.Errors by path,
// each message naming the sensor that refuses the value.
func defaultsErrors(problems []ToolDefaultsProblem) settings.Errors {
	var out settings.Errors
	seen := map[string]bool{}
	for _, p := range problems {
		who := p.SensorName
		if who == "" {
			who = p.SensorID.String()
		}
		for _, e := range p.Errors {
			if seen[e.Path] {
				continue
			}
			seen[e.Path] = true
			out = append(out, settings.Error{Path: e.Path, Message: fmt.Sprintf("%s (sensor %q)", e.Message, who)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// requireImpactStepUp asks for the acting user's recent re-authentication
// when the change sets an Impact (T1) option to a new value.
func (s *SensorService) requireImpactStepUp(ctx context.Context, schema *settings.Schema, before, after map[string]any, actx *auditapp.AuditContext) error {
	if s.stepUp == nil || len(sensordom.ImpactChanges(schema, before, after)) == 0 {
		return nil
	}
	actor := ""
	if actx != nil {
		actor = actx.ActorID
	}
	return s.stepUp.RequireRecentAuth(ctx, actor)
}

// auditToolDefaults records the change of an organization's tool defaults
// ("tool_settings.<tool>.<key>"); a change to an Impact option is high
// severity. Sensitive and unknown keys are redacted.
func (s *SensorService) auditToolDefaults(ctx context.Context, tenantID shared.ID, tool string, schema *settings.Schema,
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
	keys := make([]string, 0, len(old))
	for k := range old {
		changes.Set("tool_settings."+tool+"."+k, old[k], updated[k])
		keys = append(keys, k)
	}
	sort.Strings(keys)
	severity := audit.SeverityMedium
	if len(sensordom.ImpactChanges(schema, before, after)) > 0 {
		severity = audit.SeverityHigh
	}
	msg := fmt.Sprintf("Organization defaults of %s changed: %s", tool, strings.Join(keys, ", "))
	if after == nil {
		msg = fmt.Sprintf("Organization defaults of %s reset", tool)
	}
	s.logAudit(ctx, *actx, auditapp.NewSuccessEvent(audit.ActionSettingsUpdated, audit.ResourceTypeTenant, tenantID.String()).
		WithResourceName("tool defaults: "+tool).WithChanges(changes).WithMessage(msg).WithSeverity(severity).
		WithMetadata("tool", tool))
}
