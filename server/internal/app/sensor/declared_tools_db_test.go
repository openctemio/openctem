package sensor_test

// Declared tools against a migrated database: a tool a sensor declares with a
// valid contract joins its organization's catalog and is kept in the
// manifest; nothing crosses organizations, shadows a platform tool or
// overwrites a member's own tool. Requires DATABASE_URL.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// declaredToolJSON is one manifest tool entry with a contract whose
// descriptor hashes to its digest.
func declaredToolJSON(t *testing.T, name, version, display string) string {
	t.Helper()
	desc := fmt.Sprintf(`{"apiVersion":"openctem.io/tool/v1","name":%q,"version":%q,"description":"Checks web origins.",`+
		`"presentation":{"display_name":%q,"category":"web","icon":"shield"},"class":"target-scan","tier":"T2",`+
		`"implements":[{"capability":"dast.web@1"}],"consumes":["http_service"],"produces":["finding:misconfiguration"],`+
		`"config":{"type":"object","additionalProperties":false,"properties":{"request_timeout":{"type":"integer","minimum":1,"maximum":60}}}}`,
		name, version, display)
	sum := sha256.Sum256([]byte(desc))
	contract := map[string]any{
		"api_version": "openctem.io/tool/v1", "digest": "sha256:" + hex.EncodeToString(sum[:]), "version": version,
		"class": "target-scan", "tier": "T2", "network": "targets", "consumes": []string{"http_service"},
		"produces": []string{"finding:misconfiguration"}, "implements": []string{"dast.web@1"},
		"origin": "adapter", "descriptor": json.RawMessage(desc),
	}
	b, err := json.Marshal(map[string]any{"name": name, "kind": "scanner", "version": version, "installed": true,
		"capabilities": []string{}, "contract": contract})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDeclaredToolsJoinTheCatalog_DB(t *testing.T) {
	h := newActivityHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	tools := postgres.NewToolRepository(db)
	svc := sensorapp.NewSensorService(postgres.NewSensorRepository(db), nil, logger.NewNop())
	svc.SetDeclaredTools(tools)

	tenantA, tenantB := h.tenant(), h.tenant()
	// A member of A already has a tool named "mytool".
	own, err := tooldom.NewTenantCustomTool(tenantA, shared.ID{}, "mytool", "Mine", nil, tooldom.InstallBinary)
	if err != nil {
		t.Fatal(err)
	}
	if err := tools.Create(ctx, own); err != nil {
		t.Fatal(err)
	}

	sensorID := h.sensor(tenantA)
	a, err := svc.GetSensor(ctx, tenantA.String(), sensorID.String())
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"schema":1,"tools":[` +
		declaredToolJSON(t, "toyweb-it", "0.1.0", "Toy web checker") + `,` +
		declaredToolJSON(t, "nuclei", "9.9.9", "Not the platform nuclei") + `,` +
		declaredToolJSON(t, "mytool", "1.0.0", "Overwrite attempt") + `,` +
		`{"name":"nocontract-it","kind":"scanner","version":"1.0.0","installed":true}]}`
	res, err := svc.RegisterManifest(ctx, a, []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.AcceptedTools, "toyweb-it") {
		t.Fatalf("a declared tool is kept in the manifest: accepted %v ignored %+v", res.AcceptedTools, res.Ignored)
	}
	if slices.Contains(res.AcceptedTools, "nocontract-it") {
		t.Fatal("a tool without a contract still needs the catalog")
	}

	row, err := tools.GetByName(ctx, tenantA, "toyweb-it")
	if err != nil {
		t.Fatal(err)
	}
	if !row.IsDeclared() || row.TenantID == nil || *row.TenantID != tenantA || row.DisplayName != "Toy web checker" ||
		!slices.Equal(row.Capabilities, []string{"dast.web"}) || row.IsBuiltin {
		t.Fatalf("declared row %+v", row)
	}
	if props, _ := row.ConfigSchema["properties"].(map[string]any); props["request_timeout"] == nil {
		t.Fatalf("the settings schema is the descriptor's: %v", row.ConfigSchema)
	}

	// A declared row has no install method; the catalog lists still read it.
	page, err := postgres.NewTenantToolConfigRepository(db).ListToolsWithConfig(ctx, tenantA, tooldom.ToolFilter{}, pagination.New(1, 200))
	if err != nil || !slices.ContainsFunc(page.Data, func(w *tooldom.ToolWithConfig) bool { return w.Tool.Name == "toyweb-it" }) {
		t.Fatalf("catalog with settings: %v", err)
	}
	if _, err := tools.ListAvailableTools(ctx, tenantA, tooldom.ToolFilter{}, pagination.New(1, 200)); err != nil {
		t.Fatalf("available tools: %v", err)
	}

	// Another organization does not see it.
	if _, err := tools.GetByName(ctx, tenantB, "toyweb-it"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-organization read: %v", err)
	}
	// A platform tool's name is never taken by a declaration.
	if _, err := tools.GetByTenantAndName(ctx, tenantA, "nuclei"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a declaration shadowed the platform tool: %v", err)
	}
	// A member's own tool is never overwritten.
	mine, err := tools.GetByTenantAndName(ctx, tenantA, "mytool")
	if err != nil || mine.IsDeclared() || mine.DisplayName != "Mine" {
		t.Fatalf("member's tool: %+v %v", mine, err)
	}

	// A sensor that is not active declares nothing.
	off := h.sensor(tenantA)
	h.exec(`UPDATE sensors SET status = 'disabled' WHERE id = $1`, off.String())
	b, err := svc.GetSensor(ctx, tenantA.String(), off.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = svc.RegisterManifest(ctx, b, []byte(`{"schema":1,"tools":[`+declaredToolJSON(t, "from-disabled", "1.0.0", "X")+`]}`))
	if _, err := tools.GetByName(ctx, tenantA, "from-disabled"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a disabled sensor declared a tool: %v", err)
	}

	// A newer version refreshes the row; an older one does not.
	raw2 := `{"schema":1,"tools":[` + declaredToolJSON(t, "toyweb-it", "0.2.0", "Toy web checker 2") + `]}`
	if _, err := svc.RegisterManifest(ctx, a, []byte(raw2)); err != nil {
		t.Fatal(err)
	}
	raw3 := `{"schema":1,"tools":[` + declaredToolJSON(t, "toyweb-it", "0.0.1", "Old") + `]}`
	if _, err := svc.RegisterManifest(ctx, a, []byte(raw3)); err != nil {
		t.Fatal(err)
	}
	row, _ = tools.GetByName(ctx, tenantA, "toyweb-it")
	if row.DisplayName != "Toy web checker 2" || row.CurrentVersion != "0.2.0" {
		t.Fatalf("refresh: %q %q", row.DisplayName, row.CurrentVersion)
	}
}

// The organization holds at most MaxDeclaredToolsPerTenant declared tools.
func TestDeclaredToolsAreBounded_DB(t *testing.T) {
	h := newActivityHarness(t)
	ctx := context.Background()
	tools := postgres.NewToolRepository(&postgres.DB{DB: h.db})
	tenant := h.tenant()
	for i := 0; i < tooldom.MaxDeclaredToolsPerTenant; i++ {
		tl, err := tooldom.NewDeclaredTool(tenant, tooldom.Declaration{Name: fmt.Sprintf("bulk-%d", i), Digest: "sha256:x"})
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := tools.CreateDeclared(ctx, tl); err != nil || !ok {
			t.Fatalf("declared %d: %v %v", i, ok, err)
		}
	}
	tl, _ := tooldom.NewDeclaredTool(tenant, tooldom.Declaration{Name: "one-too-many", Digest: "sha256:x"})
	if ok, err := tools.CreateDeclared(ctx, tl); err != nil || ok {
		t.Fatalf("over the bound: %v %v", ok, err)
	}
}

// declaredToolJSONWithParams is declaredToolJSON whose descriptor maps the
// standard param max_duration_minutes of dast.web@1 to its key "minutes".
func declaredToolJSONWithParams(t *testing.T, name string) string {
	t.Helper()
	desc := fmt.Sprintf(`{"apiVersion":"openctem.io/tool/v1","name":%q,"version":"1.0.0","description":"Checks web origins.",`+
		`"class":"target-scan","tier":"T2",`+
		`"implements":[{"capability":"dast.web@1","params":{"max_duration_minutes":{"key":"minutes"}}}],`+
		`"consumes":["http_service"],"produces":["finding:misconfiguration"],`+
		`"config":{"type":"object","additionalProperties":false,"properties":{"minutes":{"type":"integer","minimum":1,"maximum":60,"x-octm-scope":"scan"}}}}`,
		name)
	sum := sha256.Sum256([]byte(desc))
	contract := map[string]any{
		"api_version": "openctem.io/tool/v1", "digest": "sha256:" + hex.EncodeToString(sum[:]), "version": "1.0.0",
		"class": "target-scan", "tier": "T2", "network": "targets", "consumes": []string{"http_service"},
		"produces": []string{"finding:misconfiguration"}, "implements": []string{"dast.web@1"},
		"origin": "adapter", "descriptor": json.RawMessage(desc),
	}
	b, err := json.Marshal(map[string]any{"name": name, "kind": "scanner", "version": "1.0.0", "installed": true,
		"capabilities": []string{}, "contract": contract})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A declared tool runs a capability step of its organization, through the
// real catalog: its param mapping survives the metadata column, a step's
// standard param reaches it under its own key, and another organization's
// step never resolves to it.
func TestDeclaredToolRunsACapabilityStep_DB(t *testing.T) {
	h := newActivityHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	tools := postgres.NewToolRepository(db)
	svc := sensorapp.NewSensorService(postgres.NewSensorRepository(db), nil, logger.NewNop())
	svc.SetDeclaredTools(tools)

	tenantA, tenantB := h.tenant(), h.tenant()
	a, err := svc.GetSensor(ctx, tenantA.String(), h.sensor(tenantA).String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterManifest(ctx, a, []byte(`{"schema":1,"tools":[`+declaredToolJSONWithParams(t, "toyweb-cap")+`]}`)); err != nil {
		t.Fatal(err)
	}

	step := func() *scanworkflow.Step {
		return &scanworkflow.Step{ID: shared.NewID(), StepKey: "dast", Capabilities: []string{"dast.web"},
			PreferTools: []string{"toyweb-cap"}, Config: map[string]any{"max_duration_minutes": 30}}
	}
	got, err := scanapp.ResolveStepTool(ctx, tools, tenantA, step())
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "toyweb-cap" || !got.Declared || got.Capability() != "dast.web@1" {
		t.Fatalf("resolved %+v", got)
	}
	if cfg := got.WithTool(step()).Config; cfg["minutes"] != 30 || cfg["max_duration_minutes"] != nil {
		t.Fatalf("config %v, want the standard param under the tool's key", cfg)
	}

	// Another organization: its step cannot resolve to A's tool.
	if _, err := scanapp.ResolveStepTool(ctx, tools, tenantB, step()); err == nil {
		t.Fatal("another organization's step resolved to A's declared tool")
	}
	// Switched off, the tool is not a candidate any more.
	h.exec(`UPDATE tools SET is_active = false WHERE tenant_id = $1 AND name = 'toyweb-cap'`, tenantA.String())
	if _, err := scanapp.ResolveStepTool(ctx, tools, tenantA, step()); err == nil {
		t.Fatal("a switched-off declared tool was picked")
	}
}
