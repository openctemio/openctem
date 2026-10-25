package scan

import (
	"context"
	"errors"
	"fmt"
	"testing"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// tenantSelector has online sensors only for the tenants listed (with the
// tools listed; "" = any tool), and records every tenant it was asked about.
type tenantSelector struct {
	stubSelector
	online map[shared.ID]map[string]bool
	asked  map[shared.ID]bool
}

func (s *tenantSelector) CheckSensorAvailability(_ context.Context, tenantID shared.ID, tool string, _ bool) *SensorAvailability {
	s.asked[tenantID] = true
	tools := s.online[tenantID]
	ok := tools != nil && (tool == "" || tools[tool])
	return &SensorAvailability{Available: ok, HasTenantSensor: ok}
}

// tenantAvailability answers tool availability per tenant.
type tenantAvailability struct {
	byTenant map[shared.ID]map[string]*sensordom.ToolAvailability
	asked    map[shared.ID]bool
}

func (f *tenantAvailability) ToolAvailabilityFor(_ context.Context, tenantID shared.ID, _ *shared.ID, name string) (*sensordom.ToolAvailability, error) {
	f.asked[tenantID] = true
	return f.byTenant[tenantID][name], nil
}

func toolOf(t *testing.T, capability string) string {
	t.Helper()
	st, ok := stage.Lookup(stage.Key(capability))
	if !ok || st.DefaultTool() == "" {
		t.Fatalf("%s has no stage tool", capability)
	}
	return st.DefaultTool()
}

func TestCoverageReadiness_EachReason(t *testing.T) {
	ctx := context.Background()
	const capability = "probe.http"
	tool := toolOf(t, capability)
	tenant := shared.NewID()
	for name, c := range map[string]struct {
		ta     *sensordom.ToolAvailability
		online map[string]bool
		want   string
	}{
		"ready":             {&sensordom.ToolAvailability{Status: sensordom.ToolReady, SensorsTotal: 1, SensorsOnline: 1}, map[string]bool{tool: true}, ""},
		"tool switched off": {&sensordom.ToolAvailability{Status: sensordom.ToolDisabled}, map[string]bool{tool: true}, covdom.ReadyPolicyDisabled},
		"offline only":      {&sensordom.ToolAvailability{Status: sensordom.ToolOfflineOnly, SensorsTotal: 2}, map[string]bool{"other": true}, covdom.ReadySensorOffline},
		"outdated":          {&sensordom.ToolAvailability{Status: sensordom.ToolOutdated, SensorsTotal: 1, SensorsOnline: 1}, map[string]bool{tool: true}, covdom.ReadySensorOutdated},
		"excluded by policy": {&sensordom.ToolAvailability{Status: sensordom.ToolNoSensor, SensorsExcluded: 1}, map[string]bool{"other": true},
			covdom.ReadyToolNotAllowed},
		"no sensor at all":         {&sensordom.ToolAvailability{Status: sensordom.ToolNoSensor}, nil, covdom.ReadyNoEligibleSensor},
		"sensors without the tool": {&sensordom.ToolAvailability{Status: sensordom.ToolNoSensor}, map[string]bool{"other": true}, covdom.ReadyToolMissing},
		// Availability says ready, but the trigger's sensor check finds no
		// online sensor with the tool (it went offline in between).
		"ready but none online": {&sensordom.ToolAvailability{Status: sensordom.ToolReady, SensorsTotal: 1, SensorsOnline: 1}, map[string]bool{"other": true},
			covdom.ReadySensorOffline},
		// No availability answer (tool not in the catalog): the sensor check
		// alone decides.
		"unknown, no sensor": {nil, nil, covdom.ReadyNoEligibleSensor},
		"unknown, sensor":    {nil, map[string]bool{tool: true}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			avail := &tenantAvailability{asked: map[shared.ID]bool{},
				byTenant: map[shared.ID]map[string]*sensordom.ToolAvailability{tenant: {tool: c.ta}}}
			sel := &tenantSelector{asked: map[shared.ID]bool{}, online: map[shared.ID]map[string]bool{}}
			if c.online != nil {
				sel.online[tenant] = c.online
			}
			s := &Service{toolAvailability: avail, sensorSelector: sel, logger: logger.NewNop()}
			if got := s.CoverageReadiness(ctx, tenant, []string{capability})[capability]; got != c.want {
				t.Fatalf("readiness = %q, want %q", got, c.want)
			}
		})
	}
}

// Tenant isolation: another tenant's sensors and tools never make a tenant
// ready, and only the tenant's own sources are read.
func TestCoverageReadiness_OtherTenantsSensorsNeverCount(t *testing.T) {
	ctx := context.Background()
	const capability = "resolve.dns"
	tool := toolOf(t, capability)
	a, b := shared.NewID(), shared.NewID()
	avail := &tenantAvailability{asked: map[shared.ID]bool{}, byTenant: map[shared.ID]map[string]*sensordom.ToolAvailability{
		a: {tool: {Status: sensordom.ToolReady, SensorsTotal: 1, SensorsOnline: 1}},
	}}
	sel := &tenantSelector{asked: map[shared.ID]bool{}, online: map[shared.ID]map[string]bool{a: {tool: true}}}
	s := &Service{toolAvailability: avail, sensorSelector: sel, logger: logger.NewNop()}

	if got := s.CoverageReadiness(ctx, a, []string{capability})[capability]; got != "" {
		t.Fatalf("tenant a = %q, want ready", got)
	}
	avail.asked, sel.asked = map[shared.ID]bool{}, map[shared.ID]bool{}
	if got := s.CoverageReadiness(ctx, b, []string{capability})[capability]; got != covdom.ReadyNoEligibleSensor {
		t.Fatalf("tenant b = %q, want no_eligible_sensor (a's sensor must not count)", got)
	}
	if avail.asked[a] || sel.asked[a] {
		t.Fatal("tenant b's readiness read tenant a's sensors")
	}
}

// A capability that is not a stage gets no reason (the planner never plans one).
func TestCoverageReadiness_UnknownCapabilityIgnored(t *testing.T) {
	s := &Service{logger: logger.NewNop()}
	got := s.CoverageReadiness(context.Background(), shared.NewID(), []string{"not.a_stage"})
	if _, ok := got["not.a_stage"]; ok {
		t.Fatalf("unknown capability got a reason: %v", got)
	}
}

func TestCoverageReadinessForRefusal(t *testing.T) {
	de := func(code string) error {
		return fmt.Errorf("failed to trigger coverage: %w", shared.NewDomainError(code, "x", shared.ErrValidation))
	}
	tu := func(status string, excluded int) error {
		return fmt.Errorf("wrapped: %w", &ToolUnavailableError{
			Domain: shared.NewDomainError(CodeNoSensorForTool, "x", shared.ErrValidation), Status: status, SensorsExcluded: excluded})
	}
	for name, c := range map[string]struct {
		err  error
		want string
	}{
		"tool offline":           {tu(string(sensordom.ToolOfflineOnly), 0), covdom.ReadySensorOffline},
		"tool excluded":          {tu(string(sensordom.ToolNoSensor), 2), covdom.ReadyToolNotAllowed},
		"tool on no sensor":      {tu(string(sensordom.ToolNoSensor), 0), covdom.ReadyToolMissing},
		"no sensor available":    {de("NO_SENSOR_AVAILABLE"), covdom.ReadyNoEligibleSensor},
		"no zone coverage":       {de("NO_ZONE_COVERAGE"), covdom.ReadyNoEligibleSensor},
		"shared sensors refused": {de(codePlatformRefused), covdom.ReadyNoEligibleSensor},
		"sensor policy":          {de(codeSensorPolicyRefused), covdom.ReadyToolNotAllowed},
		"tool disabled":          {de("TOOL_DISABLED"), covdom.ReadyPolicyDisabled},
		"approval":               {de("SCAN_APPROVAL_REQUIRED"), covdom.ReadyPolicyDisabled},
		"window never opens":     {de(CodeWindowNeverOpens), covdom.ReadyPolicyDisabled},
		"scan paused":            {de("SCAN_NOT_TRIGGERABLE"), covdom.ReadyPolicyDisabled},
		// About the batch's targets: handled per batch, not a readiness.
		"targets excluded": {de("ALL_TARGETS_EXCLUDED"), ""},
		"no targets":       {de("NO_TARGETS"), ""},
		"not a refusal":    {errors.New("connection reset"), ""},
	} {
		if got := CoverageReadinessForRefusal(c.err); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

type countingRunRepo struct {
	scanrun.RunRepository
	created int
}

func (r *countingRunRepo) Create(context.Context, *scanrun.Run) error { r.created++; return nil }

type summaryOnlyScans struct{ scan.Repository }

func (summaryOnlyScans) RefreshRunSummary(context.Context, shared.ID, shared.ID) error { return nil }

// A coverage trigger's refusal is returned without a blocked run; any other
// trigger's refusal is still recorded as one.
func TestTriggerAndRecord_NoBlockedRunForCoverage(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	sc, err := scan.NewScan(tenant, "Continuous coverage: resolve.dns", shared.ID{}, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.Status = scan.StatusDisabled // refused before anything else is read
	runs := &countingRunRepo{}
	s := &Service{runRepo: runs, scanRepo: summaryOnlyScans{}, logger: logger.NewNop()}

	_, err = s.triggerAndRecord(ctx, sc, TriggerScanExecInput{TenantID: tenant.String(), ScanID: sc.ID.String(), NoBlockedRun: true})
	if CoverageReadinessForRefusal(err) != covdom.ReadyPolicyDisabled {
		t.Fatalf("err = %v, want a policy refusal", err)
	}
	if runs.created != 0 {
		t.Fatalf("%d blocked runs recorded for a coverage trigger", runs.created)
	}
	if _, err = s.triggerAndRecord(ctx, sc, TriggerScanExecInput{TenantID: tenant.String(), ScanID: sc.ID.String()}); err == nil {
		t.Fatal("disabled scan triggered")
	}
	if runs.created != 1 {
		t.Fatalf("blocked runs = %d, want 1 for a normal trigger", runs.created)
	}
}
