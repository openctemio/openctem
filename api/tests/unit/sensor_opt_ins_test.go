package unit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/command"
	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// research/25 D3 and D9: interactsh and custom templates in sensor jobs are
// off for every organization until an owner enables them; enabling is
// audited (critical) and alerted; with them off the platform never sends
// such a job, whatever the sensor's policy allows.

type fixedOptIns struct {
	o   sensor.OptIns
	err error
}

func (f fixedOptIns) SensorOptIns(context.Context, shared.ID) (sensor.OptIns, error) {
	return f.o, f.err
}

// T-P0c: a v0.9.0 sensor without a local policy (legacy: both opt-ins on)
// never receives an interactsh or custom-template command while the
// organization keeps the default (off).
func TestOptIns_DefaultOffWithholdsFromEverySensor(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	absent := &sensor.Sensor{ID: shared.NewID(), TenantID: &tenantID, LocalPolicy: &sensor.LocalPolicyReport{State: sensor.LocalPolicyAbsent}}
	lookup := policySensorLookup{sensors: map[shared.ID]*sensor.Sensor{absent.ID: absent}}

	repo := newCmdMockRepo()
	plain := pendingCmd(repo, tenantID, `{"scanner":"nuclei","target":"203.0.113.9"}`)
	oast := pendingCmd(repo, tenantID, `{"scanner":"nuclei","target":"203.0.113.9","config":{"allow_interactsh":true}}`)
	tmpl := pendingCmd(repo, tenantID, `{"scanner":"nuclei","target":"203.0.113.9","custom_templates":[{"id":"x"}]}`)

	poll := func(svc *command.Service) map[shared.ID]bool {
		cmds, err := svc.Poll(ctx, command.PollInput{TenantID: tenantID.String(), SensorID: absent.ID.String(), Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		got := map[shared.ID]bool{}
		for _, c := range cmds {
			got[c.ID] = true
		}
		return got
	}

	off := command.NewService(repo, newCmdTestLogger(), command.WithSensorLookup(lookup), command.WithOptInPolicy(fixedOptIns{}))
	if got := poll(off); !got[plain.ID] || got[oast.ID] || got[tmpl.ID] {
		t.Fatalf("default off: polled %v, want only the plain job", got)
	}
	if _, err := off.Acknowledge(ctx, tenantID.String(), absent.ID.String(), oast.ID.String()); !errors.Is(err, command.ErrOptInDisabled) ||
		!errors.Is(err, command.ErrCommandClaimed) {
		t.Fatalf("claim by id of the interactsh job: %v", err)
	}
	if repo.commands[oast.ID.String()].Status != commanddom.CommandStatusPending {
		t.Fatal("the refused claim changed the job")
	}

	// The organization enabled interactsh only.
	on := command.NewService(repo, newCmdTestLogger(), command.WithSensorLookup(lookup),
		command.WithOptInPolicy(fixedOptIns{o: sensor.OptIns{AllowInteractsh: true}}))
	if got := poll(on); !got[oast.ID] || got[tmpl.ID] {
		t.Fatalf("interactsh enabled: polled %v", got)
	}

	// Enabled at the organization, refused by the sensor's own policy:
	// still not sent (the platform never widens the sensor).
	absent.LocalPolicy = &sensor.LocalPolicyReport{State: sensor.LocalPolicyEnforced, Summary: &sensor.LocalPolicySummary{TargetsAllow: -1}}
	all := command.NewService(repo, newCmdTestLogger(), command.WithSensorLookup(lookup),
		command.WithOptInPolicy(fixedOptIns{o: sensor.OptIns{AllowInteractsh: true, AllowCustomTemplates: true}}))
	if got := poll(all); got[oast.ID] || got[tmpl.ID] || !got[plain.ID] {
		t.Fatalf("enabled but refused locally: polled %v", got)
	}

	// The switches cannot be read: fail closed.
	broken := command.NewService(repo, newCmdTestLogger(), command.WithSensorLookup(lookup), command.WithOptInPolicy(fixedOptIns{err: errors.New("db down")}))
	if got := poll(broken); got[oast.ID] || got[tmpl.ID] {
		t.Fatalf("unreadable opt-ins: polled %v", got)
	}
}

func newOptInScanService(o scanservice.OptInPolicy) (*scanservice.Service, *testScanServiceDeps) {
	deps := &testScanServiceDeps{
		scanRepo:       newMockScanRepo(),
		templateRepo:   newMockTemplateRepo(),
		assetGroupRepo: newMockAssetGroupRepo(),
		runRepo:        newMockRunRepo(),
		stepRepo:       newMockStepRepo(),
		commandRepo:    newMockCommandRepo(),
		toolRepo:       newMockToolRepo(),
		sensorSelector: &mockSensorSelector{available: true},
		secValidator:   &mockSecurityValidator{},
		auditSvc:       &mockAuditService{},
	}
	svc := scanservice.NewService(deps.scanRepo, deps.templateRepo, deps.assetGroupRepo, deps.runRepo,
		deps.stepRepo, &mockStepRunRepo{}, deps.commandRepo, &mockScannerTemplateRepo{}, &mockTemplateSourceRepo{},
		deps.toolRepo, &mockTemplateSyncer{}, deps.sensorSelector, deps.secValidator, logger.NewNop(),
		allowAllTargetChecks(scanservice.WithAuditService(deps.auditSvc), scanservice.WithOptInPolicy(o))...)
	deps.toolRepo.tools["nuclei"] = &tool.Tool{ID: shared.NewID(), Name: "nuclei", IsActive: true, SupportedTargets: []string{"url", "domain", "ip"}}
	return svc, deps
}

func optInCode(err error) string {
	var de *shared.DomainError
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

func TestOptIns_ScanCreateRefusedWhileOff(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	create := func(svc *scanservice.Service, cfg map[string]any) error {
		_, err := svc.CreateScan(ctx, scanservice.CreateScanInput{TenantID: tenant.String(), Name: "s", ScanType: "single",
			ScannerName: "nuclei", ScannerConfig: cfg, Targets: []string{"203.0.113.5"}})
		return err
	}
	off, _ := newOptInScanService(fixedOptIns{})
	for name, cfg := range map[string]map[string]any{
		"interactsh bool":   {"allow_interactsh": true},
		"interactsh string": {"allow_interactsh": "true"},
		"custom templates":  {"custom_template_ids": []any{shared.NewID().String()}},
	} {
		if err := create(off, cfg); optInCode(err) != "SENSOR_OPT_IN_DISABLED" {
			t.Errorf("%s: err = %v, want SENSOR_OPT_IN_DISABLED", name, err)
		}
	}
	if err := create(off, map[string]any{"allow_interactsh": false, "severity": "high"}); err != nil {
		t.Errorf("a scan without opt-ins: %v", err)
	}
	on, _ := newOptInScanService(fixedOptIns{o: sensor.OptIns{AllowInteractsh: true}})
	if err := create(on, map[string]any{"allow_interactsh": true}); err != nil {
		t.Errorf("interactsh enabled: %v", err)
	}
	broken, _ := newOptInScanService(fixedOptIns{err: errors.New("db down")})
	if err := create(broken, map[string]any{"allow_interactsh": true}); err == nil {
		t.Error("unreadable opt-ins: scan created")
	}
}

// An existing scan with allow_interactsh still runs, without it, and says
// so; one with custom templates is refused.
func TestOptIns_TriggerStripsInteractshAndRefusesTemplates(t *testing.T) {
	tenant := shared.NewID()
	svc, deps := newOptInScanService(fixedOptIns{})
	storedCfg := map[string]any{"allow_interactsh": true, "severity": "high"}
	sc := singleScan(t, deps, tenant, "nuclei", 1, storedCfg, "203.0.113.5")
	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps.commandRepo.commands) != 1 {
		t.Fatalf("commands = %d", len(deps.commandRepo.commands))
	}
	for _, c := range deps.commandRepo.commands {
		var p struct {
			Config        map[string]any `json:"config"`
			ScannerConfig map[string]any `json:"scanner_config"`
		}
		if err := json.Unmarshal(c.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if _, ok := p.Config["allow_interactsh"]; ok {
			t.Error("allow_interactsh reached the command config")
		}
		if _, ok := p.ScannerConfig["allow_interactsh"]; ok {
			t.Error("allow_interactsh reached the command scanner_config")
		}
		if p.Config["severity"] != "high" {
			t.Errorf("the rest of the config was lost: %v", p.Config)
		}
	}
	if !hasWarning(warningsOf(run), "allow_interactsh was removed") {
		t.Errorf("warnings %v do not say interactsh was removed", warningsOf(run))
	}
	// The scan's own config is copied, never edited: only this run is
	// narrowed (the stored row is not written by a trigger).
	if v, _ := storedCfg["allow_interactsh"].(bool); !v {
		t.Error("the scan's config map was edited in place")
	}

	svc, deps = newOptInScanService(fixedOptIns{})
	sc = singleScan(t, deps, tenant, "nuclei", 1, map[string]any{"custom_template_ids": []any{shared.NewID().String()}}, "203.0.113.5")
	if _, err := trigger(t, svc, sc); optInCode(err) != "SENSOR_OPT_IN_DISABLED" {
		t.Fatalf("custom templates: err = %v", err)
	}
	if len(deps.commandRepo.commands) != 0 || dispatchedRuns(deps) != 0 {
		t.Error("a refused trigger left a run or command")
	}
	if b := blockedRuns(deps, sc.ID); len(b) != 1 || b[0].RefusalCode != "SENSOR_OPT_IN_DISABLED" {
		t.Errorf("the refusal is not one blocked run: %+v", b)
	}
}

func TestOptIns_CommandPayloadRefused(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	svc, _ := newOptInScanService(fixedOptIns{})
	for _, payload := range []string{
		`{"scanner":"nuclei","target":"203.0.113.5","config":{"allow_interactsh":true}}`,
		`{"scanner":"nuclei","target":"203.0.113.5","scanner_config":{"allow_interactsh":"true"}}`,
		`{"scanner":"nuclei","target":"203.0.113.5","custom_templates":[{"id":"a"}]}`,
	} {
		if _, err := svc.GateCommandPayload(ctx, tenant, nil, json.RawMessage(payload)); err == nil ||
			!errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want a refusal", payload, err)
		}
	}
	// A plain payload passes the opt-in check (it then meets the scope
	// checks, which this service does not wire).
	if _, err := svc.GateCommandPayload(ctx, tenant, nil, json.RawMessage(`{"scanner":"nuclei","target":"203.0.113.5"}`)); err != nil &&
		strings.Contains(err.Error(), "turned off") {
		t.Errorf("plain payload refused for an opt-in: %v", err)
	}
}

// D9: turning an opt-in on is audited at critical severity; turning it off
// at medium; a save that changes neither records no opt-in entry.
func TestOptIns_EnablingIsAudited(t *testing.T) {
	ctx := context.Background()
	auditRepo := newMockAuditRepo()
	svc, repo := newTestTenantServiceWithOptions(tenantapp.WithTenantAuditService(auditsvc.NewAuditService(auditRepo, logger.NewNop())))
	tn := seedTenant(repo, "Team", "team-optin")
	actx := auditsvc.AuditContext{ActorID: shared.NewID().String()}

	optInEntries := func() []*audit.AuditLog {
		var out []*audit.AuditLog
		for _, l := range auditRepo.logs {
			if l.Action() == audit.ActionSensorOptInChanged {
				out = append(out, l)
			}
		}
		return out
	}

	if _, err := svc.UpdateSecuritySettings(ctx, tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{MFARequired: boolPtr(true)}, actx); err != nil {
		t.Fatal(err)
	}
	if n := len(optInEntries()); n != 0 {
		t.Fatalf("an unrelated save recorded %d opt-in entries", n)
	}
	o, err := svc.SensorOptIns(ctx, tn.ID())
	if err != nil || o.AllowInteractsh || o.AllowCustomTemplates {
		t.Fatalf("default opt-ins %+v err %v, want both off", o, err)
	}

	if _, err := svc.UpdateSecuritySettings(ctx, tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{AllowSensorInteractsh: boolPtr(true)}, actx); err != nil {
		t.Fatal(err)
	}
	got := optInEntries()
	if len(got) != 1 || got[0].Severity() != audit.SeverityCritical || got[0].Metadata()["setting"] != "allow_sensor_interactsh" {
		t.Fatalf("enable audit: %d entries %+v", len(got), got)
	}
	if o, _ := svc.SensorOptIns(ctx, tn.ID()); !o.AllowInteractsh || o.AllowCustomTemplates {
		t.Fatalf("after enabling interactsh: %+v", o)
	}

	if _, err := svc.UpdateSecuritySettings(ctx, tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{AllowSensorInteractsh: boolPtr(false)}, actx); err != nil {
		t.Fatal(err)
	}
	got = optInEntries()
	medium := 0
	for _, l := range got {
		if l.Severity() == audit.SeverityMedium && strings.Contains(l.Message(), "disabled") {
			medium++
		}
	}
	if len(got) != 2 || medium != 1 {
		t.Fatalf("disable audit: %d entries, %d medium", len(got), medium)
	}
}
