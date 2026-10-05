package tenablesc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// ---- fakes (tenant-scoped like the real repositories) ----

type fakeIntegrations struct {
	rows    map[shared.ID]*integration.Integration
	updates int
}

func (f *fakeIntegrations) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*integration.Integration, error) {
	i, ok := f.rows[id]
	if !ok || i.TenantID() != tenantID {
		return nil, integration.ErrIntegrationNotFound
	}
	return i, nil
}

func (f *fakeIntegrations) Update(_ context.Context, i *integration.Integration) error {
	f.updates++
	f.rows[i.ID()] = i
	return nil
}

type fakeSensors struct {
	rows map[shared.ID]*sensordom.Sensor
}

func (f *fakeSensors) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*sensordom.Sensor, error) {
	s, ok := f.rows[id]
	if !ok || s.TenantID == nil || *s.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

type fakeCommands struct {
	rows map[shared.ID]*command.Command
}

func (f *fakeCommands) Create(_ context.Context, c *command.Command) error {
	f.rows[c.ID] = c
	return nil
}

func (f *fakeCommands) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*command.Command, error) {
	c, ok := f.rows[id]
	if !ok || c.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return c, nil
}

type fakeReports struct {
	reports map[shared.ID][]ingestreport.CoverageReport
}

func (f *fakeReports) CommandCoverage(_ context.Context, _, commandID shared.ID) (*ingestreport.CommandCoverage, error) {
	return &ingestreport.CommandCoverage{Reports: f.reports[commandID]}, nil
}

type fakeClaimer struct {
	win   bool
	calls int
}

func (f *fakeClaimer) ClaimSyncDue(context.Context, shared.ID, shared.ID, *time.Time, time.Time) (bool, error) {
	f.calls++
	return f.win, nil
}

type env struct {
	svc      *Service
	ints     *fakeIntegrations
	sensors  *fakeSensors
	cmds     *fakeCommands
	reports  *fakeReports
	tenant   shared.ID
	sensorID shared.ID
	intg     *integration.Integration
	now      time.Time
}

func connectorSensor(tenant shared.ID, tools ...string) *sensordom.Sensor {
	t := tenant
	s := &sensordom.Sensor{ID: shared.NewID(), TenantID: &t, Status: sensordom.SensorStatusActive}
	reported := make([]sensordom.ReportedTool, 0, len(tools))
	for _, name := range tools {
		reported = append(reported, sensordom.ReportedTool{Name: name, Installed: true})
	}
	s.Reported.Tools = reported
	return s
}

func connectorIntegration(tenant, sensorID shared.ID, extra map[string]any) *integration.Integration {
	i := integration.NewIntegration(shared.NewID(), tenant, "sc", integration.CategorySecurity,
		integration.ProviderTenable, integration.AuthTypeAPIKey)
	cfg := map[string]any{"engine": "tenable_sc", "execution_mode": "sensor", "sensor_id": sensorID.String(), "instance": "sc-prod"}
	for k, v := range extra {
		cfg[k] = v
	}
	i.SetConfig(cfg)
	return i
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		ints:    &fakeIntegrations{rows: map[shared.ID]*integration.Integration{}},
		sensors: &fakeSensors{rows: map[shared.ID]*sensordom.Sensor{}},
		cmds:    &fakeCommands{rows: map[shared.ID]*command.Command{}},
		reports: &fakeReports{reports: map[shared.ID][]ingestreport.CoverageReport{}},
		tenant:  shared.NewID(),
		now:     time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC),
	}
	sn := connectorSensor(e.tenant, ToolName, "nuclei")
	e.sensorID = sn.ID
	e.sensors.rows[sn.ID] = sn
	e.intg = connectorIntegration(e.tenant, sn.ID, nil)
	e.ints.rows[e.intg.ID()] = e.intg
	e.svc = NewService(e.ints, e.sensors, e.cmds, e.reports, nil, logger.NewNop())
	e.svc.now = func() time.Time { return e.now }
	return e
}

// ---- config ----

func TestParseConnectorConfigMap(t *testing.T) {
	sid := shared.NewID().String()
	base := func() map[string]any {
		return map[string]any{"engine": "tenable_sc", "execution_mode": "sensor", "sensor_id": sid}
	}
	ok, err := ParseConnectorConfigMap(base())
	if err != nil || ok.Instance != "default" || ok.MinSeverity != DefaultMinSeverity || ok.FullSyncDays != DefaultFullSyncDays {
		t.Fatalf("defaults: %+v %v", ok, err)
	}
	cases := map[string]func(map[string]any){
		"nessus_pro engine":   func(m map[string]any) { m["engine"] = "nessus_pro" },
		"direct mode":         func(m map[string]any) { m["execution_mode"] = "direct" },
		"no sensor":           func(m map[string]any) { delete(m, "sensor_id") },
		"bad sensor":          func(m map[string]any) { m["sensor_id"] = "nope" },
		"bad instance":        func(m map[string]any) { m["instance"] = "../etc" },
		"severity range":      func(m map[string]any) { m["min_severity"] = float64(5) },
		"full days range":     func(m map[string]any) { m["full_sync_days"] = float64(0) },
		"repositories shape":  func(m map[string]any) { m["repositories"] = "5" },
		"repository negative": func(m map[string]any) { m["repositories"] = []any{float64(-1)} },
		"unknown engine":      func(m map[string]any) { m["engine"] = "tenable_io" },
	}
	for name, mut := range cases {
		m := base()
		mut(m)
		if _, err := ParseConnectorConfigMap(m); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want a validation error, got %v", name, err)
		}
	}
	m := base()
	m["repositories"] = []any{float64(5), float64(7), float64(5)}
	m["min_severity"] = float64(0)
	cc, err := ParseConnectorConfigMap(m)
	if err != nil || len(cc.Repositories) != 2 || cc.MinSeverity != 0 {
		t.Fatalf("repositories dedup / info severity: %+v %v", cc, err)
	}
}

func TestSyncWindow(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	cfg := ConnectorConfig{FullSyncDays: 7}
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }

	if m, _ := syncWindow(SyncState{}, cfg, now); m != ModeFull {
		t.Fatal("first sync must be full")
	}
	m, w := syncWindow(SyncState{LastSuccessfulSync: ago(30 * time.Hour), LastFullSync: ago(48 * time.Hour)}, cfg, now)
	if m != ModeIncremental || w != 3 {
		t.Fatalf("30h gap: %s %d, want incremental 3 (2 days + 1 overlap)", m, w)
	}
	if m, w := syncWindow(SyncState{LastSuccessfulSync: ago(time.Minute), LastFullSync: ago(time.Hour)}, cfg, now); m != ModeIncremental || w != 2 {
		t.Fatalf("1m gap: %s %d", m, w)
	}
	if m, _ := syncWindow(SyncState{LastSuccessfulSync: ago(time.Hour), LastFullSync: ago(8 * 24 * time.Hour)}, cfg, now); m != ModeFull {
		t.Fatal("stale full sync must trigger a full sync")
	}
}

// ---- request ----

func TestRequestSync_QueuesPinnedCommand(t *testing.T) {
	e := newEnv(t)
	res, err := e.svc.RequestSync(context.Background(), e.tenant, e.intg.ID(), TriggerManual, nil)
	if err != nil {
		t.Fatal(err)
	}
	cmd := e.cmds.rows[res.CommandID]
	if cmd == nil || cmd.Type != command.CommandTypeConnectorSync || cmd.TenantID != e.tenant {
		t.Fatalf("command %+v", cmd)
	}
	if cmd.SensorID == nil || *cmd.SensorID != e.sensorID {
		t.Fatal("command must be pinned to the integration's sensor")
	}
	if cmd.ExpiresAt == nil || !cmd.ExpiresAt.Equal(e.now.Add(SyncCommandTTL)) {
		t.Fatalf("expiry %v", cmd.ExpiresAt)
	}
	var p SyncPayload
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Scanner != ToolName || p.Instance != "sc-prod" || p.Mode != ModeFull || p.IntegrationID != e.intg.ID().String() || p.MinSeverity != 1 {
		t.Fatalf("payload %+v", p)
	}
	// No credential or URL ever travels in the payload.
	var raw map[string]any
	_ = json.Unmarshal(cmd.Payload, &raw)
	for _, k := range []string{"url", "base_url", "access_key", "secret_key", "credentials"} {
		if _, ok := raw[k]; ok {
			t.Fatalf("payload carries %q", k)
		}
	}
	if State(e.intg).OpenCommandID != res.CommandID.String() {
		t.Fatal("open command not recorded")
	}

	// A second request returns the open one.
	again, err := e.svc.RequestSync(context.Background(), e.tenant, e.intg.ID(), TriggerManual, nil)
	if err != nil || !again.AlreadyOpen || again.CommandID != res.CommandID || len(e.cmds.rows) != 1 {
		t.Fatalf("second request: %+v %v (commands %d)", again, err, len(e.cmds.rows))
	}
}

func TestRequestSync_CrossTenantAndRefusals(t *testing.T) {
	ctx := context.Background()

	t.Run("another tenant's integration is not found", func(t *testing.T) {
		e := newEnv(t)
		_, err := e.svc.RequestSync(ctx, shared.NewID(), e.intg.ID(), TriggerManual, nil)
		if !errors.Is(err, shared.ErrNotFound) || len(e.cmds.rows) != 0 {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("another tenant's sensor is refused", func(t *testing.T) {
		e := newEnv(t)
		foreign := connectorSensor(shared.NewID(), ToolName)
		e.sensors.rows[foreign.ID] = foreign
		e.intg.SetConfig(connectorIntegration(e.tenant, foreign.ID, nil).Config())
		_, err := e.svc.RequestSync(ctx, e.tenant, e.intg.ID(), TriggerManual, nil)
		if !errors.Is(err, shared.ErrValidation) || len(e.cmds.rows) != 0 {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a platform sensor is refused", func(t *testing.T) {
		e := newEnv(t)
		e.sensors.rows[e.sensorID].IsPlatformSensor = true
		_, err := e.svc.RequestSync(ctx, e.tenant, e.intg.ID(), TriggerManual, nil)
		if !errors.Is(err, ErrPlatformSensor) || len(e.cmds.rows) != 0 {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a sensor without the connector is refused", func(t *testing.T) {
		e := newEnv(t)
		e.sensors.rows[e.sensorID].Reported.Tools = []sensordom.ReportedTool{{Name: "nuclei", Installed: true}}
		_, err := e.svc.RequestSync(ctx, e.tenant, e.intg.ID(), TriggerManual, nil)
		if !errors.Is(err, ErrSensorUnavailable) || len(e.cmds.rows) != 0 {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("an inactive sensor is refused", func(t *testing.T) {
		e := newEnv(t)
		e.sensors.rows[e.sensorID].Status = sensordom.SensorStatusDisabled
		if _, err := e.svc.RequestSync(ctx, e.tenant, e.intg.ID(), TriggerManual, nil); !errors.Is(err, ErrSensorUnavailable) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a disabled integration does not sync", func(t *testing.T) {
		e := newEnv(t)
		e.intg.SetStatus(integration.StatusDisabled)
		if _, err := e.svc.RequestSync(ctx, e.tenant, e.intg.ID(), TriggerManual, nil); !errors.Is(err, ErrDisabled) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a non-connector integration is not handled", func(t *testing.T) {
		e := newEnv(t)
		e.intg.SetConfig(map[string]any{"engine": "nessus_pro", "execution_mode": "sensor"})
		if _, err := e.svc.RequestSync(ctx, e.tenant, e.intg.ID(), TriggerManual, nil); !errors.Is(err, ErrNotConnector) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestValidateConnector(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.svc.ValidateConnector(ctx, e.tenant, e.intg.Config()); err != nil {
		t.Fatalf("own sensor: %v", err)
	}
	if err := e.svc.ValidateConnector(ctx, shared.NewID(), e.intg.Config()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("other tenant: %v", err)
	}
	e.sensors.rows[e.sensorID].IsPlatformSensor = true
	if err := e.svc.ValidateConnector(ctx, e.tenant, e.intg.Config()); !errors.Is(err, ErrPlatformSensor) {
		t.Fatalf("platform sensor: %v", err)
	}
}

// ---- reconcile ----

func complete(t *testing.T, e *env, id shared.ID, status command.CommandStatus, meta map[string]any) {
	t.Helper()
	cmd := e.cmds.rows[id]
	cmd.Status = status
	started := e.now.Add(-10 * time.Minute)
	cmd.StartedAt = &started
	if meta != nil {
		b, _ := json.Marshal(map[string]any{"status": "completed", "metadata": meta})
		cmd.Result = b
	}
	if status == command.CommandStatusFailed {
		cmd.ErrorMessage = "credentials_rejected: Tenable.sc refused the API keys of instance sc-prod"
	}
}

func TestReconcile_SuccessMovesCursor(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	res, _ := e.svc.RequestSync(ctx, e.tenant, e.intg.ID(), TriggerManual, nil)
	complete(t, e, res.CommandID, command.CommandStatusCompleted, map[string]any{
		"tenable_version": "6.4.0", "licensed_ips": float64(1000), "active_ips": float64(420),
		"hosts": float64(12), "open": float64(80), "mitigated": float64(3), "plugins": float64(40),
		"url": "https://sc.corp", // never read
	})
	e.reports.reports[res.CommandID] = []ingestreport.CoverageReport{
		{State: protov2.StateCompleted, ToolName: ToolName},
		{State: protov2.StateProcessing, ToolName: ToolName},
	}
	if changed, err := e.svc.Reconcile(ctx, e.intg); err != nil || changed {
		t.Fatalf("pending report: changed=%v err=%v", changed, err)
	}
	if State(e.intg).LastSuccessfulSync != nil {
		t.Fatal("cursor moved before every report completed")
	}
	e.reports.reports[res.CommandID][1].State = protov2.StateCompleted
	if changed, err := e.svc.Reconcile(ctx, e.intg); err != nil || !changed {
		t.Fatalf("settled: changed=%v err=%v", changed, err)
	}
	st := State(e.intg)
	want := e.now.Add(-10 * time.Minute)
	if st.LastSuccessfulSync == nil || !st.LastSuccessfulSync.Equal(want) || st.LastFullSync == nil {
		t.Fatalf("cursor %+v, want the command start %v", st, want)
	}
	if st.OpenCommandID != "" || st.LastOutcome != OutcomeCompleted || st.TenableVersion != "6.4.0" ||
		st.LicensedIPs != 1000 || st.ActiveIPs != 420 || st.OpenVulns != 80 || st.MitigatedVulns != 3 {
		t.Fatalf("state %+v", st)
	}
	if e.intg.Status() != integration.StatusConnected || e.intg.SyncError() != "" {
		t.Fatalf("status %s err %q", e.intg.Status(), e.intg.SyncError())
	}
	// The next sync is incremental.
	next, err := e.svc.RequestSync(ctx, e.tenant, e.intg.ID(), TriggerManual, nil)
	if err != nil || next.Mode != ModeIncremental {
		t.Fatalf("next: %+v %v", next, err)
	}
}

func TestReconcile_FailureKeepsCursor(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	prev := e.now.Add(-24 * time.Hour)
	writeState(e.intg, SyncState{LastSuccessfulSync: &prev, LastFullSync: &prev})
	res, _ := e.svc.RequestSync(ctx, e.tenant, e.intg.ID(), TriggerManual, nil)
	complete(t, e, res.CommandID, command.CommandStatusFailed, nil)
	if _, err := e.svc.Reconcile(ctx, e.intg); err != nil {
		t.Fatal(err)
	}
	st := State(e.intg)
	if st.LastSuccessfulSync == nil || !st.LastSuccessfulSync.Equal(prev) {
		t.Fatalf("a failed sync moved the cursor: %+v", st)
	}
	if st.LastOutcome != OutcomeFailed || e.intg.SyncError() == "" || st.OpenCommandID != "" {
		t.Fatalf("failure not recorded: %+v err=%q", st, e.intg.SyncError())
	}
}

func TestReconcile_FailedReportFailsSync(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	res, _ := e.svc.RequestSync(ctx, e.tenant, e.intg.ID(), TriggerManual, nil)
	complete(t, e, res.CommandID, command.CommandStatusCompleted, map[string]any{})
	e.reports.reports[res.CommandID] = []ingestreport.CoverageReport{{State: protov2.StateFailed, ToolName: ToolName}}
	if _, err := e.svc.Reconcile(ctx, e.intg); err != nil {
		t.Fatal(err)
	}
	if st := State(e.intg); st.LastSuccessfulSync != nil || st.LastOutcome != OutcomeFailed {
		t.Fatalf("state %+v", st)
	}
}

// ---- schedule ----

func TestScheduledSync(t *testing.T) {
	ctx := context.Background()

	t.Run("due and claimed queues one sync", func(t *testing.T) {
		e := newEnv(t)
		c := &fakeClaimer{win: true}
		e.svc.SetSyncClaimer(c)
		ok, err := e.svc.ScheduledSync(ctx, e.intg)
		if err != nil || !ok || len(e.cmds.rows) != 1 {
			t.Fatalf("ok=%v err=%v commands=%d", ok, err, len(e.cmds.rows))
		}
		if next := e.intg.NextSyncAt(); next == nil || !next.Equal(e.now.Add(SyncInterval(e.intg))) {
			t.Fatalf("next %v", next)
		}
		// Open sync: nothing more is queued.
		if ok, _ := e.svc.ScheduledSync(ctx, e.intg); ok || len(e.cmds.rows) != 1 {
			t.Fatal("queued a second sync while one is open")
		}
	})
	t.Run("claim lost queues nothing", func(t *testing.T) {
		e := newEnv(t)
		e.svc.SetSyncClaimer(&fakeClaimer{win: false})
		if ok, err := e.svc.ScheduledSync(ctx, e.intg); ok || err != nil || len(e.cmds.rows) != 0 {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
	})
	t.Run("not yet due queues nothing", func(t *testing.T) {
		e := newEnv(t)
		later := e.now.Add(time.Hour)
		e.intg.SetNextSyncAt(&later)
		if ok, _ := e.svc.ScheduledSync(ctx, e.intg); ok || len(e.cmds.rows) != 0 {
			t.Fatal("queued before due")
		}
	})
	t.Run("a refusal is recorded and retried later", func(t *testing.T) {
		e := newEnv(t)
		e.sensors.rows[e.sensorID].Status = sensordom.SensorStatusDisabled
		ok, err := e.svc.ScheduledSync(ctx, e.intg)
		if ok || err != nil || e.intg.SyncError() == "" || e.intg.NextSyncAt() == nil {
			t.Fatalf("ok=%v err=%v syncErr=%q", ok, err, e.intg.SyncError())
		}
	})
	t.Run("minimum interval", func(t *testing.T) {
		e := newEnv(t)
		e.intg.SetSyncInterval(5)
		if SyncInterval(e.intg) != MinSyncIntervalMinutes*time.Minute {
			t.Fatalf("interval %v", SyncInterval(e.intg))
		}
	})
}

func TestCapText(t *testing.T) {
	if got := capText("a\x00b\x1bc\ttab", 100); got != "abc\ttab" {
		t.Fatalf("%q", got)
	}
	if got := capText("ééé", 3); got != "é" {
		t.Fatalf("rune boundary: %q", got)
	}
}
