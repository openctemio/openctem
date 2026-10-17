package unit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/command"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Per-sensor tool settings ride in the job (docs/architecture/sensors.md,
// "Tool settings"): settings_layers.sensor carries the claiming sensor's
// stored values for the job's tool, inside the signed payload, on every
// hand-out path; settings that no longer validate fail the job; a value a
// command's creator put in settings_layers never reaches the sensor.

type fakeToolSettings struct {
	layers  map[string]map[string]any // tenant|sensor|tool: the sensor layer
	tenants map[string]map[string]any // tenant|sensor|tool: the inherited organization layer
	err     error
	calls   int
}

func (f *fakeToolSettings) ToolSettingsLayers(_ context.Context, tenantID, sensorID shared.ID, tool string) (tenant, sensor map[string]any, err error) {
	f.calls++
	if f.err != nil {
		return nil, nil, f.err
	}
	key := tenantID.String() + "|" + sensorID.String() + "|" + tool
	return f.tenants[key], f.layers[key], nil
}

type capturingSigner struct{ statements []jobsign.Statement }

func (c *capturingSigner) SignJob(_ context.Context, st jobsign.Statement) (json.RawMessage, error) {
	c.statements = append(c.statements, st)
	return json.RawMessage(`{"payloadType":"test"}`), nil
}

type toolSettingsFixture struct {
	tenant, sensor shared.ID
	repo           *recheckRepo
	src            *fakeToolSettings
	signer         *capturingSigner
	svc            *command.Service
}

func newToolSettingsFixture() *toolSettingsFixture {
	f := &toolSettingsFixture{tenant: shared.NewID(), sensor: shared.NewID(), repo: newRecheckRepo(),
		src: &fakeToolSettings{layers: map[string]map[string]any{}}, signer: &capturingSigner{}}
	f.svc = command.NewService(f.repo, newCmdTestLogger(), command.WithToolSettings(f.src), command.WithJobSigner(f.signer))
	return f
}

func (f *toolSettingsFixture) run(name string, c *commanddom.Command) (*commanddom.Command, error) {
	ctx := context.Background()
	switch name {
	case "poll":
		cmds, err := f.svc.Poll(ctx, command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10})
		return find(cmds, c), err
	case "claim-N":
		cmds, err := f.svc.Claim(ctx, command.ClaimInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10, MaxJobs: 10})
		return find(cmds, c), err
	default:
		return f.svc.Acknowledge(ctx, f.tenant.String(), f.sensor.String(), c.ID.String())
	}
}

var toolSettingsPaths = []string{"poll", "claim-N", "claim by id"}

func settingsLayers(t *testing.T, payload json.RawMessage) map[string]map[string]any {
	t.Helper()
	var p struct {
		Layers map[string]map[string]any `json:"settings_layers"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatalf("payload %s: %v", payload, err)
	}
	return p.Layers
}

func TestToolSettings_PayloadCarriesTheSensorLayer(t *testing.T) {
	for _, path := range toolSettingsPaths {
		t.Run(path, func(t *testing.T) {
			f := newToolSettingsFixture()
			f.src.layers[f.tenant.String()+"|"+f.sensor.String()+"|nuclei"] = map[string]any{"rate_limit": json.Number("300")}
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"scanner":"Nuclei","targets":["a.example.com"]}`, nil)
			stored := string(c.Payload)
			got, err := f.run(path, c)
			if err != nil || got == nil {
				t.Fatalf("not handed out: %v", err)
			}
			layers := settingsLayers(t, got.Payload)
			if fmt.Sprint(layers["sensor"]["rate_limit"]) != "300" || len(layers) != 1 {
				t.Fatalf("settings_layers = %v (payload %s)", layers, got.Payload)
			}
			if string(f.repo.commands[c.ID.String()].Payload) != stored {
				t.Fatal("the stored command was changed")
			}
			if path == "claim-N" {
				// The job signature covers the layer: the statement's digest
				// is over the payload handed out.
				if len(f.signer.statements) != 1 || f.signer.statements[0].PayloadSHA256 != jobsign.PayloadDigest(got.Payload) {
					t.Fatalf("signed digest does not cover the delivered payload: %+v", f.signer.statements)
				}
			}
		})
	}
}

// The organization's defaults the sensor inherits ride next to the sensor's
// own values, inside the signed payload.
func TestToolSettings_PayloadCarriesTheTenantLayer(t *testing.T) {
	for _, path := range toolSettingsPaths {
		t.Run(path, func(t *testing.T) {
			f := newToolSettingsFixture()
			key := f.tenant.String() + "|" + f.sensor.String() + "|nuclei"
			f.src.tenants = map[string]map[string]any{key: {"retries": json.Number("2")}}
			f.src.layers[key] = map[string]any{"rate_limit": json.Number("300")}
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"scanner":"nuclei","targets":["a.example.com"]}`, nil)
			got, err := f.run(path, c)
			if err != nil || got == nil {
				t.Fatalf("not handed out: %v", err)
			}
			layers := settingsLayers(t, got.Payload)
			if fmt.Sprint(layers["tenant"]["retries"]) != "2" || fmt.Sprint(layers["sensor"]["rate_limit"]) != "300" || len(layers) != 2 {
				t.Fatalf("settings_layers = %v", layers)
			}
			if path == "claim-N" && f.signer.statements[0].PayloadSHA256 != jobsign.PayloadDigest(got.Payload) {
				t.Fatal("signed digest does not cover the delivered payload")
			}
			// Only the tenant layer: it is delivered alone.
			f2 := newToolSettingsFixture()
			f2.src.tenants = map[string]map[string]any{f2.tenant.String() + "|" + f2.sensor.String() + "|nuclei": {"retries": json.Number("0")}}
			c2 := f2.repo.add(f2.tenant, commanddom.CommandTypeScan, `{"scanner":"nuclei"}`, nil)
			got2, err := f2.run(path, c2)
			if err != nil || got2 == nil {
				t.Fatalf("not handed out: %v", err)
			}
			if l := settingsLayers(t, got2.Payload); len(l) != 1 || fmt.Sprint(l["tenant"]["retries"]) != "0" {
				t.Fatalf("settings_layers = %v", l)
			}
		})
	}
}

func TestToolSettings_CreatorValueIsReplacedOrRemoved(t *testing.T) {
	for _, path := range toolSettingsPaths {
		t.Run(path, func(t *testing.T) {
			f := newToolSettingsFixture()
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan,
				`{"scanner":"nuclei","settings_layers":{"sensor":{"headless":true}}}`, nil)
			got, err := f.run(path, c)
			if err != nil || got == nil {
				t.Fatalf("not handed out: %v", err)
			}
			if strings.Contains(string(got.Payload), "settings_layers") {
				t.Fatalf("a creator's settings_layers reached the sensor: %s", got.Payload)
			}
		})
	}
}

func TestToolSettings_InvalidSettingsFailTheJob(t *testing.T) {
	for _, path := range toolSettingsPaths {
		t.Run(path, func(t *testing.T) {
			f := newToolSettingsFixture()
			f.src.err = fmt.Errorf("%w: /rate_limit: above the maximum", sensordom.ErrToolSettingsInvalid)
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"scanner":"nuclei"}`, nil)
			got, err := f.run(path, c)
			if got != nil {
				t.Fatalf("a job with invalid settings was handed out: %s", got.Payload)
			}
			if path == "claim by id" && !errors.Is(err, command.ErrToolSettingsInvalidAtClaim) {
				t.Fatalf("claim by id: %v", err)
			}
			stored := f.repo.commands[c.ID.String()]
			if stored.Status != commanddom.CommandStatusFailed || !strings.HasPrefix(stored.ErrorMessage, command.FailureToolSettingsInvalid+": ") {
				t.Fatalf("stored %s %q", stored.Status, stored.ErrorMessage)
			}
		})
	}
}

func TestToolSettings_ReadErrorWithholdsTheJob(t *testing.T) {
	for _, path := range toolSettingsPaths {
		t.Run(path, func(t *testing.T) {
			f := newToolSettingsFixture()
			f.src.err = errors.New("database unavailable")
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"scanner":"nuclei"}`, nil)
			got, err := f.run(path, c)
			if got != nil {
				t.Fatal("handed out without its settings")
			}
			if path == "claim by id" && !errors.Is(err, command.ErrToolSettingsUnavailable) {
				t.Fatalf("claim by id: %v", err)
			}
			if stored := f.repo.commands[c.ID.String()]; stored.Status != commanddom.CommandStatusPending {
				t.Fatalf("stored %s, want pending", stored.Status)
			}
		})
	}
}

func TestToolSettings_OnlyScanJobsWithATool(t *testing.T) {
	f := newToolSettingsFixture()
	f.repo.add(f.tenant, commanddom.CommandType("collect"), `{"a":1}`, nil)
	f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"targets":["a.example.com"]}`, nil)
	cmds, err := f.svc.Claim(context.Background(), command.ClaimInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10, MaxJobs: 10})
	if err != nil || len(cmds) != 2 {
		t.Fatalf("claimed %d, %v", len(cmds), err)
	}
	if f.src.calls != 0 {
		t.Fatalf("settings looked up %d times for jobs without a tool", f.src.calls)
	}
}
