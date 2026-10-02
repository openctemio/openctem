package sensor

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/command"
	sensordom "github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type fakeContentSensors struct{ byID map[string]*sensordom.Sensor }

func (f *fakeContentSensors) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*sensordom.Sensor, error) {
	s, ok := f.byID[id.String()]
	if !ok || s.TenantID == nil || *s.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

func (f *fakeContentSensors) ListAllSensors(_ context.Context, tenantID string) ([]*sensordom.Sensor, error) {
	var out []*sensordom.Sensor
	for _, s := range f.byID {
		if s.TenantID != nil && s.TenantID.String() == tenantID {
			out = append(out, s)
		}
	}
	return out, nil
}

type fakePolicies struct {
	stored *sensordom.StoredContentPolicy
}

func (f *fakePolicies) GetContentPolicy(context.Context, shared.ID) (*sensordom.StoredContentPolicy, error) {
	return f.stored, nil
}

func (f *fakePolicies) SaveContentPolicy(_ context.Context, p *sensordom.StoredContentPolicy) error {
	p.UpdatedAt = time.Now()
	cp := *p
	f.stored = &cp
	return nil
}

type fakeCommands struct{ created []*command.Command }

func (f *fakeCommands) Create(_ context.Context, cmd *command.Command) error {
	f.created = append(f.created, cmd)
	return nil
}

func (f *fakeCommands) OpenCommandsOfType(_ context.Context, tenantID shared.ID, cmdType string) (map[string]string, error) {
	out := map[string]string{}
	for _, c := range f.created {
		if c.TenantID == tenantID && string(c.Type) == cmdType && c.Status == command.CommandStatusPending {
			out[c.SensorID.String()] = c.ID.String()
		}
	}
	return out, nil
}

func contentSensor(tenant shared.ID, managed bool, status sensordom.SensorStatus) *sensordom.Sensor {
	s := &sensordom.Sensor{ID: shared.NewID(), TenantID: &tenant, Name: "s", Status: status}
	s.Reported.Tools = []sensordom.ReportedTool{{Name: "trivy", Installed: true,
		Content: []sensordom.ReportedContent{{Name: sensordom.ContentTrivyDB, Version: "v", Managed: managed}}}}
	return s
}

func newTestContentService(sensors ...*sensordom.Sensor) (*ContentService, *fakeCommands, *fakePolicies) {
	fs := &fakeContentSensors{byID: map[string]*sensordom.Sensor{}}
	for _, s := range sensors {
		fs.byID[s.ID.String()] = s
	}
	cmds, pols := &fakeCommands{}, &fakePolicies{}
	return NewContentService(fs, fs, pols, cmds, nil, logger.NewNop()), cmds, pols
}

func TestContentService_RefreshSensor(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	ok := contentSensor(tenant, true, sensordom.SensorStatusActive)
	old := contentSensor(tenant, false, sensordom.SensorStatusActive)
	off := contentSensor(tenant, true, sensordom.SensorStatusDisabled)
	svc, cmds, _ := newTestContentService(ok, old, off)
	ctx := context.Background()

	id, pending, err := svc.RefreshSensor(ctx, tenant, ok.ID, []string{sensordom.ContentTrivyDB}, true, nil)
	if err != nil || pending || len(cmds.created) != 1 {
		t.Fatalf("refresh: id=%v pending=%v err=%v created=%d", id, pending, err, len(cmds.created))
	}
	c := cmds.created[0]
	if c.Type != command.CommandTypeRefreshContent || c.SensorID == nil || *c.SensorID != ok.ID || c.ExpiresAt == nil ||
		time.Until(*c.ExpiresAt) < 23*time.Hour {
		t.Fatalf("command = %+v", c)
	}
	var payload struct {
		Content []string                 `json:"content"`
		Force   bool                     `json:"force"`
		Policy  *sensordom.ContentPolicy `json:"policy"`
	}
	if err := json.Unmarshal(c.Payload, &payload); err != nil || !payload.Force || payload.Policy == nil ||
		payload.Policy.Pin(sensordom.ContentTrivyDB).MaxAgeHours != 48 || len(payload.Content) != 1 {
		t.Fatalf("payload %s %v", c.Payload, err)
	}
	if containsSource(c.Payload) {
		t.Fatalf("payload names a source: %s", c.Payload)
	}

	// Again: the open command is returned, nothing new is created.
	id2, pending, err := svc.RefreshSensor(ctx, tenant, ok.ID, nil, true, nil)
	if err != nil || !pending || id2 != id || len(cmds.created) != 1 {
		t.Fatalf("dedup: id=%v pending=%v err=%v created=%d", id2, pending, err, len(cmds.created))
	}

	for _, s := range []*sensordom.Sensor{old, off} {
		if _, _, err := svc.RefreshSensor(ctx, tenant, s.ID, nil, true, nil); !errors.Is(err, ErrContentRefreshUnsupported) ||
			!errors.Is(err, shared.ErrConflict) {
			t.Errorf("ineligible sensor: %v", err)
		}
	}
	if _, _, err := svc.RefreshSensor(ctx, other, ok.ID, nil, true, nil); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("other tenant: %v", err)
	}
	if _, _, err := svc.RefreshSensor(ctx, tenant, ok.ID, []string{"evil"}, true, nil); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("unknown content name: %v", err)
	}
}

func containsSource(payload []byte) bool {
	var m map[string]any
	_ = json.Unmarshal(payload, &m)
	pol, _ := m["policy"].(map[string]any)
	content, _ := pol["content"].(map[string]any)
	for _, v := range content {
		pin, _ := v.(map[string]any)
		for _, k := range []string{"source", "url", "repository", "mirror"} {
			if _, ok := pin[k]; ok {
				return true
			}
		}
	}
	return false
}

func TestContentService_FleetAndPolicy(t *testing.T) {
	tenant := shared.NewID()
	a := contentSensor(tenant, true, sensordom.SensorStatusActive)
	b := contentSensor(tenant, true, sensordom.SensorStatusActive)
	old := contentSensor(tenant, false, sensordom.SensorStatusActive)
	svc, cmds, pols := newTestContentService(a, b, old)
	ctx := context.Background()

	if _, _, err := svc.RefreshSensor(ctx, tenant, a.ID, nil, true, nil); err != nil {
		t.Fatal(err)
	}
	res, err := svc.RefreshFleet(ctx, tenant, nil, true, nil)
	if err != nil || res.CommandsCreated != 1 || res.Skipped != 2 {
		t.Fatalf("fleet: %+v %v", res, err)
	}

	// Invalid policy: nothing saved.
	bad := sensordom.ContentPolicy{Content: map[string]sensordom.ContentPin{"x": {}}}
	if _, _, err := svc.UpdatePolicy(ctx, tenant, bad, true, nil); !errors.Is(err, shared.ErrValidation) || pols.stored != nil {
		t.Fatalf("invalid policy: %v stored=%v", err, pols.stored)
	}

	// The defaults while nothing is stored.
	view, err := svc.GetPolicy(ctx, tenant)
	if err != nil || view.UpdatedAt != nil || view.Policy.Pin(sensordom.ContentNucleiTemplates).MaxAgeHours != 336 {
		t.Fatalf("default view %+v %v", view, err)
	}

	pol := sensordom.ContentPolicy{Content: map[string]sensordom.ContentPin{
		sensordom.ContentNucleiTemplates: {Version: "v10.4.9"},
	}}
	view, res, err = svc.UpdatePolicy(ctx, tenant, pol, true, nil)
	if err != nil || view.UpdatedAt == nil {
		t.Fatalf("update: %+v %v", view, err)
	}
	if pin := view.Policy.Pin(sensordom.ContentNucleiTemplates); pin.Version != "v10.4.9" || pin.MaxAgeHours != 336 {
		t.Fatalf("effective pin %+v", pin)
	}
	// a and b have open refreshes; old does not manage content.
	if res.CommandsCreated != 0 || res.Skipped != 3 {
		t.Fatalf("apply_now: %+v", res)
	}
	if eff := svc.EffectivePolicy(ctx, tenant); eff.Pin(sensordom.ContentNucleiTemplates).Version != "v10.4.9" {
		t.Fatalf("effective policy %+v", eff)
	}
	if len(cmds.created) != 2 {
		t.Fatalf("commands %d", len(cmds.created))
	}
}
