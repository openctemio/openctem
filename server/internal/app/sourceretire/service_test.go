package sourceretire

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	dom "github.com/openctemio/openctem/server/pkg/domain/sourceretire"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type fakeRepo struct {
	preview  dom.Preview
	created  *dom.Retirement
	existing *dom.Retirement
	batches  int
}

func (f *fakeRepo) Preview(context.Context, shared.ID, dom.Selector, dom.Options, *shared.ID) (*dom.Preview, error) {
	p := f.preview
	return &p, nil
}

func (f *fakeRepo) Create(_ context.Context, r *dom.Retirement) (*dom.Retirement, error) {
	if f.existing != nil {
		e := *f.existing
		e.AlreadyRetired = true
		return &e, nil
	}
	c := *r
	c.ID, c.State = shared.NewID(), dom.StateApplying
	f.created = &c
	return &c, nil
}

func (f *fakeRepo) Get(_ context.Context, tenantID, id shared.ID) (*dom.Retirement, error) {
	if f.created != nil && f.created.ID == id && f.created.TenantID == tenantID {
		return f.created, nil
	}
	return nil, dom.ErrNotFound
}

func (f *fakeRepo) List(context.Context, shared.ID, bool, int) ([]*dom.Retirement, error) {
	return nil, nil
}

func (f *fakeRepo) ArchiveBatch(context.Context, shared.ID, shared.ID, time.Time) (*dom.BatchResult, error) {
	f.batches++
	f.created.State = dom.StateActive
	return &dom.BatchResult{Moved: 1, IDs: []shared.ID{shared.NewID()}, Finished: true}, nil
}

func (f *fakeRepo) StartRestore(context.Context, shared.ID, shared.ID, *shared.ID, string) (*dom.Retirement, error) {
	return nil, dom.ErrNotFound
}

func (f *fakeRepo) RestoreBatch(context.Context, shared.ID, shared.ID, time.Time) (*dom.BatchResult, error) {
	return &dom.BatchResult{Finished: true}, nil
}

func (f *fakeRepo) Live(context.Context, shared.ID) ([]dom.Selector, error) { return nil, nil }
func (f *fakeRepo) Pending(context.Context, int) ([]dom.PendingRef, error)  { return nil, nil }

type fakeSensors struct{ byID map[shared.ID]*sensor.Sensor }

func (f fakeSensors) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*sensor.Sensor, error) {
	s, ok := f.byID[id]
	if !ok || s.TenantID == nil || *s.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

type fakeConnectors struct {
	tenant, integration, sensor shared.ID
}

func (f fakeConnectors) ConnectorSource(_ context.Context, tenantID, integrationID shared.ID) (shared.ID, string, string, error) {
	if tenantID != f.tenant || integrationID != f.integration {
		return shared.ID{}, "", "", shared.ErrNotFound
	}
	return f.sensor, "tenable_sc", "Tenable main", nil
}

type fakeScope struct {
	scope *shared.DataScope
	err   error
}

func (f fakeScope) ResolveStrict(context.Context, shared.ID) (*shared.DataScope, error) {
	return f.scope, f.err
}

type fakeAudit struct{ events []auditapp.AuditEvent }

func (f *fakeAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	f.events = append(f.events, e)
	return nil
}

type rig struct {
	svc                           *Service
	repo                          *fakeRepo
	audit                         *fakeAudit
	tenant, other, sensorID, intg shared.ID
	otherSensor                   shared.ID
}

func newRig(scope *shared.DataScope) *rig {
	r := &rig{repo: &fakeRepo{preview: dom.Preview{Total: 3, Archive: 2}}, audit: &fakeAudit{},
		tenant: shared.NewID(), other: shared.NewID(), sensorID: shared.NewID(), intg: shared.NewID(), otherSensor: shared.NewID()}
	t, o := r.tenant, r.other
	sensors := fakeSensors{byID: map[shared.ID]*sensor.Sensor{
		r.sensorID:    {ID: r.sensorID, TenantID: &t, Name: "edge-1"},
		r.otherSensor: {ID: r.otherSensor, TenantID: &o, Name: "theirs"},
	}}
	r.svc = NewService(r.repo, sensors, fakeConnectors{tenant: r.tenant, integration: r.intg, sensor: r.sensorID},
		fakeScope{scope: scope}, r.audit, logger.NewNop())
	return r
}

func (r *rig) sensorSource(id shared.ID) Source {
	return Source{Selector: dom.Selector{Kind: dom.KindSensorTool, SensorID: &id, Tool: "junk"}}
}

func TestRetire_RefusesNarrowedDataScope(t *testing.T) {
	r := newRig(&shared.DataScope{UserID: shared.NewID()})
	if _, _, err := r.svc.Preview(context.Background(), r.tenant, r.sensorSource(r.sensorID), dom.Options{}); !errors.Is(err, dom.ErrFullDataAccessRequired) {
		t.Fatalf("preview: %v", err)
	}
	_, _, err := r.svc.Retire(context.Background(), r.tenant, RetireInput{Source: r.sensorSource(r.sensorID), Reason: "junk results"}, Actor{})
	if !errors.Is(err, dom.ErrFullDataAccessRequired) || r.repo.created != nil {
		t.Fatalf("retire: %v (created %v)", err, r.repo.created)
	}
	// An unwired scope fails closed.
	r.svc.scope = nil
	if _, _, err := r.svc.Preview(context.Background(), r.tenant, r.sensorSource(r.sensorID), dom.Options{}); !errors.Is(err, dom.ErrFullDataAccessRequired) {
		t.Fatalf("unwired scope: %v", err)
	}
}

func TestRetire_AnotherTenantsSensorOrIntegrationIsNotFound(t *testing.T) {
	r := newRig(nil)
	if _, _, err := r.svc.Preview(context.Background(), r.tenant, r.sensorSource(r.otherSensor), dom.Options{}); !errors.Is(err, dom.ErrSourceNotFound) {
		t.Fatalf("other tenant's sensor: %v", err)
	}
	intg := r.intg
	if _, _, err := r.svc.Preview(context.Background(), r.other, Source{IntegrationID: &intg}, dom.Options{}); !errors.Is(err, dom.ErrSourceNotFound) {
		t.Fatalf("integration from another tenant: %v", err)
	}
}

func TestRetire_IntegrationResolvesOnServer(t *testing.T) {
	r := newRig(nil)
	intg := r.intg
	ret, _, err := r.svc.Retire(context.Background(), r.tenant, RetireInput{Source: Source{IntegrationID: &intg},
		Reason: "replaced by the sensor scan"}, Actor{UserID: shared.NewID().String()})
	if err != nil {
		t.Fatal(err)
	}
	if ret.Selector.Kind != dom.KindSensorTool || *ret.Selector.SensorID != r.sensorID || ret.Selector.Tool != "tenable_sc" ||
		ret.IntegrationID == nil || *ret.IntegrationID != r.intg || ret.Label != "Tenable main" {
		t.Fatalf("retirement = %+v", ret)
	}
	if ret.State != dom.StateActive || r.repo.batches != 1 {
		t.Fatalf("state %s after %d batches", ret.State, r.repo.batches)
	}
	if len(r.audit.events) != 1 || r.audit.events[0].Action != auditdom.ActionSourceRetired {
		t.Fatalf("audit = %+v", r.audit.events)
	}
}

func TestRetire_CriticalNeedsSeparateConfirm(t *testing.T) {
	r := newRig(nil)
	r.repo.preview.CriticalOrKEV = 1
	in := RetireInput{Source: r.sensorSource(r.sensorID), Reason: "junk results"}
	_, p, err := r.svc.Retire(context.Background(), r.tenant, in, Actor{})
	if !errors.Is(err, dom.ErrConfirmCriticalRequired) || p == nil || p.CriticalOrKEV != 1 || r.repo.created != nil {
		t.Fatalf("without confirm: %v, %+v", err, p)
	}
	in.ConfirmCritical = true
	if _, _, err := r.svc.Retire(context.Background(), r.tenant, in, Actor{}); err != nil {
		t.Fatalf("with confirm: %v", err)
	}
}

func TestRetire_ValidatesReasonAndOptions(t *testing.T) {
	r := newRig(nil)
	for name, in := range map[string]RetireInput{
		"short reason":  {Source: r.sensorSource(r.sensorID), Reason: "junk"},
		"bad mode":      {Source: r.sensorSource(r.sensorID), Reason: "junk results", Options: dom.Options{Mode: "delete"}},
		"bad severity":  {Source: r.sensorSource(r.sensorID), Reason: "junk results", Options: dom.Options{Severities: []vulnerability.Severity{"urgent"}}},
		"no tool":       {Source: Source{Selector: dom.Selector{Kind: dom.KindUpload}}, Reason: "junk results"},
		"unknown kind":  {Source: Source{Selector: dom.Selector{Kind: "database", Tool: "x"}}, Reason: "junk results"},
		"upload sensor": {Source: Source{Selector: dom.Selector{Kind: dom.KindUpload, Tool: "x", SensorID: &r.sensorID}}, Reason: "junk results"},
	} {
		if _, _, err := r.svc.Retire(context.Background(), r.tenant, in, Actor{}); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRetire_AlreadyRetiredIsIdempotent(t *testing.T) {
	r := newRig(nil)
	r.repo.existing = &dom.Retirement{ID: shared.NewID(), TenantID: r.tenant, State: dom.StateActive}
	ret, _, err := r.svc.Retire(context.Background(), r.tenant, RetireInput{Source: r.sensorSource(r.sensorID), Reason: "junk results"}, Actor{})
	if err != nil || !ret.AlreadyRetired || ret.ID != r.repo.existing.ID || r.repo.batches != 0 || len(r.audit.events) != 0 {
		t.Fatalf("second retire = %+v, %v (batches %d, audits %d)", ret, err, r.repo.batches, len(r.audit.events))
	}
}

func TestRestore_AnotherTenantIsNotFound(t *testing.T) {
	r := newRig(nil)
	if _, err := r.svc.Restore(context.Background(), r.other, shared.NewID(), "", Actor{}); !errors.Is(err, dom.ErrNotFound) {
		t.Fatalf("restore: %v", err)
	}
}
