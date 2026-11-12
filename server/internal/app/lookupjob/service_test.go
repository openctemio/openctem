package lookupjob

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/contract/ctlookup"

	"github.com/openctemio/openctem/server/pkg/domain/lookupjob"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/jobsign"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// memRepo mirrors the SQL rules of the Postgres repository.
type memRepo struct {
	mu       sync.Mutex
	jobs     map[shared.ID]*lookupjob.Job
	eligible bool
}

func newMemRepo() *memRepo { return &memRepo{jobs: map[shared.ID]*lookupjob.Job{}, eligible: true} }

func (r *memRepo) Create(_ context.Context, j *lookupjob.Job) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := *j
	r.jobs[j.ID] = &c
	return nil
}

func (r *memRepo) Claim(_ context.Context, sensorID shared.ID, caps []string, now time.Time) (*lookupjob.Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, j := range r.jobs {
		if j.Status == lookupjob.StatusOpen && j.ExpiresAt.After(now) && slices.Contains(caps, j.Capability) {
			j.Status, j.SensorID = lookupjob.StatusClaimed, &sensorID
			c := *j
			return &c, nil
		}
	}
	return nil, nil
}

func (r *memRepo) FinishForPlatform(_ context.Context, id, sensorID shared.ID, status string, res json.RawMessage, code string, _ time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[id]
	if !ok || j.Status != lookupjob.StatusClaimed || j.SensorID == nil || *j.SensorID != sensorID {
		return false, nil
	}
	j.Status, j.Result, j.ErrorCode = status, res, code
	return true, nil
}

func (r *memRepo) Get(_ context.Context, tenantID, id shared.ID) (*lookupjob.Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[id]
	if !ok || j.TenantID != tenantID {
		return nil, lookupjob.ErrNotFound
	}
	c := *j
	return &c, nil
}

func (r *memRepo) Delete(_ context.Context, tenantID, id shared.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if j, ok := r.jobs[id]; ok && j.TenantID == tenantID {
		delete(r.jobs, id)
	}
	return nil
}

func (r *memRepo) Purge(context.Context, time.Time) (int64, error) { return 0, nil }

func (r *memRepo) EligibleSensorExists(context.Context, string, time.Time) (bool, error) {
	return r.eligible, nil
}

func (r *memRepo) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.jobs) }

type fakeSigner struct {
	err error
	sts []jobsign.Statement
}

func (s *fakeSigner) SignJob(_ context.Context, st jobsign.Statement) (json.RawMessage, error) {
	s.sts = append(s.sts, st)
	return json.RawMessage(`{}`), s.err
}

func platformSensor(caps ...string) *sensor.Sensor {
	return &sensor.Sensor{ID: shared.NewID(), Scope: sensor.ScopeInstance, Status: sensor.SensorStatusActive, Capabilities: caps}
}

func newSvc(repo *memRepo, signer Signer) *Service {
	cfg := Config{Timeout: 2 * time.Second, Poll: 5 * time.Millisecond}
	if signer != nil {
		cfg.Signer = signer
	}
	return NewService(cfg, repo, logger.NewNop())
}

func TestAvailableNeedsASignerAndASensor(t *testing.T) {
	repo := newMemRepo()
	if newSvc(repo, nil).Available(context.Background(), ctlookup.Capability) {
		t.Fatal("available without a job signer")
	}
	svc := newSvc(repo, &fakeSigner{})
	if !svc.Available(context.Background(), ctlookup.Capability) || svc.Available(context.Background(), "scan.ports@1") {
		t.Fatal("availability by capability")
	}
	repo.eligible = false
	if svc.Available(context.Background(), ctlookup.Capability) {
		t.Fatal("available without an eligible sensor")
	}
	if _, err := svc.Ask(context.Background(), shared.NewID(), ctlookup.Capability, "example.com", ctlookup.Input{Domain: "example.com"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ask without a sensor: %v", err)
	}
}

// SECURITY: only an active instance-scope sensor with no organization that
// reports the capability is offered or may answer a job.
func TestNextRefusesSensorsThatMayNotServe(t *testing.T) {
	svc := newSvc(newMemRepo(), &fakeSigner{})
	tenant := shared.NewID()
	org := platformSensor(ctlookup.Capability)
	org.Scope, org.TenantID = sensor.ScopeOrganization, &tenant
	inactive := platformSensor(ctlookup.Capability)
	inactive.Status = sensor.SensorStatusDisabled
	for name, sn := range map[string]*sensor.Sensor{
		"organization sensor": org, "inactive": inactive, "no capability": platformSensor("feed.relay@1"), "nil": nil,
	} {
		if _, _, err := svc.Next(context.Background(), sn); !errors.Is(err, ErrNotEligible) {
			t.Errorf("%s: %v", name, err)
		}
		if err := svc.Done(context.Background(), sn, shared.NewID().String(), Result{Output: json.RawMessage(`{}`)}); !errors.Is(err, ErrNotEligible) {
			t.Errorf("%s done: %v", name, err)
		}
	}
}

func TestAskRoundTripAndCleanup(t *testing.T) {
	repo := newMemRepo()
	signer := &fakeSigner{}
	svc := newSvc(repo, signer)
	tenant := shared.NewID()
	sn := platformSensor(ctlookup.Capability)
	go func() {
		for {
			n, _, err := svc.Next(context.Background(), sn)
			if err != nil {
				return
			}
			if n != nil {
				_ = svc.Done(context.Background(), sn, n.ID, Result{Output: json.RawMessage(`{"records":[],"source_status":[]}`)})
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	raw, err := svc.Ask(context.Background(), tenant, ctlookup.Capability, "example.com", ctlookup.Input{Domain: "example.com"})
	if err != nil || string(raw) != `{"records":[],"source_status":[]}` {
		t.Fatalf("ask: %s %v", raw, err)
	}
	st := signer.sts[0]
	if st.TenantID != tenant.String() || st.SensorID != sn.ID.String() || st.SensorScope != jobsign.SensorScopeInstance ||
		st.CommandType != jobsign.CommandTypeLookup || st.Tool != ctlookup.Tool || !slices.Equal(st.Targets, []string{"example.com"}) {
		t.Fatalf("statement %+v", st)
	}
	if repo.count() != 0 {
		t.Fatal("the answered job was kept")
	}
}

func TestAskOutcomes(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	sn := platformSensor(ctlookup.Capability)

	// No sensor claims it: a timeout, and the question is removed.
	repo := newMemRepo()
	svc := newSvc(repo, &fakeSigner{})
	svc.cfg.Timeout = 50 * time.Millisecond
	if _, err := svc.Ask(ctx, tenant, ctlookup.Capability, "example.com", ctlookup.Input{Domain: "example.com"}); !errors.Is(err, ErrTimeout) {
		t.Fatalf("timeout: %v", err)
	}
	if repo.count() != 0 {
		t.Fatal("expired job kept")
	}

	// The signer refuses (an excluded name): refused, with its reason.
	repo = newMemRepo()
	svc = newSvc(repo, &fakeSigner{err: &jobsign.RefusalError{Status: 403, Reason: "target_excluded"}})
	go func() {
		for i := 0; i < 200; i++ {
			if n, _, _ := svc.Next(ctx, sn); n == nil && repo.count() > 0 {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	_, err := svc.Ask(ctx, tenant, ctlookup.Capability, "example.com", ctlookup.Input{Domain: "example.com"})
	var fe *FailedError
	if !errors.As(err, &fe) || fe.Status != lookupjob.StatusRefused || fe.Code != "signer_target_excluded" {
		t.Fatalf("refused: %v", err)
	}

	// A sensor error code is kept short and safe; no answer is a failure.
	repo = newMemRepo()
	svc = newSvc(repo, &fakeSigner{})
	go func() {
		for i := 0; i < 200; i++ {
			if n, _, _ := svc.Next(ctx, sn); n != nil {
				_ = svc.Done(ctx, sn, n.ID, Result{Error: "Timeout <script>\n"})
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	_, err = svc.Ask(ctx, tenant, ctlookup.Capability, "example.com", ctlookup.Input{Domain: "example.com"})
	if !errors.As(err, &fe) || fe.Status != lookupjob.StatusFailed || fe.Code != "sensor_timeoutscript" {
		t.Fatalf("failed: %v", err)
	}
}

// A job answered by one sensor cannot be answered by another, nor twice.
func TestDoneOnlyByTheClaimingSensorOnce(t *testing.T) {
	ctx := context.Background()
	repo := newMemRepo()
	svc := newSvc(repo, &fakeSigner{})
	a, b := platformSensor(ctlookup.Capability), platformSensor(ctlookup.Capability)
	j := &lookupjob.Job{ID: shared.NewID(), TenantID: shared.NewID(), Capability: ctlookup.Capability, Tool: ctlookup.Tool,
		Target: "example.com", Input: json.RawMessage(`{}`), Status: lookupjob.StatusOpen, ExpiresAt: time.Now().Add(time.Minute)}
	_ = repo.Create(ctx, j)
	n, _, err := svc.Next(ctx, a)
	if err != nil || n == nil {
		t.Fatalf("next: %v", err)
	}
	res := Result{Output: json.RawMessage(`{"records":[]}`)}
	if err := svc.Done(ctx, b, n.ID, res); !errors.Is(err, lookupjob.ErrClosed) {
		t.Fatalf("other sensor: %v", err)
	}
	if err := svc.Done(ctx, a, n.ID, res); err != nil {
		t.Fatal(err)
	}
	if err := svc.Done(ctx, a, n.ID, res); !errors.Is(err, lookupjob.ErrClosed) {
		t.Fatalf("twice: %v", err)
	}
	if err := svc.Done(ctx, a, "not-an-id", res); !errors.Is(err, lookupjob.ErrClosed) {
		t.Fatalf("bad id: %v", err)
	}
}
