package sensor

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/commandlog"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

type fakeFleet struct {
	reads, writes int
	job           SharedJob
}

func (f *fakeFleet) ListSharedSensors(context.Context) ([]SharedFleetSensor, error) { return nil, nil }
func (f *fakeFleet) SharedQueue(context.Context) (SharedQueue, error)               { return SharedQueue{}, nil }
func (f *fakeFleet) ListSharedJobs(context.Context, SharedJobFilter, pagination.Pagination) (pagination.Result[SharedJob], error) {
	return pagination.Result[SharedJob]{}, nil
}
func (f *fakeFleet) GetSharedJob(context.Context, shared.ID) (SharedJob, json.RawMessage, error) {
	f.reads++
	return f.job, json.RawMessage(`{"targets":["t.example"],"result":"secret"}`), nil
}
func (f *fakeFleet) SetSharedSensorStatus(context.Context, shared.ID, string, string) (string, error) {
	f.writes++
	return "s", nil
}

type fakeLogs struct{ calls int }

func (l *fakeLogs) ListForCommand(context.Context, shared.ID, shared.ID, int) (commandlog.Page, error) {
	l.calls++
	return commandlog.Page{Lines: []commandlog.Line{{Msg: "line"}}}, nil
}

type fakeAudit struct {
	rows []*admin.AuditLog
	fail bool
}

func (a *fakeAudit) Create(_ context.Context, l *admin.AuditLog) error {
	if a.fail {
		return errors.New("db down")
	}
	a.rows = append(a.rows, l)
	return nil
}

// The audited view reads nothing without a reason, returns nothing when the
// audit row cannot be written, and returns targets and logs only after it is.
func TestSharedFleet_JobDetails_AuditFirst(t *testing.T) {
	ctx := context.Background()
	actor, _ := admin.NewAdminUser("ops@platform.test", "Ops", admin.AdminRoleOpsAdmin, nil)
	store := &fakeFleet{job: SharedJob{ID: shared.NewID(), TenantID: shared.NewID(), Tool: "nuclei"}}
	logs := &fakeLogs{}
	audit := &fakeAudit{}
	svc := NewSharedFleetService(store, logs, audit, logger.NewNop())

	if _, err := svc.JobDetails(ctx, store.job.ID, AdminChange{Actor: actor, Reason: " "}); !errors.Is(err, shared.ErrValidation) || store.reads != 0 {
		t.Fatalf("no reason: %v reads=%d", err, store.reads)
	}
	if _, err := svc.JobDetails(ctx, store.job.ID, AdminChange{Reason: "x"}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("no actor: %v", err)
	}
	audit.fail = true
	if d, err := svc.JobDetails(ctx, store.job.ID, AdminChange{Actor: actor, Reason: "abuse report"}); err == nil || d != nil || logs.calls != 0 {
		t.Fatalf("audit failure still served data: %+v %v", d, err)
	}
	audit.fail = false
	d, err := svc.JobDetails(ctx, store.job.ID, AdminChange{Actor: actor, Reason: "abuse report"})
	if err != nil || len(d.Targets) != 1 || d.Targets[0] != "t.example" || len(d.Logs) != 1 {
		t.Fatalf("details: %+v %v", d, err)
	}
	if len(audit.rows) != 1 || audit.rows[0].Action != ActionSharedSensorJobViewed || audit.rows[0].Severity != admin.SeverityHigh {
		t.Fatalf("audit: %+v", audit.rows)
	}
}

// A remote action needs a reason and an audit log; nothing is written
// otherwise.
func TestSharedFleet_ActionsRefuseWithoutReasonOrAudit(t *testing.T) {
	ctx := context.Background()
	actor, _ := admin.NewAdminUser("root@platform.test", "Root", admin.AdminRoleSuperAdmin, nil)
	store := &fakeFleet{}
	if err := NewSharedFleetService(store, nil, &fakeAudit{}, logger.NewNop()).Pause(ctx, shared.NewID(), AdminChange{Actor: actor}); !errors.Is(err, shared.ErrValidation) || store.writes != 0 {
		t.Fatalf("no reason: %v writes=%d", err, store.writes)
	}
	if err := NewSharedFleetService(store, nil, nil, logger.NewNop()).Retire(ctx, shared.NewID(), AdminChange{Actor: actor, Reason: "x"}); err == nil || store.writes != 0 {
		t.Fatalf("no audit log: %v writes=%d", err, store.writes)
	}
	audit := &fakeAudit{}
	if err := NewSharedFleetService(store, nil, audit, logger.NewNop()).Resume(ctx, shared.NewID(), AdminChange{Actor: actor, Reason: "x"}); err != nil ||
		store.writes != 1 || len(audit.rows) != 1 || audit.rows[0].Severity != admin.SeverityCritical {
		t.Fatalf("resume: %v writes=%d audit=%+v", err, store.writes, audit.rows)
	}
}
