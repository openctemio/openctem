package inbox

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

const (
	testTenant = "11111111-1111-1111-1111-111111111111"
	testUser   = "22222222-2222-2222-2222-222222222222"
)

// fakeFindings returns fixed counts and records what it was asked.
type fakeFindings struct {
	keys        []string
	caller      finding.FilterCaller
	approvalIn  *finding.ApprovalQueueInput
	closureAsks int
	err         error
}

func (f *fakeFindings) IncludeInformational(context.Context, string, *bool) bool { return false }

func (f *fakeFindings) CountQuickViewsOf(_ context.Context, c finding.FilterCaller, _ bool, keys []string) ([]finding.QuickViewCount, error) {
	f.keys, f.caller = keys, c
	if f.err != nil {
		return nil, f.err
	}
	n := map[string]int64{
		vulnerability.QuickViewMyQueue: 5, vulnerability.QuickViewMyTeam: 9,
		vulnerability.QuickViewMyDueSoon: 2, vulnerability.QuickViewMyAcceptedExpiring: 1,
	}
	out := make([]finding.QuickViewCount, 0, len(keys))
	for _, k := range keys {
		out = append(out, finding.QuickViewCount{Key: k, Count: n[k]})
	}
	return out, nil
}

func (f *fakeFindings) CountApprovalQueues(_ context.Context, in finding.ApprovalQueueInput) (map[vulnerability.ApprovalQueue]int64, error) {
	f.approvalIn = &in
	// A counter that (wrongly) counted review without the permission must
	// still not reach the response.
	return map[vulnerability.ApprovalQueue]int64{vulnerability.ApprovalQueueReview: 3, vulnerability.ApprovalQueueRequested: 2}, nil
}

func (f *fakeFindings) CountClosureProposals(context.Context, string) (int, error) {
	f.closureAsks++
	return 1, nil
}

type fakeTasks struct {
	in    *remediationapp.ListTasksInput
	count int64
}

func (f *fakeTasks) CountTasks(_ context.Context, in remediationapp.ListTasksInput) (int64, error) {
	f.in = &in
	return f.count, nil
}

type fakeModules map[string]bool

func (m fakeModules) IsReadable(_ context.Context, _, id string) bool { return !m[id] }

func perms(ps ...permission.Permission) func(string) bool {
	return func(p string) bool {
		return slices.ContainsFunc(ps, func(x permission.Permission) bool { return x.String() == p })
	}
}

func val(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestSummary_EveryQueueAndTotal(t *testing.T) {
	f, tasks := &fakeFindings{}, &fakeTasks{count: 1}
	s := NewService(f, tasks, nil)
	sum, err := s.Summary(context.Background(), Caller{
		TenantID: testTenant, UserID: testUser,
		Has: perms(permission.FindingsRead, permission.FindingsApprove, permission.FindingsVerify, permission.RemediationRead),
	})
	if err != nil {
		t.Fatal(err)
	}
	q := sum.Queues
	got := []any{val(q.Assigned), val(q.Team), val(q.DueSoon), val(q.Review), val(q.Requested), val(q.Expiring), val(q.Tasks), val(q.ReadyToClose)}
	want := []any{int64(5), int64(9), int64(2), int64(3), int64(2), int64(1), int64(1), int64(1)}
	if !slices.Equal(got, want) {
		t.Errorf("queues = %v, want %v", got, want)
	}
	// 5 + 3 + 2 + 1 + 1 + 1: team and due_soon are not in the total.
	if sum.Total != 13 {
		t.Errorf("total = %d, want 13", sum.Total)
	}
	// Only the four finding queues are counted, as the caller.
	if !slices.Equal(f.keys, findingQueueViews) || f.caller.UserID != testUser || f.caller.TenantID != testTenant {
		t.Errorf("quick views asked %v as %+v", f.keys, f.caller)
	}
	if f.approvalIn == nil || f.approvalIn.CallerID != testUser || !f.approvalIn.CanApprove {
		t.Errorf("approval queues asked %+v", f.approvalIn)
	}
	// My tasks: the caller's, open states only, as the task list's assignee=me.
	if tasks.in == nil || !tasks.in.Mine || tasks.in.CallerID == nil || tasks.in.CallerID.String() != testUser ||
		!slices.Equal(tasks.in.Filter.States, remediationdom.OpenTaskStates()) {
		t.Errorf("tasks asked %+v", tasks.in)
	}
}

func TestSummary_QueuesFollowPermissions(t *testing.T) {
	cases := []struct {
		name    string
		has     []permission.Permission
		present []string
	}{
		{"reader", []permission.Permission{permission.FindingsRead},
			[]string{"assigned", "team", "due_soon", "requested", "expiring"}},
		{"approver", []permission.Permission{permission.FindingsRead, permission.FindingsApprove},
			[]string{"assigned", "team", "due_soon", "review", "requested", "expiring"}},
		{"verifier", []permission.Permission{permission.FindingsRead, permission.FindingsVerify},
			[]string{"assigned", "team", "due_soon", "requested", "expiring", "ready_to_close"}},
		{"tasks only", []permission.Permission{permission.RemediationRead}, []string{"tasks"}},
		// findings:approve alone reads no finding: no review count.
		{"approve without read", []permission.Permission{permission.FindingsApprove, permission.FindingsVerify}, nil},
		{"nothing", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeFindings{}
			sum, err := NewService(f, &fakeTasks{count: 4}, nil).Summary(context.Background(),
				Caller{TenantID: testTenant, UserID: testUser, Has: perms(tc.has...)})
			if err != nil {
				t.Fatal(err)
			}
			q := sum.Queues
			byKey := map[string]*int64{"assigned": q.Assigned, "team": q.Team, "due_soon": q.DueSoon, "review": q.Review,
				"requested": q.Requested, "expiring": q.Expiring, "tasks": q.Tasks, "ready_to_close": q.ReadyToClose}
			var present []string
			for _, k := range []string{"assigned", "team", "due_soon", "review", "requested", "expiring", "tasks", "ready_to_close"} {
				if byKey[k] != nil {
					present = append(present, k)
				}
			}
			if !slices.Equal(present, tc.present) {
				t.Errorf("present = %v, want %v", present, tc.present)
			}
			if !slices.Contains(tc.present, "review") && f.approvalIn != nil && f.approvalIn.CanApprove {
				t.Errorf("approval queues counted with CanApprove for a caller without findings:approve")
			}
			if !slices.Contains(tc.present, "ready_to_close") && f.closureAsks != 0 {
				t.Errorf("closure proposals counted for a caller without findings:verify")
			}
			if !slices.Contains(tc.has, permission.FindingsRead) && f.keys != nil {
				t.Errorf("finding queues counted without findings:read")
			}
		})
	}
}

func TestSummary_TasksNeedTheRemediationModule(t *testing.T) {
	tasks := &fakeTasks{count: 4}
	sum, err := NewService(&fakeFindings{}, tasks, fakeModules{moduledom.ModuleRemediation: true}).Summary(context.Background(),
		Caller{TenantID: testTenant, UserID: testUser, Has: perms(permission.RemediationRead)})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Queues.Tasks != nil || tasks.in != nil || sum.Total != 0 {
		t.Errorf("tasks counted with the module off: %+v", sum)
	}
}

func TestSummary_NeedsAPerson(t *testing.T) {
	for _, user := range []string{"", "not-a-uuid"} {
		f := &fakeFindings{}
		_, err := NewService(f, &fakeTasks{}, nil).Summary(context.Background(),
			Caller{TenantID: testTenant, UserID: user, IsAdmin: true, Has: perms(permission.FindingsRead)})
		if !errors.Is(err, ErrNoPerson) || !errors.Is(err, shared.ErrValidation) {
			t.Errorf("user %q: err = %v, want ErrNoPerson", user, err)
		}
		if f.keys != nil {
			t.Errorf("user %q: counted before refusing", user)
		}
	}
}

func TestSummary_CountErrorFails(t *testing.T) {
	boom := errors.New("boom")
	_, err := NewService(&fakeFindings{err: boom}, nil, nil).Summary(context.Background(),
		Caller{TenantID: testTenant, UserID: testUser, Has: perms(permission.FindingsRead)})
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the count error (never a partial summary)", err)
	}
}
