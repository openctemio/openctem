package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/module"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/reportschedule"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// memSchedules is an in-memory, tenant-scoped schedule repository.
type memSchedules struct {
	rows map[shared.ID]*reportschedule.ReportSchedule
}

func (m *memSchedules) Create(_ context.Context, s *reportschedule.ReportSchedule) error {
	m.rows[s.ID()] = s
	return nil
}

func (m *memSchedules) GetByID(_ context.Context, tenantID, id shared.ID) (*reportschedule.ReportSchedule, error) {
	s, ok := m.rows[id]
	if !ok || s.TenantID() != tenantID {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

func (m *memSchedules) Update(_ context.Context, s *reportschedule.ReportSchedule) error {
	m.rows[s.ID()] = s
	return nil
}

func (m *memSchedules) Delete(_ context.Context, tenantID, id shared.ID) error {
	s, ok := m.rows[id]
	if !ok || s.TenantID() != tenantID {
		return shared.ErrNotFound
	}
	delete(m.rows, id)
	return nil
}

func (m *memSchedules) List(_ context.Context, f reportschedule.ScheduleFilter, page pagination.Pagination) (pagination.Result[*reportschedule.ReportSchedule], error) {
	out := []*reportschedule.ReportSchedule{}
	for _, s := range m.rows {
		if f.TenantID != nil && s.TenantID() == *f.TenantID {
			out = append(out, s)
		}
	}
	return pagination.NewResult(out, int64(len(out)), page), nil
}

func (m *memSchedules) ListDue(context.Context, time.Time) ([]*reportschedule.ReportSchedule, error) {
	return nil, nil
}

type fixedNames map[shared.ID]string

func (f fixedNames) GetUserNameByID(_ context.Context, id shared.ID) (string, error) {
	return f[id], nil
}

// A report schedule is changed only by its creator or a holder of
// reports:manage, and its recipients are shown only to them. Before, any
// reports:write holder could pause or delete the owner's executive digest
// and every reports:read holder saw every recipient address.
func TestReportSchedule_OwnershipAndRecipientDisclosure(t *testing.T) {
	tenant, otherTenant := shared.NewID(), shared.NewID()
	owner, member, viewer := shared.NewID(), shared.NewID(), shared.NewID()

	newSchedule := func(tn, by shared.ID, name string) *reportschedule.ReportSchedule {
		s, err := reportschedule.NewReportSchedule(tn, name, "executive_summary", "html", "0 8 * * 1")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRecipients([]reportschedule.Recipient{{Email: "ciso@corp.example"}, {Email: "board@corp.example"}})
		s.SetCreatedBy(by)
		return s
	}

	type caller struct {
		user  shared.ID
		perms []string
	}
	ownerC := caller{owner, []string{"reports:read", "reports:write", "reports:manage"}}
	memberC := caller{member, []string{"reports:read", "reports:write"}}
	viewerC := caller{viewer, []string{"reports:read"}}

	setup := func() (*ReportScheduleHandler, *memSchedules, *reportschedule.ReportSchedule, *reportschedule.ReportSchedule, *reportschedule.ReportSchedule) {
		repo := &memSchedules{rows: map[shared.ID]*reportschedule.ReportSchedule{}}
		exec := newSchedule(tenant, owner, "Weekly executive summary")
		mine := newSchedule(tenant, member, "My weekly digest")
		foreign := newSchedule(otherTenant, member, "Other org digest")
		for _, s := range []*reportschedule.ReportSchedule{exec, mine, foreign} {
			repo.rows[s.ID()] = s
		}
		h := NewReportScheduleHandler(module.NewReportScheduleService(repo, logger.NewNop()), logger.NewNop())
		h.SetCreatorNames(fixedNames{owner: "Alex Owner", member: "Sam Member"})
		return h, repo, exec, mine, foreign
	}

	do := func(h *ReportScheduleHandler, c caller, method, id, body string) *httptest.ResponseRecorder {
		path := "/api/v1/reports/schedules/"
		if id != "" {
			path += id
		}
		if method == http.MethodPatch {
			path += "/toggle"
		}
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if id != "" {
			req.SetPathValue("id", id)
		}
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
		ctx = context.WithValue(ctx, middleware.UserIDKey, c.user.String())
		ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, c.perms)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		switch {
		case method == http.MethodDelete:
			h.Delete(w, req)
		case method == http.MethodPatch:
			h.Toggle(w, req)
		case id != "":
			h.Get(w, req)
		default:
			h.List(w, req)
		}
		return w
	}

	t.Run("member cannot pause or delete another member's schedule", func(t *testing.T) {
		h, repo, exec, _, _ := setup()
		if w := do(h, memberC, http.MethodPatch, exec.ID().String(), `{"active":false}`); w.Code != http.StatusForbidden {
			t.Errorf("member pauses owner's schedule: status %d, want 403", w.Code)
		}
		if !repo.rows[exec.ID()].IsActive() {
			t.Error("owner's schedule was paused by a member")
		}
		if w := do(h, memberC, http.MethodDelete, exec.ID().String(), ""); w.Code != http.StatusForbidden {
			t.Errorf("member deletes owner's schedule: status %d, want 403", w.Code)
		}
		if _, ok := repo.rows[exec.ID()]; !ok {
			t.Error("owner's schedule was deleted by a member")
		}
	})

	t.Run("creator manages their own schedule", func(t *testing.T) {
		h, repo, _, mine, _ := setup()
		if w := do(h, memberC, http.MethodPatch, mine.ID().String(), `{"active":false}`); w.Code != http.StatusOK {
			t.Fatalf("creator pauses own schedule: status %d", w.Code)
		}
		if repo.rows[mine.ID()].IsActive() {
			t.Error("own schedule still active after pause")
		}
		if w := do(h, memberC, http.MethodDelete, mine.ID().String(), ""); w.Code != http.StatusNoContent {
			t.Errorf("creator deletes own schedule: status %d", w.Code)
		}
	})

	t.Run("reports:manage holder manages any schedule in the tenant", func(t *testing.T) {
		h, _, _, mine, _ := setup()
		if w := do(h, ownerC, http.MethodPatch, mine.ID().String(), `{"active":false}`); w.Code != http.StatusOK {
			t.Errorf("manager pauses member's schedule: status %d", w.Code)
		}
		if w := do(h, ownerC, http.MethodDelete, mine.ID().String(), ""); w.Code != http.StatusNoContent {
			t.Errorf("manager deletes member's schedule: status %d", w.Code)
		}
	})

	t.Run("another tenant's schedule is not found, even for a manager", func(t *testing.T) {
		h, repo, _, _, foreign := setup()
		for _, c := range []caller{ownerC, memberC} {
			if w := do(h, c, http.MethodDelete, foreign.ID().String(), ""); w.Code != http.StatusNotFound {
				t.Errorf("cross-tenant delete: status %d, want 404", w.Code)
			}
			if w := do(h, c, http.MethodPatch, foreign.ID().String(), `{"active":false}`); w.Code != http.StatusNotFound {
				t.Errorf("cross-tenant toggle: status %d, want 404", w.Code)
			}
			if w := do(h, c, http.MethodGet, foreign.ID().String(), ""); w.Code != http.StatusNotFound {
				t.Errorf("cross-tenant get: status %d, want 404", w.Code)
			}
		}
		if _, ok := repo.rows[foreign.ID()]; !ok || !foreign.IsActive() {
			t.Error("another tenant's schedule was changed")
		}
	})

	t.Run("recipients only for the creator and managers", func(t *testing.T) {
		h, _, exec, mine, _ := setup()
		list := func(c caller) map[string]reportScheduleResponse {
			w := do(h, c, http.MethodGet, "", "")
			if w.Code != http.StatusOK {
				t.Fatalf("list: status %d", w.Code)
			}
			var body struct {
				Data []reportScheduleResponse `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			out := map[string]reportScheduleResponse{}
			for _, r := range body.Data {
				out[r.ID] = r
			}
			if len(out) != 2 {
				t.Fatalf("list returned %d schedules, want this tenant's 2", len(out))
			}
			if strings.Contains(w.Body.String(), "Other org digest") {
				t.Error("list leaked another tenant's schedule")
			}
			return out
		}

		v := list(viewerC)
		for _, id := range []string{exec.ID().String(), mine.ID().String()} {
			if len(v[id].Recipients) != 0 || v[id].CanManage {
				t.Errorf("viewer sees recipients %v / can_manage %v on %s", v[id].Recipients, v[id].CanManage, v[id].Name)
			}
			if v[id].RecipientCount != 2 {
				t.Errorf("recipient_count = %d, want 2", v[id].RecipientCount)
			}
		}
		if v[exec.ID().String()].CreatedByName != "Alex Owner" {
			t.Errorf("created_by_name = %q", v[exec.ID().String()].CreatedByName)
		}

		m := list(memberC)
		if len(m[exec.ID().String()].Recipients) != 0 || m[exec.ID().String()].CanManage {
			t.Error("member sees the owner's schedule recipients or may manage it")
		}
		if len(m[mine.ID().String()].Recipients) != 2 || !m[mine.ID().String()].CanManage {
			t.Error("creator does not see their own recipients")
		}

		o := list(ownerC)
		for _, id := range []string{exec.ID().String(), mine.ID().String()} {
			if len(o[id].Recipients) != 2 || !o[id].CanManage {
				t.Errorf("manager does not see recipients of %s", o[id].Name)
			}
		}

		w := do(h, viewerC, http.MethodGet, exec.ID().String(), "")
		if strings.Contains(w.Body.String(), "ciso@corp.example") {
			t.Error("GET one schedule disclosed recipients to a viewer")
		}
	})

	t.Run("schedule without a creator is managed only through the permission", func(t *testing.T) {
		h, repo, _, _, _ := setup()
		legacy, err := reportschedule.NewReportSchedule(tenant, "legacy", "executive_summary", "html", "0 8 * * 1")
		if err != nil {
			t.Fatal(err)
		}
		repo.rows[legacy.ID()] = legacy
		if w := do(h, memberC, http.MethodDelete, legacy.ID().String(), ""); w.Code != http.StatusForbidden {
			t.Errorf("member deletes creator-less schedule: status %d, want 403", w.Code)
		}
		if w := do(h, ownerC, http.MethodDelete, legacy.ID().String(), ""); w.Code != http.StatusNoContent {
			t.Errorf("manager deletes creator-less schedule: status %d", w.Code)
		}
	})
}

// The manage permission is granted to owners and admins only.
func TestReportsManage_GrantedToOwnerAndAdminOnly(t *testing.T) {
	for role, want := range map[string]bool{"owner": true, "admin": true, "member": false, "viewer": false} {
		got := false
		for r, perms := range permission.RolePermissions {
			if string(r) != role {
				continue
			}
			for _, p := range perms {
				if p == permission.ReportsManage {
					got = true
				}
			}
		}
		if got != want {
			t.Errorf("role %s holds reports:manage = %v, want %v", role, got, want)
		}
	}
}
