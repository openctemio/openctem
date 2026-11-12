package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// limitsMemRepo holds operator limits for one organization.
type limitsMemRepo struct {
	lims []limits.Limit
}

func (m *limitsMemRepo) GetSelfServiceDefaults(context.Context) (limits.Limits, int, error) {
	return nil, 0, shared.ErrNotFound
}
func (m *limitsMemRepo) SaveSelfServiceDefaults(context.Context, limits.Limits, int, *shared.ID, time.Time) (int, error) {
	return 1, nil
}
func (m *limitsMemRepo) ListLimits(_ context.Context, t shared.ID, o limits.Origin) ([]limits.Limit, error) {
	out := []limits.Limit{}
	for _, l := range m.lims {
		if l.TenantID == t && l.Origin == o {
			out = append(out, l)
		}
	}
	return out, nil
}
func (m *limitsMemRepo) SetLimit(context.Context, limits.Limit) error { return nil }
func (m *limitsMemRepo) DeleteLimit(context.Context, shared.ID, limits.Key, limits.Origin) error {
	return nil
}
func (m *limitsMemRepo) ListDenies(context.Context, shared.ID, limits.Origin) ([]limits.FeatureDeny, error) {
	return nil, nil
}
func (m *limitsMemRepo) SetDeny(context.Context, limits.FeatureDeny) error { return nil }
func (m *limitsMemRepo) DeleteDeny(context.Context, shared.ID, string, limits.Origin) error {
	return nil
}
func (m *limitsMemRepo) ReplaceOrigin(context.Context, shared.ID, limits.Origin, []limits.Limit, []limits.FeatureDeny) error {
	return nil
}
func (m *limitsMemRepo) Usage(context.Context, shared.ID, bool) (map[limits.Key]int, error) {
	return map[limits.Key]int{limits.Seats: 7}, nil
}
func (m *limitsMemRepo) CountOwnedTenants(context.Context, shared.ID) (int, error) { return 0, nil }
func (m *limitsMemRepo) ListGrace(context.Context, shared.ID) (map[string]time.Time, error) {
	return nil, nil
}
func (m *limitsMemRepo) StartGrace(context.Context, shared.ID, []string, time.Time) error { return nil }
func (m *limitsMemRepo) EndGrace(context.Context, shared.ID, []string) error              { return nil }

func ownLimits(t *testing.T, h *LimitsHandler, tenant shared.ID) (int, OrganizationLimitsResponse, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/organization/limits", nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.TenantIDKey, tenant.String()))
	rec := httptest.NewRecorder()
	h.GetOwnLimits(rec, r)
	var resp OrganizationLimitsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp, rec.Body.String()
}

// The organization's own view: nothing applies by default (no list, no
// link); when a limit applies it lists only that limit, never the
// operator's note, and the account page link when one is configured.
func TestGetOwnLimits(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	repo := &limitsMemRepo{lims: []limits.Limit{{TenantID: a, Key: limits.Seats, Value: 5, Origin: limits.OriginOperator, Reason: "internal note: unpaid invoice"}}}
	h := NewLimitsHandler(entitlement.NewService(repo, nil, nil), nil, logger.NewNop())
	h.SetAccountPortalURL("https://account.example.com")

	code, resp, _ := ownLimits(t, h, b)
	if code != http.StatusOK || resp.Applies || len(resp.Limits) != 0 || len(resp.Denied) != 0 || resp.AccountPortalURL != "" {
		t.Fatalf("nothing applies to b: %d %+v", code, resp)
	}
	code, resp, raw := ownLimits(t, h, a)
	if code != http.StatusOK || !resp.Applies || !resp.OverLimit || len(resp.Limits) != 1 || resp.Limits[0].Key != limits.Seats ||
		resp.Limits[0].Used != 7 || resp.AccountPortalURL != "https://account.example.com" {
		t.Fatalf("a: %d %+v", code, resp)
	}
	if strings.Contains(raw, "unpaid") || strings.Contains(raw, "origin") || strings.Contains(raw, `"plan"`) {
		t.Fatalf("operator notes must not reach the organization: %s", raw)
	}
}

func TestWriteLimitError(t *testing.T) {
	rec := httptest.NewRecorder()
	if !WriteLimitError(rec, &limits.ErrLimitReached{Key: limits.Seats, Limit: 5, Used: 5}) {
		t.Fatal("not handled")
	}
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "LIMIT_REACHED") || strings.Contains(strings.ToLower(rec.Body.String()), "plan") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if WriteLimitError(httptest.NewRecorder(), errors.New("other")) {
		t.Fatal("other errors are not limit errors")
	}
}
