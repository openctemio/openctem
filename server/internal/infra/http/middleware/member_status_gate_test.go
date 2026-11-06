package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

type staticMembershipReader struct{ m *tenantdom.Membership }

func (r staticMembershipReader) GetMembership(context.Context, shared.ID, shared.ID) (*tenantdom.Membership, error) {
	if r.m == nil {
		return nil, shared.ErrNotFound
	}
	return r.m, nil
}

func membershipWithStatus(userID, tenantID shared.ID, status tenantdom.MemberStatus) *tenantdom.Membership {
	return tenantdom.ReconstituteMembershipWithStatus(shared.NewID(), userID, tenantID, tenantdom.RoleAdmin, nil,
		time.Now(), status, nil, nil)
}

// Both membership gates (URL tenant and token tenant) admit an ACTIVE
// membership only. A suspended (disabled) or offboarded member, and a status
// added later, is refused: the gate is a positive check (member lifecycle).
func TestMembershipGates_AdmitActiveOnly(t *testing.T) {
	u, err := userdom.New("gate@example.com", "Gate")
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	tenantID := shared.NewID()
	cases := []struct {
		status tenantdom.MemberStatus
		want   int
	}{
		{tenantdom.MemberStatusActive, http.StatusOK},
		{tenantdom.MemberStatusSuspended, http.StatusForbidden},
		{tenantdom.MemberStatusOffboarded, http.StatusForbidden},
		{tenantdom.MemberStatus("future_status"), http.StatusForbidden},
	}
	for _, c := range cases {
		reader := staticMembershipReader{m: membershipWithStatus(u.ID(), tenantID, c.status)}
		ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

		// URL-tenant chain.
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/x/members", nil)
		ctx := context.WithValue(req.Context(), LocalUserKey, u)
		ctx = context.WithValue(ctx, TeamIDKey, tenantID)
		rec := httptest.NewRecorder()
		RequireMembership(reader)(ok).ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code != c.want {
			t.Errorf("RequireMembership(%s) = %d, want %d", c.status, rec.Code, c.want)
		}

		// Token-tenant chain (/me, notifications, websocket upgrade).
		req = httptest.NewRequest(http.MethodGet, "/api/v1/ws", nil)
		ctx = context.WithValue(req.Context(), LocalUserKey, u)
		ctx = context.WithValue(ctx, TenantIDKey, tenantID.String())
		rec = httptest.NewRecorder()
		RequireActiveMembershipFromJWT(reader)(ok).ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code != c.want {
			t.Errorf("RequireActiveMembershipFromJWT(%s) = %d, want %d", c.status, rec.Code, c.want)
		}
	}
}
