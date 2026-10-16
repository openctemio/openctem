package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestRequireAdminStepUp(t *testing.T) {
	now := time.Now()
	a := admin.Reconstitute(shared.NewID(), "root@example.com", "Root", admin.AdminRoleSuperAdmin, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now)
	sess := &admin.Session{ID: shared.NewID(), AdminID: a.ID(), MFAVerified: true}

	cases := []struct {
		name      string
		confirmer AdminStepUpConfirmer
		noAdmin   bool
		header    string
		wantCode  int
		wantBody  string
		wantNext  bool
	}{
		{name: "no session", noAdmin: true, confirmer: AdminStepUpFunc(nil), wantCode: http.StatusUnauthorized},
		{name: "nil confirmer refuses", wantCode: http.StatusServiceUnavailable},
		{name: "no code", confirmer: refuse(admin.ErrStepUpRequired), wantCode: http.StatusUnauthorized, wantBody: string(CodeAdminStepUpRequired)},
		{name: "wrong code", header: "000000", confirmer: refuse(admin.ErrInvalidMFACode), wantCode: http.StatusUnauthorized, wantBody: string(CodeAdminStepUpRequired)},
		{name: "no authenticator", header: "123456", confirmer: refuse(admin.ErrStepUpUnavailable), wantCode: http.StatusForbidden, wantBody: string(CodeAdminStepUpUnavailable)},
		{name: "store error", header: "123456", confirmer: refuse(errors.New("db down")), wantCode: http.StatusInternalServerError},
		{name: "confirmed", header: " 123456 ", confirmer: AdminStepUpFunc(func(_ context.Context, got *admin.AdminUser, s *admin.Session, code, purpose string, _ AdminStepUpClient) error {
			if got != a || s != sess || code != "123456" || purpose != "admin.provision" {
				return errors.New("unexpected arguments")
			}
			return nil
		}), wantCode: http.StatusNoContent, wantNext: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				if !AdminSteppedUp(r.Context()) {
					t.Error("a confirmed request must carry the stepped-up mark")
				}
				w.WriteHeader(http.StatusNoContent)
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/administrators/", nil)
			if !tc.noAdmin {
				ctx := withAdmin(req.Context(), a, AdminAuthMethodSession)
				ctx = context.WithValue(ctx, AdminSessionKey, sess)
				req = req.WithContext(ctx)
			}
			if tc.header != "" {
				req.Header.Set(AdminStepUpHeader, tc.header)
			}
			rec := httptest.NewRecorder()
			var c AdminStepUpConfirmer
			if tc.confirmer != nil {
				c = tc.confirmer
			}
			RequireAdminStepUp(c, "admin.provision")(next).ServeHTTP(rec, req)
			if rec.Code != tc.wantCode || reached != tc.wantNext || !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("got %d next=%v %s; want %d next=%v %q", rec.Code, reached, rec.Body.String(), tc.wantCode, tc.wantNext, tc.wantBody)
			}
		})
	}
	if AdminSteppedUp(context.Background()) {
		t.Fatal("a plain context is not stepped up")
	}
}

func refuse(err error) AdminStepUpConfirmer {
	return AdminStepUpFunc(func(context.Context, *admin.AdminUser, *admin.Session, string, string, AdminStepUpClient) error {
		return err
	})
}
