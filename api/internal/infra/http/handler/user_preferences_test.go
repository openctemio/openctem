package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// prefsUserRepo stores one user in memory; every other repository method
// panics on the nil embedded interface.
type prefsUserRepo struct {
	user.Repository
	u *user.User
}

func (f *prefsUserRepo) GetByID(_ context.Context, id shared.ID) (*user.User, error) {
	if f.u.ID() != id {
		return nil, shared.ErrNotFound
	}
	return f.u, nil
}

func (f *prefsUserRepo) Update(_ context.Context, u *user.User) error {
	f.u = u
	return nil
}

// TestUpdatePreferences_ReturnsPreferencesObject pins the PUT response to the
// same shape as GET /users/me/preferences. It used to return the whole user
// object; the web cached it under the preferences key, read theme/language as
// undefined, reset the form to system/en, and the next Save persisted those
// defaults (23a B4).
func TestUpdatePreferences_ReturnsPreferencesObject(t *testing.T) {
	u, err := user.New("ada@example.com", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	repo := &prefsUserRepo{u: u}
	h := NewUserHandler(tenant.NewUserService(repo, logger.NewNop()), nil, nil, validator.New(), logger.NewNop())

	body, _ := json.Marshal(map[string]string{"theme": "dark", "language": "vi"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/me/preferences", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.LocalUserKey, u))
	rec := httptest.NewRecorder()
	h.UpdatePreferences(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["theme"] != "dark" || got["language"] != "vi" {
		t.Errorf("response theme/language = %v/%v, want dark/vi: %v", got["theme"], got["language"], got)
	}
	for _, userField := range []string{"id", "email", "name", "preferences"} {
		if _, ok := got[userField]; ok {
			t.Errorf("response carries user field %q; want the preferences object only: %v", userField, got)
		}
	}
	if p := repo.u.Preferences(); p.Theme != "dark" || p.Language != "vi" {
		t.Errorf("stored preferences = %+v, want dark/vi", p)
	}
}
