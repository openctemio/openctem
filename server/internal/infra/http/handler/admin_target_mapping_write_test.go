package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// fakeTargetMappingRepo keeps mappings in memory and, like the real table,
// refuses a second mapping for the same (target_type, asset_type) pair.
type fakeTargetMappingRepo struct {
	tool.TargetMappingRepository // only the CRUD methods below are used
	byID                         map[string]*tool.TargetAssetTypeMapping
}

func newFakeTargetMappingRepo() *fakeTargetMappingRepo {
	return &fakeTargetMappingRepo{byID: map[string]*tool.TargetAssetTypeMapping{}}
}

func (f *fakeTargetMappingRepo) Create(_ context.Context, m *tool.TargetAssetTypeMapping) error {
	for _, e := range f.byID {
		if e.TargetType == m.TargetType && e.AssetType == m.AssetType {
			return fmt.Errorf("%w: duplicate pair", shared.ErrAlreadyExists)
		}
	}
	cp := *m
	f.byID[m.ID.String()] = &cp
	return nil
}

func (f *fakeTargetMappingRepo) GetByID(_ context.Context, id shared.ID) (*tool.TargetAssetTypeMapping, error) {
	m, ok := f.byID[id.String()]
	if !ok {
		return nil, nil
	}
	cp := *m
	return &cp, nil
}

func (f *fakeTargetMappingRepo) Update(_ context.Context, m *tool.TargetAssetTypeMapping) error {
	cp := *m
	f.byID[m.ID.String()] = &cp
	return nil
}

func (f *fakeTargetMappingRepo) List(context.Context, tool.TargetMappingFilter, pagination.Pagination) (pagination.Result[*tool.TargetAssetTypeMapping], error) {
	return pagination.Result[*tool.TargetAssetTypeMapping]{}, nil
}

func (f *fakeTargetMappingRepo) seed(t *testing.T, priority int) *tool.TargetAssetTypeMapping {
	t.Helper()
	m := tool.NewTargetAssetTypeMapping("certificate", asset.AssetTypeDomain)
	m.Priority = priority
	require.NoError(t, f.Create(context.Background(), m))
	return m
}

func mappingSuperAdminRequest(t *testing.T, method, target, body string, id string) *http.Request {
	t.Helper()
	a, err := admin.NewAdminUser("root@example.test", "Root", admin.AdminRoleSuperAdmin, nil)
	require.NoError(t, err)
	// Every mapping write carries a reason; a body that has none gets one so
	// the tests exercise the field they are about.
	if method != http.MethodGet && !strings.Contains(body, `"reason"`) {
		const reason = `"reason":"Reviewed with the scanning team"`
		if strings.TrimSpace(body) == "" || strings.TrimSpace(body) == "{}" {
			body = "{" + reason + "}"
		} else {
			body = "{" + reason + "," + strings.TrimPrefix(strings.TrimSpace(body), "{")
		}
	}
	r := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	ctx := context.WithValue(r.Context(), middleware.AdminUserKey, a)
	if id != "" {
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", id)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rc)
	}
	return r.WithContext(ctx)
}

func TestAdminTargetMappingCreate_Validation(t *testing.T) {
	long := strings.Repeat("a", tool.MaxMappingDescriptionLength+1)
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantMsg    string
	}{
		{"defaults are valid", `{"target_type":"certificate","asset_type":"subdomain"}`, http.StatusCreated, ""},
		{"primary", `{"target_type":"certificate","asset_type":"subdomain","is_primary":true}`, http.StatusCreated, ""},
		{"min priority", `{"target_type":"certificate","asset_type":"subdomain","priority":1}`, http.StatusCreated, ""},
		{"max priority", `{"target_type":"certificate","asset_type":"subdomain","priority":1000}`, http.StatusCreated, ""},
		{"zero priority", `{"target_type":"certificate","asset_type":"subdomain","priority":0}`, http.StatusBadRequest, "priority must be between 1 and 1000"},
		{"negative priority", `{"target_type":"certificate","asset_type":"subdomain","priority":-5}`, http.StatusBadRequest, "priority must be between 1 and 1000"},
		{"priority too high", `{"target_type":"certificate","asset_type":"subdomain","priority":1001}`, http.StatusBadRequest, "priority must be between 1 and 1000"},
		{"description at limit", `{"target_type":"certificate","asset_type":"subdomain","description":"` + long[1:] + `"}`, http.StatusCreated, ""},
		{"description too long", `{"target_type":"certificate","asset_type":"subdomain","description":"` + long + `"}`, http.StatusBadRequest, "description must be at most 500 characters"},
		{"duplicate pair", `{"target_type":"certificate","asset_type":"domain"}`, http.StatusConflict, "target type certificate is already mapped to asset type domain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newFakeTargetMappingRepo()
			repo.seed(t, 10) // certificate -> domain
			h := NewAdminTargetMappingHandler(repo, logger.NewNop())

			w := httptest.NewRecorder()
			h.Create(w, mappingSuperAdminRequest(t, http.MethodPost, "/api/v1/admin/target-mappings", tt.body, ""))

			assert.Equal(t, tt.wantStatus, w.Code, w.Body.String())
			if tt.wantMsg != "" {
				assert.Contains(t, w.Body.String(), tt.wantMsg)
			}
			if tt.wantStatus != http.StatusCreated {
				assert.Len(t, repo.byID, 1, "a rejected request must not store anything")
			}
		})
	}
}

func TestAdminTargetMappingUpdate_Validation(t *testing.T) {
	t.Run("rejects an out-of-range priority and keeps the stored one", func(t *testing.T) {
		repo := newFakeTargetMappingRepo()
		m := repo.seed(t, 20)
		h := NewAdminTargetMappingHandler(repo, logger.NewNop())

		w := httptest.NewRecorder()
		h.Update(w, mappingSuperAdminRequest(t, http.MethodPatch, "/x", `{"priority":0}`, m.ID.String()))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, 20, repo.byID[m.ID.String()].Priority)
	})

	t.Run("rejects a description that is too long", func(t *testing.T) {
		repo := newFakeTargetMappingRepo()
		m := repo.seed(t, 20)
		h := NewAdminTargetMappingHandler(repo, logger.NewNop())
		body := `{"description":"` + strings.Repeat("é", tool.MaxMappingDescriptionLength+1) + `"}`

		w := httptest.NewRecorder()
		h.Update(w, mappingSuperAdminRequest(t, http.MethodPatch, "/x", body, m.ID.String()))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("a stored legacy priority does not block an unrelated edit", func(t *testing.T) {
		repo := newFakeTargetMappingRepo()
		m := repo.seed(t, 5000) // written before the bounds existed
		h := NewAdminTargetMappingHandler(repo, logger.NewNop())

		w := httptest.NewRecorder()
		h.Update(w, mappingSuperAdminRequest(t, http.MethodPatch, "/x", `{"is_active":false}`, m.ID.String()))

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.False(t, repo.byID[m.ID.String()].IsActive)
	})

	t.Run("is_primary wins over an invalid priority", func(t *testing.T) {
		repo := newFakeTargetMappingRepo()
		m := repo.seed(t, 20)
		h := NewAdminTargetMappingHandler(repo, logger.NewNop())

		w := httptest.NewRecorder()
		h.Update(w, mappingSuperAdminRequest(t, http.MethodPatch, "/x", `{"is_primary":true,"priority":0}`, m.ID.String()))

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, tool.PrimaryMappingPriority, repo.byID[m.ID.String()].Priority)
	})
}

func TestValidateMappingFields(t *testing.T) {
	assert.NoError(t, tool.ValidateMappingPriority(tool.MinMappingPriority))
	assert.NoError(t, tool.ValidateMappingPriority(tool.MaxMappingPriority))
	assert.True(t, shared.IsValidation(tool.ValidateMappingPriority(0)))
	assert.True(t, shared.IsValidation(tool.ValidateMappingPriority(tool.MaxMappingPriority+1)))
	// Counted in characters, not bytes.
	assert.NoError(t, tool.ValidateMappingDescription(strings.Repeat("é", tool.MaxMappingDescriptionLength)))
	assert.True(t, shared.IsValidation(tool.ValidateMappingDescription(strings.Repeat("a", tool.MaxMappingDescriptionLength+1))))
}

// The registry is the one built-in source: a pair it already declares is
// refused, and nothing is stored.
func TestAdminTargetMappingCreate_RegistryCoveredPairIsRefused(t *testing.T) {
	for _, body := range []string{
		`{"target_type":"url","asset_type":"website"}`,
		`{"target_type":"domain","asset_type":"domain"}`,
		`{"target_type":"url","asset_type":"discovered_url"}`, // an alias name the registry stands for
	} {
		repo := newFakeTargetMappingRepo()
		h := NewAdminTargetMappingHandler(repo, logger.NewNop())
		w := httptest.NewRecorder()
		h.Create(w, mappingSuperAdminRequest(t, http.MethodPost, "/api/v1/admin/target-mappings", body, ""))
		assert.Equal(t, http.StatusConflict, w.Code, body+" "+w.Body.String())
		assert.Contains(t, w.Body.String(), "already covered by the asset type registry")
		assert.Empty(t, repo.byID, "nothing may be stored")
	}
	// A pair the registry does not declare is still accepted.
	repo := newFakeTargetMappingRepo()
	h := NewAdminTargetMappingHandler(repo, logger.NewNop())
	w := httptest.NewRecorder()
	h.Create(w, mappingSuperAdminRequest(t, http.MethodPost, "/api/v1/admin/target-mappings", `{"target_type":"certificate","asset_type":"domain"}`, ""))
	assert.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}

// The built-in pairs are listed read-only and agree with the Create rule.
func TestAdminTargetMappingRegistry(t *testing.T) {
	h := NewAdminTargetMappingHandler(newFakeTargetMappingRepo(), logger.NewNop())
	w := httptest.NewRecorder()
	h.Registry(w, httptest.NewRequest(http.MethodGet, "/api/v1/admin/target-mappings/registry", nil))
	require.Equal(t, http.StatusOK, w.Code)
	var resp RegistryTargetPairsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Data)
	found := false
	for _, p := range resp.Data {
		assert.True(t, tool.IsValidTargetType(p.TargetType), p.TargetType)
		if p.TargetType == "domain" && p.AssetType == "domain" {
			found = true
		}
	}
	assert.True(t, found, "domain -> domain is a built-in pair")
}

// A read-only administrator can neither add nor change a mapping.
func TestAdminTargetMappingWrites_ReadOnlyAdminRefused(t *testing.T) {
	a, err := admin.NewAdminUser("ro@example.test", "Read", admin.AdminRoleReadonly, nil)
	require.NoError(t, err)
	repo := newFakeTargetMappingRepo()
	m := repo.seed(t, 20)
	h := NewAdminTargetMappingHandler(repo, logger.NewNop())
	req := func(method, body string) *http.Request {
		r := httptest.NewRequest(method, "/x", bytes.NewBufferString(body))
		return r.WithContext(context.WithValue(r.Context(), middleware.AdminUserKey, a))
	}
	w := httptest.NewRecorder()
	h.Create(w, req(http.MethodPost, `{"target_type":"certificate","asset_type":"subdomain"}`))
	assert.Equal(t, http.StatusForbidden, w.Code)
	w = httptest.NewRecorder()
	h.Update(w, opsAsReadonly(a, req(http.MethodPatch, `{"priority":5}`), m.ID.String()))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Len(t, repo.byID, 1)
	assert.Equal(t, 20, repo.byID[m.ID.String()].Priority)
}

func opsAsReadonly(_ *admin.AdminUser, r *http.Request, id string) *http.Request {
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}
