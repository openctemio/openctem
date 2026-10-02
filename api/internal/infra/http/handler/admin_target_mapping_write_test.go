package handler

import (
	"bytes"
	"context"
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
	m := tool.NewTargetAssetTypeMapping("url", asset.AssetTypeWebsite)
	m.Priority = priority
	require.NoError(t, f.Create(context.Background(), m))
	return m
}

func opsAdminRequest(t *testing.T, method, target, body string, id string) *http.Request {
	t.Helper()
	a, err := admin.NewAdminUser("ops@example.test", "Ops", admin.AdminRoleOpsAdmin, nil)
	require.NoError(t, err)
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
		{"defaults are valid", `{"target_type":"url","asset_type":"api"}`, http.StatusCreated, ""},
		{"primary", `{"target_type":"url","asset_type":"api","is_primary":true}`, http.StatusCreated, ""},
		{"min priority", `{"target_type":"url","asset_type":"api","priority":1}`, http.StatusCreated, ""},
		{"max priority", `{"target_type":"url","asset_type":"api","priority":1000}`, http.StatusCreated, ""},
		{"zero priority", `{"target_type":"url","asset_type":"api","priority":0}`, http.StatusBadRequest, "priority must be between 1 and 1000"},
		{"negative priority", `{"target_type":"url","asset_type":"api","priority":-5}`, http.StatusBadRequest, "priority must be between 1 and 1000"},
		{"priority too high", `{"target_type":"url","asset_type":"api","priority":1001}`, http.StatusBadRequest, "priority must be between 1 and 1000"},
		{"description at limit", `{"target_type":"url","asset_type":"api","description":"` + long[1:] + `"}`, http.StatusCreated, ""},
		{"description too long", `{"target_type":"url","asset_type":"api","description":"` + long + `"}`, http.StatusBadRequest, "description must be at most 500 characters"},
		{"duplicate pair", `{"target_type":"url","asset_type":"website"}`, http.StatusConflict, "target type url is already mapped to asset type website"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newFakeTargetMappingRepo()
			repo.seed(t, 10) // url -> website
			h := NewAdminTargetMappingHandler(repo, logger.NewNop())

			w := httptest.NewRecorder()
			h.Create(w, opsAdminRequest(t, http.MethodPost, "/api/v1/admin/target-mappings", tt.body, ""))

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
		h.Update(w, opsAdminRequest(t, http.MethodPatch, "/x", `{"priority":0}`, m.ID.String()))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, 20, repo.byID[m.ID.String()].Priority)
	})

	t.Run("rejects a description that is too long", func(t *testing.T) {
		repo := newFakeTargetMappingRepo()
		m := repo.seed(t, 20)
		h := NewAdminTargetMappingHandler(repo, logger.NewNop())
		body := `{"description":"` + strings.Repeat("é", tool.MaxMappingDescriptionLength+1) + `"}`

		w := httptest.NewRecorder()
		h.Update(w, opsAdminRequest(t, http.MethodPatch, "/x", body, m.ID.String()))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("a stored legacy priority does not block an unrelated edit", func(t *testing.T) {
		repo := newFakeTargetMappingRepo()
		m := repo.seed(t, 5000) // written before the bounds existed
		h := NewAdminTargetMappingHandler(repo, logger.NewNop())

		w := httptest.NewRecorder()
		h.Update(w, opsAdminRequest(t, http.MethodPatch, "/x", `{"is_active":false}`, m.ID.String()))

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.False(t, repo.byID[m.ID.String()].IsActive)
	})

	t.Run("is_primary wins over an invalid priority", func(t *testing.T) {
		repo := newFakeTargetMappingRepo()
		m := repo.seed(t, 20)
		h := NewAdminTargetMappingHandler(repo, logger.NewNop())

		w := httptest.NewRecorder()
		h.Update(w, opsAdminRequest(t, http.MethodPatch, "/x", `{"is_primary":true,"priority":0}`, m.ID.String()))

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
