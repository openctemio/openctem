package unit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func newTagFilterHandler() (*handler.AssetHandler, *HandlerMockRepository) {
	repo := NewHandlerMockRepository()
	log := logger.NewDevelopment()
	svc := assetapp.NewAssetService(repo, log)
	return handler.NewAssetHandler(svc, validator.New(), log), repo
}

func TestAssetHandler_List_TagModes(t *testing.T) {
	h, repo := newTagFilterHandler()
	req := withTenantContext(httptest.NewRequest(http.MethodGet, "/api/v1/assets?tags=env-prod,pci&tags_mode=all&exclude_tags=retired", nil))
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	f := repo.lastFilter
	if !slices.Equal(f.Tags, []string{"env-prod", "pci"}) || !f.TagsMatchAll || !slices.Equal(f.ExcludeTags, []string{"retired"}) {
		t.Fatalf("filter = tags %v all %v exclude %v", f.Tags, f.TagsMatchAll, f.ExcludeTags)
	}
	if f.TenantID == nil || *f.TenantID != testTenantID.String() {
		t.Fatalf("list not tenant scoped: %v", f.TenantID)
	}

	// any is the default; an exclusion alone needs no include list.
	rec = httptest.NewRecorder()
	h.List(rec, withTenantContext(httptest.NewRequest(http.MethodGet, "/api/v1/assets?tags=a&exclude_tags=b,c", nil)))
	if rec.Code != http.StatusOK || repo.lastFilter.TagsMatchAll || len(repo.lastFilter.ExcludeTags) != 2 {
		t.Fatalf("any default: %d all=%v exclude=%v", rec.Code, repo.lastFilter.TagsMatchAll, repo.lastFilter.ExcludeTags)
	}
}

func TestAssetHandler_List_TagModeValidation(t *testing.T) {
	h, _ := newTagFilterHandler()
	long := make([]byte, 51)
	for i := range long {
		long[i] = 'x'
	}
	for _, q := range []string{
		"tags_mode=some",
		"exclude_tags=" + string(long),
		"exclude_tags=1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21",
	} {
		rec := httptest.NewRecorder()
		h.List(rec, withTenantContext(httptest.NewRequest(http.MethodGet, "/api/v1/assets?"+q, nil)))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status = %d, want 422", q, rec.Code)
		}
	}
}

func TestAssetHandler_ListTags_SystemTagsForNonOwner(t *testing.T) {
	h, repo := newTagFilterHandler()
	user := shared.NewID()
	req := withTenantContext(httptest.NewRequest(http.MethodGet, "/api/v1/assets/tags?q=prod&include_system=true&type=domain&limit=10", nil))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserIDKey, user.String()))
	rec := httptest.NewRecorder()
	h.ListTags(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	q := repo.lastTagQuery
	if q.Search != "prod" || !q.IncludeSystem || q.Limit != 10 || !slices.Equal(q.Types, []string{"domain"}) {
		t.Fatalf("query = %+v", q)
	}
	// Not the tenant owner (no owner proof wired): the system tags are
	// narrowed to the programs not hidden from this user.
	if q.ProgramTagViewer == nil || *q.ProgramTagViewer != user {
		t.Fatalf("program tag viewer = %v, want %s", q.ProgramTagViewer, user)
	}
	var body struct {
		Tags       []string `json:"tags"`
		SystemTags []string `json:"system_tags"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(body.Tags, []string{"env-prod"}) || !slices.Equal(body.SystemTags, []string{"bug-bounty"}) {
		t.Fatalf("body = %+v", body)
	}

	// Without include_system: no viewer needed, no system tags returned.
	rec = httptest.NewRecorder()
	h.ListTags(rec, withTenantContext(httptest.NewRequest(http.MethodGet, "/api/v1/assets/tags", nil)))
	if rec.Code != http.StatusOK || repo.lastTagQuery.IncludeSystem || repo.lastTagQuery.ProgramTagViewer != nil {
		t.Fatalf("plain list: %d %+v", rec.Code, repo.lastTagQuery)
	}
	if json.Unmarshal(rec.Body.Bytes(), &body) != nil {
		t.Fatal("bad json")
	}
}
