package unit

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
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

// The old tag params map onto the list query contract: tags + tags_mode=all
// is tag_all, exclude_tags is tag_not. The compiled filter is tenant scoped
// and binds the tags as values.
func TestAssetHandler_List_TagModes(t *testing.T) {
	h, repo := newTagFilterHandler()
	req := withTenantContext(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/assets?tags=env-prod,pci&tags_mode=all&exclude_tags=retired", nil))
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	all := repo.lastWhere.Where
	if all == nil || len(all.Args) == 0 || fmt.Sprint(all.Args[0]) != testTenantID.String() {
		t.Fatalf("list not tenant scoped: %+v", all)
	}
	if args := boundText(all.Args); !strings.Contains(args, "env-prod") || !strings.Contains(args, "pci") || !strings.Contains(args, "retired") {
		t.Fatalf("tags not bound: %s", args)
	}
	for _, v := range []string{"env-prod", "pci", "retired"} {
		if strings.Contains(all.SQL, v) {
			t.Fatalf("tag %q formatted into the SQL: %s", v, all.SQL)
		}
	}

	// any is the default; an exclusion alone needs no include list.
	rec = httptest.NewRecorder()
	h.List(rec, withTenantContext(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/assets?tags=env-prod,pci&exclude_tags=retired", nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("any default: %d (%s)", rec.Code, rec.Body.String())
	}
	if repo.lastWhere.Where.SQL == all.SQL {
		t.Fatal("tags_mode=all compiled to the same filter as the any default")
	}
	rec = httptest.NewRecorder()
	h.List(rec, withTenantContext(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/assets?exclude_tags=b,c", nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("exclusion alone: %d (%s)", rec.Code, rec.Body.String())
	}
}

// A bad tags_mode, a tag longer than any stored tag and more than 20 tags
// are refused (400 INVALID_FILTER on the list query contract), never
// silently widened.
func TestAssetHandler_List_TagModeValidation(t *testing.T) {
	h, _ := newTagFilterHandler()
	long := strings.Repeat("x", 51)
	many := make([]string, 21)
	for i := range many {
		many[i] = fmt.Sprint(i + 1)
	}
	for _, q := range []string{
		"tags_mode=some",
		"exclude_tags=" + long,
		"exclude_tags=" + strings.Join(many, ","),
		"tags=" + long,
		"tags=" + strings.Join(many, ","),
		"tags=" + strings.Join(many, ",") + "&tags_mode=all",
	} {
		rec := httptest.NewRecorder()
		h.List(rec, withTenantContext(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/assets?"+q, nil)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", q, rec.Code)
		}
	}
	// The bounds themselves are allowed.
	rec := httptest.NewRecorder()
	h.List(rec, withTenantContext(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/assets?tags="+strings.Repeat("x", 50)+"&exclude_tags="+strings.Join(many[:20], ","), nil)))
	if rec.Code != http.StatusOK {
		t.Errorf("tags at the bounds: status = %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestAssetHandler_ListTags_SystemTagsForNonOwner(t *testing.T) {
	h, repo := newTagFilterHandler()
	user := shared.NewID()
	req := withTenantContext(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/assets/tags?q=prod&include_system=true&type=domain&limit=10", nil))
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
	h.ListTags(rec, withTenantContext(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/assets/tags", nil)))
	if rec.Code != http.StatusOK || repo.lastTagQuery.IncludeSystem || repo.lastTagQuery.ProgramTagViewer != nil {
		t.Fatalf("plain list: %d %+v", rec.Code, repo.lastTagQuery)
	}
	if json.Unmarshal(rec.Body.Bytes(), &body) != nil {
		t.Fatal("bad json")
	}
}

// boundText renders bound args as the driver sees them (arrays as text).
func boundText(args []any) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if v, ok := a.(driver.Valuer); ok {
			if dv, err := v.Value(); err == nil {
				out = append(out, fmt.Sprint(dv))
				continue
			}
		}
		out = append(out, fmt.Sprint(a))
	}
	return strings.Join(out, " ")
}
