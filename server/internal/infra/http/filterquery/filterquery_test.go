package filterquery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/pkg/filterspec"
)

func testRoute(mode filterspec.UnknownMode) Route {
	reg := filterspec.MustRegistry(filterspec.Registry{
		Name: "things", TenantSQL: "t.tenant_id", ScopeAssetSQL: "t.asset_id", IDSQL: "t.id",
		Aliases: map[string]filterspec.Alias{"severities": {To: "severity"}},
	}, filterspec.Field{Name: "severity", Type: filterspec.TypeEnum, Enum: []string{"high", "low"}, Ops: []filterspec.Op{filterspec.OpIn}, SQL: "t.severity"})
	return Route{
		Name: "GET /things", Registry: reg, Options: filterspec.Options{Unknown: mode},
		DeprecatedAt: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC),
		SunsetAt:     time.Date(2027, 4, 4, 0, 0, 0, 0, time.UTC),
	}
}

func TestAliasHeadersAndMetric(t *testing.T) {
	rt := testRoute(filterspec.UnknownWarn)
	before := testutil.ToFloat64(DeprecatedParamRequests.WithLabelValues(rt.Name, "severities", "anonymous"))
	w := httptest.NewRecorder()
	spec, ok := rt.ParseQuery(w, httptest.NewRequest(http.MethodGet, "/things?severities=high", nil))
	if !ok || len(spec.Leaves()) != 1 {
		t.Fatalf("alias should work: %+v", spec)
	}
	if w.Header().Get("Deprecation") != "@"+strconv.FormatInt(rt.DeprecatedAt.Unix(), 10) || w.Header().Get("Sunset") == "" {
		t.Fatalf("headers: %v", w.Header())
	}
	if !strings.Contains(w.Header().Get("Warning"), "severities is deprecated; use severity") {
		t.Fatalf("warning: %v", w.Header())
	}
	if got := testutil.ToFloat64(DeprecatedParamRequests.WithLabelValues(rt.Name, "severities", "anonymous")); got != before+1 {
		t.Fatalf("metric: %v -> %v", before, got)
	}
}

func TestUnknownWarnMode(t *testing.T) {
	rt := testRoute(filterspec.UnknownWarn)
	w := httptest.NewRecorder()
	before := testutil.ToFloat64(UnknownParamRequests.WithLabelValues(rt.Name, "source_id"))
	_, ok := rt.ParseQuery(w, httptest.NewRequest(http.MethodGet, "/things?severity=high&source_id=secret-value&%3Cscript%3E=1", nil))
	if !ok {
		t.Fatal("warn mode must not reject")
	}
	warn := strings.Join(w.Header().Values("Warning"), " | ")
	if !strings.Contains(warn, "source_id") || strings.Contains(warn, "secret-value") || strings.Contains(warn, "<script>") {
		t.Fatalf("warning must name safe params only, never values: %q", warn)
	}
	if w.Header().Get("Deprecation") == "" {
		t.Fatal("unknown params must carry Deprecation in warn mode")
	}
	if got := testutil.ToFloat64(UnknownParamRequests.WithLabelValues(rt.Name, "source_id")); got != before+1 {
		t.Fatalf("metric not counted: %v", got)
	}
}

func TestUnknownStrictModeIs400(t *testing.T) {
	rt := testRoute(filterspec.UnknownStrict)
	w := httptest.NewRecorder()
	if _, ok := rt.ParseQuery(w, httptest.NewRequest(http.MethodGet, "/things?source_id=x", nil)); ok {
		t.Fatal("strict mode must reject")
	}
	assertInvalidFilter(t, w, "source_id")
}

func TestBadValueIs400InWarnMode(t *testing.T) {
	rt := testRoute(filterspec.UnknownWarn)
	w := httptest.NewRecorder()
	if _, ok := rt.ParseQuery(w, httptest.NewRequest(http.MethodGet, "/things?severity=urgent", nil)); ok {
		t.Fatal("a bad value must be rejected in every mode")
	}
	assertInvalidFilter(t, w, "severity")
}

func TestParseBodyLimit(t *testing.T) {
	rt := testRoute(filterspec.UnknownWarn)
	w := httptest.NewRecorder()
	body := `{"q":"` + strings.Repeat("a", filterspec.MaxBodyBytes+10) + `"}`
	if _, ok := rt.ParseBody(w, httptest.NewRequest(http.MethodPost, "/things/search", strings.NewReader(body))); ok {
		t.Fatal("an oversized body must be rejected")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
	w = httptest.NewRecorder()
	spec, ok := rt.ParseBody(w, httptest.NewRequest(http.MethodPost, "/things/search", strings.NewReader(`{"filter":{"severity":["high"]}}`)))
	if !ok || len(spec.Leaves()) != 1 {
		t.Fatalf("body: %d %s", w.Code, w.Body.String())
	}
}

func TestUnknownLabelIsBounded(t *testing.T) {
	for i := 0; i < maxUnknownLabels*2; i++ {
		unknownLabel("p" + strings.Repeat("x", i%60) + string(rune('a'+i%26)))
	}
	if got := unknownLabel("brand_new_name_after_cap"); got != "other" {
		t.Fatalf("label set must be capped, got %q", got)
	}
	if got := unknownLabel("Weird-Name"); got != "other" {
		t.Fatalf("unsafe names must be other, got %q", got)
	}
}

func assertInvalidFilter(t *testing.T, w *httptest.ResponseRecorder, param string) {
	t.Helper()
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
	var body struct {
		Code    string              `json:"code"`
		Details []filterspec.Detail `json:"details"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "INVALID_FILTER" || len(body.Details) == 0 || body.Details[0].Param != param {
		t.Fatalf("body: %s", w.Body.String())
	}
}
