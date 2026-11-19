package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/server/internal/app/feedstatus"
	"github.com/openctemio/openctem/server/internal/app/feedwatch"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type staticFeeds []feedstatus.View

func (s staticFeeds) FeedViews(context.Context) ([]feedstatus.View, error) { return s, nil }

func staleWatch(t *testing.T) *feedwatch.Service {
	t.Helper()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	asOf := now.Add(-3 * 24 * time.Hour)
	views := staticFeeds{{Source: feedstatus.SourceVulnfeed, Enabled: true, State: feedstatus.StateRefused,
		LastSyncStatus: "failed", ErrorCode: feedstatus.CodeExpired, LastSuccessAt: &asOf, DataAsOf: &asOf,
		Interval: feedstatus.IntervalVulnfeed}}
	w := feedwatch.New(views, nil, consolesettingtest.NewRepo(), logger.NewNop())
	w.SetClock(func() time.Time { return now })
	if _, err := w.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	return w
}

// Every signed-in user learns that the data is stale and since when, and
// nothing more: the error codes and explanations stay on the platform admin
// route.
func TestGetFreshness_TenantSeesStateOnly(t *testing.T) {
	h := NewThreatIntelHandler(nil, nil, logger.NewNop()).SetFreshness(staleWatch(t))
	rec := httptest.NewRecorder()
	h.GetFreshness(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/threat-intel/freshness", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	var got FreshnessResponse
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Stale || len(got.Reasons) != 1 || got.Reasons[0] != feedwatch.CodeDataStale ||
		got.StaleSince == nil || *got.StaleSince != "2026-11-15T12:00:00Z" || got.DataAsOf == nil {
		t.Fatalf("response: %s", body)
	}
	for _, leak := range []string{"expired", "refused", "detail", "conditions", "import_"} {
		if strings.Contains(body, leak) {
			t.Fatalf("tenant response carries %q: %s", leak, body)
		}
	}
}

func TestGetFreshnessAdmin_ListsConditions(t *testing.T) {
	h := NewThreatIntelHandler(nil, nil, logger.NewNop()).SetFreshness(staleWatch(t))
	rec := httptest.NewRecorder()
	h.GetFreshnessAdmin(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/admin/threat-intel/freshness", nil))
	var got AdminFreshnessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Stale || len(got.Conditions) != 2 {
		t.Fatalf("response: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "the last import was refused (expired)") {
		t.Fatalf("no detail: %s", rec.Body.String())
	}
}

// Without the watch the route answers "not stale" (never an error that
// would put every page in a failed state).
func TestGetFreshness_NoWatch(t *testing.T) {
	h := NewThreatIntelHandler(nil, nil, logger.NewNop())
	rec := httptest.NewRecorder()
	h.GetFreshness(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"stale":false`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
