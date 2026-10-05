package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func postSchedulePreview(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewScanHandler(nil, nil, nil, nil, logger.NewNop())
	req := reqWithTenant("/api/v1/scans/schedule-preview", shared.NewID())
	req.Method = http.MethodPost
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.PreviewSchedule(rec, req)
	return rec
}

func httpBody(s string) *readCloser { return &readCloser{strings.NewReader(s)} }

type readCloser struct{ *strings.Reader }

func (readCloser) Close() error { return nil }

func TestPreviewSchedule_ListsOccurrencesInTimezone(t *testing.T) {
	rec := postSchedulePreview(t, `{"schedule_type":"weekly","schedule_day":1,"schedule_time":"02:30","timezone":"Asia/Tokyo","count":3}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var resp SchedulePreviewResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Timezone != "Asia/Tokyo" || len(resp.Occurrences) != 3 {
		t.Fatalf("resp = %+v", resp)
	}
	var prev time.Time
	for _, s := range resp.Occurrences {
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatalf("occurrence %q is not RFC 3339: %v", s, err)
		}
		if !strings.HasSuffix(s, "+09:00") {
			t.Errorf("occurrence %q not in the scan timezone", s)
		}
		if tm.Weekday() != time.Monday && tm.In(time.FixedZone("JST", 9*3600)).Weekday() != time.Monday {
			t.Errorf("occurrence %q is not a Monday in Tokyo", s)
		}
		if !prev.IsZero() && !tm.After(prev) {
			t.Errorf("occurrences out of order")
		}
		prev = tm
	}
}

func TestPreviewSchedule_RefusesWithTheSaveError(t *testing.T) {
	for name, body := range map[string]string{
		"too frequent": `{"schedule_type":"rrule","schedule_rrule":"FREQ=MINUTELY;INTERVAL=5"}`,
		"bad time":     `{"schedule_type":"daily","schedule_time":"25:99"}`,
		"bad json":     `{"schedule_type":`,
		"long rrule":   `{"schedule_type":"rrule","schedule_rrule":"` + strings.Repeat("A", 501) + `"}`,
		"count":        `{"schedule_type":"daily","schedule_time":"02:00","count":50}`,
		"oversized":    `{"schedule_type":"daily","x":"` + strings.Repeat("A", 5000) + `"}`,
	} {
		if rec := postSchedulePreview(t, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (%s)", name, rec.Code, rec.Body)
		}
	}
	rec := postSchedulePreview(t, `{"schedule_type":"rrule","schedule_rrule":"FREQ=MINUTELY;INTERVAL=5"}`)
	if !strings.Contains(rec.Body.String(), "minimum interval") {
		t.Errorf("the save rule's message is not passed through: %s", rec.Body)
	}
}
