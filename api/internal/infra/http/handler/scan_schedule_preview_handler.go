package handler

import (
	"encoding/json"
	"net/http"
	"time"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
)

// maxSchedulePreviewBody bounds the preview request body (a schedule is a
// few hundred bytes; the RRULE itself is capped at 500).
const maxSchedulePreviewBody = 4 << 10

// SchedulePreviewRequest is a schedule as create/update carry it, plus how
// many occurrences to list.
type SchedulePreviewRequest struct {
	ScheduleType  string  `json:"schedule_type"`
	ScheduleCron  string  `json:"schedule_cron"`
	ScheduleRRule string  `json:"schedule_rrule"`
	ScheduleDay   *int    `json:"schedule_day"`
	ScheduleTime  *string `json:"schedule_time"` // HH:MM
	Timezone      string  `json:"timezone"`
	// Count is how many occurrences to list, 1-10 (default 5).
	Count int `json:"count"`
}

// SchedulePreviewResponse lists a schedule's next occurrences.
type SchedulePreviewResponse struct {
	// Timezone the schedule is evaluated in (IANA; UTC when none was given).
	Timezone string `json:"timezone"`
	// Occurrences are RFC 3339 timestamps with the timezone's offset, in order.
	Occurrences []string `json:"occurrences"`
}

// PreviewSchedule handles POST /api/v1/scans/schedule-preview
// @Summary      Preview a scan schedule
// @Description  Validates a schedule exactly as saving a scan would (cron or
// @Description  RRULE, timezone, the 15-minute minimum) and lists its next
// @Description  occurrences in its timezone. Reads and stores nothing.
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        request  body      SchedulePreviewRequest  true  "Schedule"
// @Success      200  {object}  SchedulePreviewResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/schedule-preview [post]
func (h *ScanHandler) PreviewSchedule(w http.ResponseWriter, r *http.Request) {
	var req SchedulePreviewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSchedulePreviewBody)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if len(req.ScheduleCron) > 100 || len(req.ScheduleRRule) > scan.MaxRRuleLength || len(req.Timezone) > 50 {
		apierror.BadRequest("schedule_cron, schedule_rrule or timezone is too long").WriteJSON(w)
		return
	}

	input := scansvc.SchedulePreviewInput{
		ScheduleType:  req.ScheduleType,
		ScheduleCron:  req.ScheduleCron,
		ScheduleRRule: req.ScheduleRRule,
		ScheduleDay:   req.ScheduleDay,
		Timezone:      req.Timezone,
		Count:         req.Count,
	}
	if req.ScheduleTime != nil && *req.ScheduleTime != "" {
		t, err := time.Parse("15:04", *req.ScheduleTime)
		if err != nil {
			apierror.BadRequest("Invalid schedule_time format, expected HH:MM").WriteJSON(w)
			return
		}
		input.ScheduleTime = &t
	}

	preview, err := scansvc.PreviewSchedule(input, time.Now())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := SchedulePreviewResponse{Timezone: preview.Timezone, Occurrences: make([]string, len(preview.Occurrences))}
	for i, t := range preview.Occurrences {
		resp.Occurrences[i] = t.Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
