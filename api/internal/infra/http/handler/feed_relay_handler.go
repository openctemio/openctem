package handler

// Feed relay routes (docs/rfcs/RFC-142-feed-relay.md). Sensor side, under
// /api/v2/sensor: the designated platform relay sensor asks for its next
// round, uploads the files, and reports the round. Admin side: the status
// and the setting (mode, relay sensor).

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/feedrelay"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	dom "github.com/openctemio/openctem/api/pkg/domain/feedrelay"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// FeedRelayUploadLimit bounds one uploaded file (the round's cap is
// checked too).
const FeedRelayUploadLimit = feedrelay.MaxFileBytes

// FeedRelayHandler serves the feed relay routes.
type FeedRelayHandler struct {
	svc    *feedrelay.Service
	logger *logger.Logger
}

// NewFeedRelayHandler creates the handler.
func NewFeedRelayHandler(svc *feedrelay.Service, log *logger.Logger) *FeedRelayHandler {
	return &FeedRelayHandler{svc: svc, logger: log.With("handler", "feed_relay")}
}

// relaySensor returns the authenticated platform sensor. An organization's
// sensor gets 403 scope-denied, like every other reason a sensor may not
// relay (one answer).
func (h *FeedRelayHandler) relaySensor(w http.ResponseWriter, r *http.Request) (*sensor.Sensor, bool) {
	s := SensorFromContext(r.Context())
	if s == nil {
		protov2.NewProblem(protov2.ProblemUnauthenticated).Write(w)
		return nil, false
	}
	if !s.IsShared() || s.TenantID != nil {
		protov2.NewProblem(protov2.ProblemScopeDenied).Write(w)
		return nil, false
	}
	return s, true
}

func (h *FeedRelayHandler) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, feedrelay.ErrNotRelay):
		protov2.NewProblem(protov2.ProblemScopeDenied).Write(w)
	case errors.Is(err, feedrelay.ErrRoundClosed):
		protov2.NewProblem(protov2.ProblemCommandNotFound).Write(w)
	case errors.Is(err, feedrelay.ErrFileRefused):
		protov2.NewProblem(protov2.ProblemDigestMismatch).Write(w)
	case errors.Is(err, feedrelay.ErrQuota):
		protov2.NewProblem(protov2.ProblemContentTooLarge).Write(w)
	default:
		h.logger.Error("feed relay", "error", logger.SanitizeError(err))
		protov2.NewProblem(protov2.ProblemInternal).Write(w)
	}
}

// Next answers GET /api/v2/sensor/feed-relay/next: 200 with the round and
// its signed statement, 204 with a Retry-After (seconds) when there is none.
func (h *FeedRelayHandler) Next(w http.ResponseWriter, r *http.Request) {
	ref, ok := h.relaySensor(w, r)
	if !ok {
		return
	}
	n, retry, err := h.svc.Next(r.Context(), ref)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	if n == nil {
		if retry > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)))
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(n)
}

// Upload answers PUT /api/v2/sensor/feed-relay/{round}/files/{name}. The
// body is streamed to the spool; Content-Length and a sha-256
// Content-Digest are required.
func (h *FeedRelayHandler) Upload(w http.ResponseWriter, r *http.Request) {
	ref, ok := h.relaySensor(w, r)
	if !ok {
		return
	}
	if r.ContentLength < 0 {
		protov2.NewProblem(protov2.ProblemLengthRequired).Write(w)
		return
	}
	if r.ContentLength > FeedRelayUploadLimit {
		protov2.NewProblem(protov2.ProblemContentTooLarge).WithLimit(FeedRelayUploadLimit).Write(w)
		return
	}
	digest, ok := sha256Digest(r.Header.Get("Content-Digest"))
	if !ok {
		protov2.NewProblem(protov2.ProblemDigestRequired).Write(w)
		return
	}
	body := http.MaxBytesReader(w, r.Body, FeedRelayUploadLimit)
	if err := h.svc.Receive(r.Context(), ref, chi.URLParam(r, "round_id"), chi.URLParam(r, "name"), body, r.ContentLength, digest); err != nil {
		h.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Done answers POST /api/v2/sensor/feed-relay/{round}/done.
func (h *FeedRelayHandler) Done(w http.ResponseWriter, r *http.Request) {
	ref, ok := h.relaySensor(w, r)
	if !ok {
		return
	}
	var rep dom.Report
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(&rep); err != nil {
		protov2.NewProblem(protov2.ProblemInvalidJSON).Write(w)
		return
	}
	if err := h.svc.Done(r.Context(), ref, chi.URLParam(r, "round_id"), rep); err != nil {
		h.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// sha256Digest reads the sha-256 member of an RFC 9530 Content-Digest.
func sha256Digest(v string) (string, bool) {
	for _, part := range strings.Split(v, ",") {
		k, val, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found || !strings.EqualFold(k, "sha-256") {
			continue
		}
		val = strings.TrimSuffix(strings.TrimPrefix(val, ":"), ":")
		b, err := base64.StdEncoding.DecodeString(val)
		if err != nil || len(b) != 32 {
			return "", false
		}
		return hex.EncodeToString(b), true
	}
	return "", false
}

// --- admin ---

// FeedRelayStatusResponse is the console view.
type FeedRelayStatusResponse struct {
	Mode    string `json:"mode"`
	Locked  string `json:"locked,omitempty"`
	Version int    `json:"version"`
	// SensorIDs are the designated relay sensors (one to three in relay
	// mode).
	SensorIDs []string `json:"sensor_ids"`
	// Bootstrap: relay mode chosen at install; the bundled sensor is
	// designated once it enrolls and reports feed.relay@1.
	Bootstrap bool                  `json:"bootstrap,omitempty"`
	Sensors   []FeedRelaySensorView `json:"sensors"`
	Feeds     []FeedRelayFeedStatus `json:"feeds"`
	// NotRelayed names feeds that stay idle in relay mode (program_feed).
	NotRelayed []string `json:"not_relayed"`
}

// FeedRelaySensorView is a designated relay sensor.
type FeedRelaySensorView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name,omitempty"`
	Status     string     `json:"status,omitempty"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	// CanRelay: an active platform sensor reporting feed.relay@1.
	CanRelay bool `json:"can_relay"`
	// Online: can relay and seen in the last 10 minutes.
	Online       bool       `json:"online"`
	LastServedAt *time.Time `json:"last_served_at,omitempty"`
	BytesToday   int64      `json:"bytes_today"`
}

// FeedRelayRoundView is one round.
type FeedRelayRoundView struct {
	Phase          string     `json:"phase"`
	Status         string     `json:"status"`
	ErrorCode      string     `json:"error_code,omitempty"`
	Refused        string     `json:"refused,omitempty"`
	Files          int        `json:"files"`
	Delivered      int        `json:"delivered"`
	BytesDelivered int64      `json:"bytes_delivered"`
	BytesWanted    int64      `json:"bytes_wanted"`
	ClaimedBy      string     `json:"claimed_by,omitempty"`
	ClaimedAt      *time.Time `json:"claimed_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	DeliveredAt    *time.Time `json:"delivered_at,omitempty"`
}

// FeedRelayFeedStatus is one feed.
type FeedRelayFeedStatus struct {
	Feed       string              `json:"feed"`
	Last       *FeedRelayRoundView `json:"last,omitempty"`
	LastImport *FeedRelayRoundView `json:"last_import,omitempty"`
	// Current is the round of the cycle in progress.
	Current *FeedRelayRoundView `json:"current,omitempty"`
	// AppliedSequence and PublishedAt describe the applied release;
	// AgeSeconds is now minus PublishedAt (the feed's age).
	AppliedSequence uint64     `json:"applied_sequence,omitempty"`
	PublishedAt     *time.Time `json:"published_at,omitempty"`
	AgeSeconds      *int64     `json:"age_seconds,omitempty"`
	// StaleReason is one code of a fixed list (no_relay_designated,
	// relay_offline, signer_refused, sensor_refused, upstream_missing,
	// pin_mismatch, verify_failed, rollback_refused, import_failed,
	// plan_failed, nothing_delivered, round_expired, spool_full), empty
	// when the feed is fine; StaleDetail completes signer_refused and
	// sensor_refused.
	StaleReason string `json:"stale_reason,omitempty"`
	StaleDetail string `json:"stale_detail,omitempty"`
}

func roundView(rd *dom.Round) *FeedRelayRoundView {
	if rd == nil {
		return nil
	}
	v := &FeedRelayRoundView{Phase: rd.Phase, Status: rd.Status, ErrorCode: rd.ErrorCode, Files: len(rd.Files),
		Delivered: rd.Delivered(), BytesDelivered: rd.DeliveredBytes, BytesWanted: rd.WantedBytes(), ClaimedAt: rd.ClaimedAt,
		CreatedAt: rd.CreatedAt, DeliveredAt: rd.DeliveredAt}
	if rd.SensorID != nil {
		v.ClaimedBy = rd.SensorID.String()
	}
	if rd.Report != nil {
		v.Refused = rd.Report.Refused
	}
	return v
}

// Status answers GET /api/v1/admin/settings/feed-relay.
// @Summary      Get the feed relay status
// @Description  How the platform receives its signed feeds: direct (the platform fetches them) or relay (designated platform sensors relay the files and the platform verifies them with each feed's pinned root, with no outbound feed request). Shows the relay sensors and, per feed, the applied release and its age, the cycle in progress and why the feed is stale. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  FeedRelayStatusResponse
// @Security     AdminAuth
// @Router       /admin/settings/feed-relay [get]
func (h *FeedRelayHandler) Status(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.Status(r.Context())
	if err != nil {
		h.logger.Error("feed relay status", "error", logger.SanitizeError(err))
		apierror.InternalServerError("feed relay status unavailable").WriteJSON(w)
		return
	}
	now := time.Now()
	out := FeedRelayStatusResponse{Mode: st.Settings.Mode, Locked: st.Settings.Locked, Version: st.Settings.Version,
		SensorIDs: st.Settings.SensorIDs, Bootstrap: st.Settings.Bootstrap, Sensors: []FeedRelaySensorView{},
		Feeds: []FeedRelayFeedStatus{}, NotRelayed: st.NotRelayed}
	for _, rs := range st.Sensors {
		v := FeedRelaySensorView{ID: rs.ID, CanRelay: rs.CanRelay, Online: rs.Online, LastServedAt: rs.LastServed, BytesToday: rs.BytesToday}
		if sn := rs.Sensor; sn != nil {
			v.Name, v.Status, v.LastSeenAt = sn.Name, string(sn.Status), sn.LastSeenAt
		}
		out.Sensors = append(out.Sensors, v)
	}
	for _, f := range st.Feeds {
		fv := FeedRelayFeedStatus{Feed: f.Feed, Last: roundView(f.Last), LastImport: roundView(f.LastImport), Current: roundView(f.Current),
			AppliedSequence: f.Freshness.Sequence, PublishedAt: f.Freshness.PublishedAt, StaleReason: f.StaleReason, StaleDetail: f.Detail}
		if p := f.Freshness.PublishedAt; p != nil {
			age := int64(now.Sub(*p) / time.Second)
			fv.AgeSeconds = &age
		}
		out.Feeds = append(out.Feeds, fv)
	}
	writeJSON(w, http.StatusOK, out)
}

// FeedRelayUpdateRequest changes the setting.
type FeedRelayUpdateRequest struct {
	Mode string `json:"mode"`
	// SensorIDs are the designated relay sensors: one to three active
	// platform sensors reporting feed.relay@1 (required in relay mode).
	SensorIDs       []string `json:"sensor_ids"`
	ExpectedVersion int      `json:"expected_version"`
}

// Update answers PUT /api/v1/admin/settings/feed-relay (super administrator,
// step-up, audited by the service).
// @Summary      Change the feed delivery
// @Description  Super admin with a step-up. relay: the designated platform sensors (one to three, each active and reporting feed.relay@1) relay every feed and the platform makes no outbound feed request; direct: the platform fetches its feeds. The mode and the sensors are saved together. Refused while a feed bundle directory is configured or without a job signer. Audited.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      FeedRelayUpdateRequest  true  "Delivery"
// @Success      200  {object}  FeedRelayStatusResponse
// @Security     AdminAuth
// @Router       /admin/settings/feed-relay [put]
func (h *FeedRelayHandler) Update(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req FeedRelayUpdateRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	if len(req.SensorIDs) > feedrelay.MaxRelays {
		apierror.BadRequest("at most three relay sensors").WriteJSON(w)
		return
	}
	_, err := h.svc.Update(r.Context(), actor, strings.TrimSpace(req.Mode), req.SensorIDs, req.ExpectedVersion,
		middleware.ClientIP(r), r.UserAgent())
	switch {
	case errors.Is(err, feedrelay.ErrInvalid):
		apierror.BadRequest("mode must be direct or relay, and relay needs one to three active platform sensors that can relay").WriteJSON(w)
		return
	case errors.Is(err, feedrelay.ErrLocked):
		apierror.Conflict("relay mode is not available on this installation").WriteJSON(w)
		return
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("the setting changed meanwhile; reload and try again").WriteJSON(w)
		return
	case err != nil:
		h.logger.Error("feed relay update", "error", logger.SanitizeError(err))
		apierror.InternalServerError("feed relay setting not saved").WriteJSON(w)
		return
	}
	h.Status(w, r)
}
