package handler

// Content delivery to sensors (research/139 §3, RFC-061 §3.4):
//
//	GET /api/v2/sensor/content/desired                         the organization's desired set (ETag, 304)
//	GET /api/v2/sensor/content/packs/{digest}                  a pack's canonical archive (immutable)
//	GET /api/v2/sensor/content/packs/{digest}/index            its file index
//	GET /api/v2/sensor/content/packs/{digest}/files/{sha256}   one of its files
//
// A sensor reads only what its organization's sensors may hold (its
// organization's active packs, the platform's stable packs); anything else
// is content-not-found. Packs are signed by the platform and verified by
// the sensor, which also checks every archive against its digest.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"

	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// ContentDelivery is what the content routes need (contentpackapp.Delivery).
type ContentDelivery interface {
	Desired(ctx context.Context, tenantID string) (*contentpackapp.Desired, string, error)
	Archive(ctx context.Context, tenantID, digest string) ([]byte, error)
	Index(ctx context.Context, tenantID, digest string) ([]contentpackapp.IndexEntry, error)
	File(ctx context.Context, tenantID, digest, sha string) ([]byte, error)
}

// SensorContentV2Handler serves content to sensors.
type SensorContentV2Handler struct {
	delivery ContentDelivery
	logger   *logger.Logger
}

// NewSensorContentV2Handler builds the content routes' handler.
func NewSensorContentV2Handler(d ContentDelivery, log *logger.Logger) *SensorContentV2Handler {
	return &SensorContentV2Handler{delivery: d, logger: log}
}

var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (h *SensorContentV2Handler) fail(w http.ResponseWriter, route string, err error) {
	if errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrValidation) {
		protov2.NewProblem(protov2.ProblemContentNotFound).Write(w)
		return
	}
	h.logger.Error("v2 sensor content request failed", "route", route, "error", sanitizeLogField(err.Error()))
	protov2.NewProblem(protov2.ProblemInternal).Write(w)
}

// Desired serves the organization's desired document; If-None-Match with
// the current ETag answers 304 with no body.
func (h *SensorContentV2Handler) Desired(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	doc, etag, err := h.delivery.Desired(r.Context(), s.TenantID.String())
	if err != nil {
		h.fail(w, "content_desired", err)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", protov2.MediaTypeJSON)
	_ = json.NewEncoder(w).Encode(doc)
}

// immutable serves bytes addressed by their hash: the ETag is the hash and
// the answer never changes, so If-None-Match is a 304.
func immutable(w http.ResponseWriter, r *http.Request, etag, contentType string, b []byte) {
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	w.Header().Set("Content-Type", contentType)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(b))
}

// Pack serves a pack's canonical archive (Range supported, for resumes).
func (h *SensorContentV2Handler) Pack(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	digest := chi.URLParam(r, "digest")
	b, err := h.delivery.Archive(r.Context(), s.TenantID.String(), digest)
	if err != nil {
		h.fail(w, "content_pack", err)
		return
	}
	immutable(w, r, `"`+digest+`"`, "application/x-tar", b)
}

// Index serves a pack's file index.
func (h *SensorContentV2Handler) Index(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	digest := chi.URLParam(r, "digest")
	idx, err := h.delivery.Index(r.Context(), s.TenantID.String(), digest)
	if err != nil {
		h.fail(w, "content_index", err)
		return
	}
	b, err := json.Marshal(idx)
	if err != nil {
		h.fail(w, "content_index", err)
		return
	}
	immutable(w, r, `"index-`+digest+`"`, protov2.MediaTypeJSON, b)
}

// File serves one file of a pack by its sha256.
func (h *SensorContentV2Handler) File(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	sha := chi.URLParam(r, "sha256")
	if !sha256HexRE.MatchString(sha) {
		protov2.NewProblem(protov2.ProblemContentNotFound).Write(w)
		return
	}
	b, err := h.delivery.File(r.Context(), s.TenantID.String(), chi.URLParam(r, "digest"), sha)
	if err != nil {
		h.fail(w, "content_file", err)
		return
	}
	immutable(w, r, `"`+sha+`"`, "application/octet-stream", b)
}
