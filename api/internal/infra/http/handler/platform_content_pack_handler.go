package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PlatformContentPackHandler serves the platform content packs (RFC-061):
// /api/v1/admin/content-packs for platform administrators (ingest, revoke,
// channels) and /api/v1/platform-content-packs, read-only, for every
// organization.
type PlatformContentPackHandler struct {
	service *contentpackapp.PlatformService
	packs   *ContentPackHandler // shared error mapping
	logger  *logger.Logger
}

// NewPlatformContentPackHandler creates a PlatformContentPackHandler.
func NewPlatformContentPackHandler(svc *contentpackapp.PlatformService, log *logger.Logger) *PlatformContentPackHandler {
	l := log.With("handler", "platform_content_pack")
	return &PlatformContentPackHandler{service: svc, packs: &ContentPackHandler{logger: l}, logger: l}
}

// PlatformContentPackResponse is a platform content pack.
type PlatformContentPackResponse struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Kind         string                 `json:"kind"`
	Digest       string                 `json:"digest"`
	SizeBytes    int64                  `json:"size_bytes"`
	FileCount    int                    `json:"file_count"`
	Tier         string                 `json:"tier" enums:"T0,T1,T2"`
	Status       string                 `json:"status" enums:"active,revoked"`
	Source       string                 `json:"source" enums:"upload,https"`
	SourceRef    string                 `json:"source_ref,omitempty"`
	SourceDigest string                 `json:"source_digest,omitempty"`
	Lint         contentpack.LintReport `json:"lint"`
	CreatedAt    time.Time              `json:"created_at"`
	RevokedAt    *time.Time             `json:"revoked_at,omitempty"`
	RevokeReason string                 `json:"revoke_reason,omitempty"`
}

// PlatformContentPackListResponse is a page of platform packs.
type PlatformContentPackListResponse struct {
	Data  []PlatformContentPackResponse `json:"data"`
	Total int                           `json:"total"`
}

// ContentChannelResponse is one channel of a pack name.
type ContentChannelResponse struct {
	Name      string    `json:"name"`
	Channel   string    `json:"channel" enums:"stable,canary"`
	PackID    string    `json:"pack_id"`
	Version   string    `json:"version"`
	Digest    string    `json:"digest"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ContentChannelListResponse lists channels.
type ContentChannelListResponse struct {
	Data []ContentChannelResponse `json:"data"`
}

// RevokePlatformContentPackResponse is a revoked pack and its name's
// channels afterwards (rolled back to the previous good pack).
type RevokePlatformContentPackResponse struct {
	Pack     PlatformContentPackResponse `json:"pack"`
	Channels []ContentChannelResponse    `json:"channels"`
}

// ImportPlatformContentPackRequest fetches an upstream release.
type ImportPlatformContentPackRequest struct {
	Name               string `json:"name"`
	Version            string `json:"version"`
	Kind               string `json:"kind"`
	URL                string `json:"url"`
	Digest             string `json:"digest"`
	AcknowledgeSecrets bool   `json:"acknowledge_secrets"`
}

// SetContentChannelRequest points a channel at a pack.
type SetContentChannelRequest struct {
	PackID string `json:"pack_id"`
}

func toPlatformContentPackResponse(p *contentpack.PlatformPack) PlatformContentPackResponse {
	return PlatformContentPackResponse{
		ID: p.ID.String(), Name: p.Name, Version: p.Version, Kind: p.Kind, Digest: p.Digest,
		SizeBytes: p.SizeBytes, FileCount: p.FileCount, Tier: string(p.Tier), Status: string(p.Status),
		Source: string(p.Source), SourceRef: p.SourceRef, SourceDigest: p.SourceDigest, Lint: p.Lint,
		CreatedAt: p.CreatedAt, RevokedAt: p.RevokedAt, RevokeReason: p.RevokeReason,
	}
}

func toContentChannels(cs []contentpack.ChannelPointer) []ContentChannelResponse {
	out := make([]ContentChannelResponse, 0, len(cs))
	for _, c := range cs {
		out = append(out, ContentChannelResponse{Name: c.Name, Channel: string(c.Channel), PackID: c.PackID.String(),
			Version: c.Version, Digest: c.Digest, UpdatedAt: c.UpdatedAt})
	}
	return out
}

// List handles GET /api/v1/admin/content-packs and GET /api/v1/platform-content-packs
// @Summary      List platform content packs
// @Description  The platform's content packs, newest first.
// @Tags         Content Packs
// @Produce      json
// @Param        kind      query     string  false  "Kind"
// @Param        name      query     string  false  "Pack name"
// @Param        status    query     string  false  "Status"  Enums(active,revoked)
// @Param        page      query     int     false  "Page (from 1)"
// @Param        per_page  query     int     false  "Page size (default 50, max 100)"
// @Success      200  {object}  PlatformContentPackListResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /platform-content-packs [get]
// @Router       /admin/content-packs [get]
func (h *PlatformContentPackHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, ok := listPageMax(w, r, 50, 100)
	if !ok {
		return
	}
	packs, total, err := h.service.List(r.Context(),
		contentpack.Filter{Kind: q.Get("kind"), Name: q.Get("name"), Status: contentpack.Status(q.Get("status"))},
		page.Limit(), page.Offset())
	if err != nil {
		h.packs.handleError(w, err)
		return
	}
	resp := PlatformContentPackListResponse{Data: make([]PlatformContentPackResponse, 0, len(packs)), Total: total}
	for _, p := range packs {
		resp.Data = append(resp.Data, toPlatformContentPackResponse(p))
	}
	writeScanZoneJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/admin/content-packs/{id} and GET /api/v1/platform-content-packs/{id}
// @Summary      Get platform content pack
// @Tags         Content Packs
// @Produce      json
// @Param        id   path      string  true  "Platform content pack ID"
// @Success      200  {object}  PlatformContentPackResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /platform-content-packs/{id} [get]
// @Router       /admin/content-packs/{id} [get]
func (h *PlatformContentPackHandler) Get(w http.ResponseWriter, r *http.Request) {
	p, err := h.service.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		h.packs.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toPlatformContentPackResponse(p))
}

// Channels handles GET /api/v1/admin/content-packs/channels and GET /api/v1/platform-content-packs/channels
// @Summary      List content channels
// @Description  The stable and canary channel of each platform pack name.
// @Tags         Content Packs
// @Produce      json
// @Success      200  {object}  ContentChannelListResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /platform-content-packs/channels [get]
// @Router       /admin/content-packs/channels [get]
func (h *PlatformContentPackHandler) Channels(w http.ResponseWriter, r *http.Request) {
	cs, err := h.service.Channels(r.Context())
	if err != nil {
		h.packs.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, ContentChannelListResponse{Data: toContentChannels(cs)})
}

// SigningKey handles GET /api/v1/admin/content-packs/signing-key and GET /api/v1/platform-content-packs/signing-key
// @Summary      Platform content signing key
// @Description  The platform content-signing public key (Ed25519) every sensor pins to verify platform packs. Not a secret.
// @Tags         Content Packs
// @Produce      json
// @Success      200  {object}  ContentSigningKeyResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      503  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /platform-content-packs/signing-key [get]
// @Router       /admin/content-packs/signing-key [get]
func (h *PlatformContentPackHandler) SigningKey(w http.ResponseWriter, _ *http.Request) {
	pub, id, err := h.service.SigningKey()
	if err != nil {
		h.packs.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, ContentSigningKeyResponse{Algorithm: "ed25519", PublicKey: pub, KeyID: id})
}

// Upload handles POST /api/v1/admin/content-packs
// @Summary      Upload platform content pack
// @Description  multipart/form-data with name, version, kind, acknowledge_secrets and archive (tar or tar.gz). Files that fail lint (refused template protocols, YAML that is not a template) are left out of the pack and listed as warnings; the rest is canonicalised, classified and signed with the platform content key. Super admin.
// @Tags         Content Packs
// @Accept       mpfd
// @Produce      json
// @Param        name                 formData  string  true   "Pack name"
// @Param        version              formData  string  true   "Version"
// @Param        kind                 formData  string  true   "Kind"
// @Param        acknowledge_secrets  formData  bool    false  "Store despite suspected credentials"
// @Param        archive              formData  file    true   "tar or tar.gz"
// @Success      201  {object}  PlatformContentPackResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      413  {object}  apierror.Error
// @Failure      422  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /admin/content-packs [post]
func (h *PlatformContentPackHandler) Upload(w http.ResponseWriter, r *http.Request) {
	maxUpload := h.service.Limits().MaxUpload
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload+64<<10)
	mr, err := r.MultipartReader()
	if err != nil {
		apierror.BadRequest("Expected multipart/form-data").WriteJSON(w)
		return
	}
	var (
		in      contentpackapp.UploadInput
		archive []byte
	)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			h.writeReadError(w, err)
			return
		}
		if archive, err = h.packs.readPart(part, &in, archive, maxUpload); err != nil {
			h.writeReadError(w, err)
			return
		}
	}
	if archive == nil {
		apierror.BadRequest("archive is required").WriteJSON(w)
		return
	}
	p, err := h.service.Upload(r.Context(), contentpackapp.PlatformInput{
		Name: in.Name, Version: in.Version, Kind: in.Kind, AcknowledgeSecrets: in.AcknowledgeSecrets,
	}, bytes.NewReader(archive))
	if err != nil {
		h.packs.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusCreated, toPlatformContentPackResponse(p))
}

func (h *PlatformContentPackHandler) writeReadError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.Is(err, errUploadTooLarge) || errors.As(err, &tooLarge) {
		apierror.New(http.StatusRequestEntityTooLarge, apierror.CodeBadRequest,
			fmt.Sprintf("The archive is larger than %d bytes", h.service.Limits().MaxUpload)).WriteJSON(w)
		return
	}
	apierror.BadRequest("Invalid multipart body").WriteJSON(w)
}

// Import handles POST /api/v1/admin/content-packs/import
// @Summary      Import platform content pack from an upstream release
// @Description  Fetches url (https, public addresses only) and refuses it unless its sha256 equals digest, then ingests it like an upload (tar or tar.gz). Super admin.
// @Tags         Content Packs
// @Accept       json
// @Produce      json
// @Param        body  body      ImportPlatformContentPackRequest  true  "Release"
// @Success      201   {object}  PlatformContentPackResponse
// @Failure      400   {object}  apierror.Error  "invalid url, fetch failed or CONTENT_DIGEST_MISMATCH"
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      422   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /admin/content-packs/import [post]
func (h *PlatformContentPackHandler) Import(w http.ResponseWriter, r *http.Request) {
	var req ImportPlatformContentPackRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	p, err := h.service.Import(r.Context(), contentpackapp.PlatformInput{
		Name: req.Name, Version: req.Version, Kind: req.Kind, AcknowledgeSecrets: req.AcknowledgeSecrets,
	}, req.URL, req.Digest)
	if err != nil {
		h.packs.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusCreated, toPlatformContentPackResponse(p))
}

// Revoke handles POST /api/v1/admin/content-packs/{id}/revoke
// @Summary      Revoke platform content pack
// @Description  Every channel naming the pack moves to the newest older active pack of its name (removed when there is none). Super admin.
// @Tags         Content Packs
// @Accept       json
// @Produce      json
// @Param        id    path      string                    true  "Platform content pack ID"
// @Param        body  body      RevokeContentPackRequest  true  "Reason"
// @Success      200   {object}  RevokePlatformContentPackResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /admin/content-packs/{id}/revoke [post]
func (h *PlatformContentPackHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	var req RevokeContentPackRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	p, cs, err := h.service.Revoke(r.Context(), chi.URLParam(r, "id"), req.Reason)
	if err != nil {
		h.packs.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, RevokePlatformContentPackResponse{Pack: toPlatformContentPackResponse(p), Channels: toContentChannels(cs)})
}

// SetChannel handles PUT /api/v1/admin/content-packs/channels/{channel}
// @Summary      Point a content channel at a pack
// @Description  Sets channel (stable or canary) of the pack's name to the pack, which must be active. Super admin.
// @Tags         Content Packs
// @Accept       json
// @Produce      json
// @Param        channel  path      string                    true  "Channel"  Enums(stable,canary)
// @Param        body     body      SetContentChannelRequest  true  "Pack"
// @Success      200      {object}  ContentChannelResponse
// @Failure      400      {object}  apierror.Error
// @Failure      401      {object}  apierror.Error
// @Failure      403      {object}  apierror.Error
// @Failure      404      {object}  apierror.Error
// @Failure      409      {object}  apierror.Error  "the pack is revoked"
// @Security     BearerAuth
// @Router       /admin/content-packs/channels/{channel} [put]
func (h *PlatformContentPackHandler) SetChannel(w http.ResponseWriter, r *http.Request) {
	var req SetContentChannelRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	c, err := h.service.MoveChannel(r.Context(), req.PackID, contentpack.Channel(chi.URLParam(r, "channel")))
	if err != nil {
		h.packs.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toContentChannels([]contentpack.ChannelPointer{*c})[0])
}

// Download handles GET /api/v1/admin/content-packs/{id}/download
// @Summary      Download platform content pack archive
// @Description  The canonical tar, checked against the pack digest (Digest header).
// @Tags         Content Packs
// @Produce      application/x-tar
// @Param        id   path  string  true  "Platform content pack ID"
// @Success      200  {file}  file
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /admin/content-packs/{id}/download [get]
func (h *PlatformContentPackHandler) Download(w http.ResponseWriter, r *http.Request) {
	p, data, err := h.service.Archive(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		h.packs.handleError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.tar"`, p.Name, p.Version))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Digest", p.Digest)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
