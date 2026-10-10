package handler

// Asset change timeline (RFC-069 §11): one asset's changes and the
// organization's recent asset changes, newest first, keyset-paged.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// AssetTimelineSourceResponse is the source that decided a change.
type AssetTimelineSourceResponse struct {
	// Kind: manual, integration, import or scan.
	Kind string `json:"kind" example:"scan"`
	// Name is the tool, importer, integration or person.
	Name string `json:"name" example:"nmap"`
	// Run is the scan task, CI run, import or feed sequence ("" when unknown).
	Run string `json:"run" example:""`
}

// AssetTimelineEventResponse is one timeline event.
type AssetTimelineEventResponse struct {
	ID        string    `json:"id"`
	AssetID   string    `json:"asset_id"`
	AssetName string    `json:"asset_name,omitempty"`
	AssetType string    `json:"asset_type,omitempty"`
	At        time.Time `json:"at"`
	Attribute string    `json:"attribute" example:"exposure"`
	OldValue  string    `json:"old_value" example:"private"`
	NewValue  string    `json:"new_value" example:"public"`
	// Added and Removed are the elements a set attribute gained and lost.
	Added   []string                    `json:"added,omitempty"`
	Removed []string                    `json:"removed,omitempty"`
	Source  AssetTimelineSourceResponse `json:"source"`
	// ActorID is the person behind a manual change.
	ActorID *string `json:"actor_id,omitempty"`
	// Reason: newer_observation, manual_lock, lock_released, ttl_expiry,
	// policy_change or source_removed.
	Reason string `json:"reason" example:"newer_observation"`
	// FlapCount > 1: the value flipped back and forth this many times within
	// an hour; old_value is where it started, new_value where it ended.
	FlapCount int `json:"flap_count" example:"1"`
}

// AssetTimelineResponse is one page of a timeline.
type AssetTimelineResponse struct {
	Items []AssetTimelineEventResponse `json:"items"`
	// NextCursor fetches the next (older) page; empty on the last page.
	NextCursor string `json:"next_cursor"`
}

// maxChangeTagLength bounds the tag filter.
const maxChangeTagLength = 100

// parseChangeQuery reads the timeline filters and cursor.
func parseChangeQuery(r *http.Request) (assetdom.ChangeQuery, error) {
	v := r.URL.Query()
	q := assetdom.ChangeQuery{}
	n, err := pagination.LimitFromRequest(v, 50, assetdom.MaxChangePageSize)
	if err != nil {
		return q, apierror.BadRequest(err.Error())
	}
	q.Limit = n
	for _, a := range splitList(v.Get("attribute")) {
		if !assetdom.TrackedAttribute(a).IsValid() {
			return q, apierror.BadRequest("unknown attribute")
		}
		q.Attributes = append(q.Attributes, a)
	}
	for _, k := range splitList(v.Get("source_kind")) {
		kind := assetdom.SourceKind(k)
		if !kind.IsValid() {
			return q, apierror.BadRequest("unknown source_kind")
		}
		q.SourceKinds = append(q.SourceKinds, kind)
	}
	q.SourceName = strings.TrimSpace(v.Get("source_name"))
	if len(q.SourceName) > assetdom.MaxSourceNameLength {
		return q, apierror.BadRequest("source_name too long")
	}
	q.Tag = strings.TrimSpace(v.Get("tag"))
	if len(q.Tag) > maxChangeTagLength {
		return q, apierror.BadRequest("tag too long")
	}
	if c := v.Get("cursor"); c != "" {
		at, id, ok := decodeChangeCursor(c)
		if !ok {
			return q, apierror.BadRequest("invalid cursor")
		}
		q.BeforeAt, q.BeforeID = &at, &id
	}
	return q, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func encodeChangeCursor(e assetdom.ChangeEvent) string {
	return base64.RawURLEncoding.EncodeToString([]byte(e.At.UTC().Format(time.RFC3339Nano) + "|" + e.ID.String()))
}

func decodeChangeCursor(c string) (time.Time, shared.ID, bool) {
	if len(c) > 200 {
		return time.Time{}, shared.ID{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, shared.ID{}, false
	}
	at, id, found := strings.Cut(string(raw), "|")
	if !found {
		return time.Time{}, shared.ID{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return time.Time{}, shared.ID{}, false
	}
	pid, err := shared.IDFromString(id)
	if err != nil {
		return time.Time{}, shared.ID{}, false
	}
	return t, pid, true
}

func writeChangePage(w http.ResponseWriter, events []assetdom.ChangeEvent, more bool) {
	out := AssetTimelineResponse{Items: make([]AssetTimelineEventResponse, 0, len(events))}
	for _, e := range events {
		item := AssetTimelineEventResponse{
			ID: e.ID.String(), AssetID: e.AssetID.String(), AssetName: e.AssetName, AssetType: e.AssetType,
			At: e.At, Attribute: e.Attribute, OldValue: e.Old, NewValue: e.New, Added: e.Added, Removed: e.Removed,
			Source: AssetTimelineSourceResponse{Kind: string(e.SourceKind), Name: e.SourceName, Run: e.SourceRun},
			Reason: string(e.Reason), FlapCount: e.FlapCount,
		}
		if e.ActorID != nil {
			s := e.ActorID.String()
			item.ActorID = &s
		}
		out.Items = append(out.Items, item)
	}
	if more && len(events) > 0 {
		out.NextCursor = encodeChangeCursor(events[len(events)-1])
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func writeChangeQueryError(w http.ResponseWriter, err error) {
	var e *apierror.Error
	if errors.As(err, &e) {
		e.WriteJSON(w)
		return
	}
	apierror.BadRequest("Invalid query").WriteJSON(w)
}

// ListAssetChanges handles GET /api/v1/assets/{id}/changes
// @Summary      Asset change timeline
// @Description  What changed on the asset, newest first: each change of a reconciled attribute's value or of the source that decides it, with the source, its run, the person for a manual change and the reason. Re-sightings of the same value are not listed; a value flipping back and forth within an hour is one entry with a count.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id           path   string  true   "Asset ID"
// @Param        attribute    query  string  false  "Comma-separated attributes"
// @Param        source_kind  query  string  false  "Comma-separated source kinds (manual, integration, import, scan)"
// @Param        source_name  query  string  false  "Source name"
// @Param        cursor       query  string  false  "next_cursor of the previous page"
// @Param        limit        query  int     false  "Page size (default 50, at most 200)"
// @Success      200  {object}  AssetTimelineResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/changes [get]
func (h *AssetHandler) ListAssetChanges(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	q, err := parseChangeQuery(r)
	if err != nil {
		writeChangeQueryError(w, err)
		return
	}
	events, more, err := h.service.ListAssetChanges(r.Context(), tenantID, r.PathValue("id"), q)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeChangePage(w, events, more)
}

// ListTenantChanges handles GET /api/v1/assets/changes
// @Summary      Recent asset changes
// @Description  The organization's recent asset changes, newest first, limited to the assets the caller may see. Filters: attribute, source kind, source name and asset tag (for example bug-bounty).
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        attribute    query  string  false  "Comma-separated attributes"
// @Param        source_kind  query  string  false  "Comma-separated source kinds (manual, integration, import, scan)"
// @Param        source_name  query  string  false  "Source name"
// @Param        tag          query  string  false  "Asset tag"
// @Param        cursor       query  string  false  "next_cursor of the previous page"
// @Param        limit        query  int     false  "Page size (default 50, at most 200)"
// @Success      200  {object}  AssetTimelineResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /assets/changes [get]
func (h *AssetHandler) ListTenantChanges(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	q, err := parseChangeQuery(r)
	if err != nil {
		writeChangeQueryError(w, err)
		return
	}
	events, more, err := h.service.ListTenantChanges(r.Context(), tenantID, q)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeChangePage(w, events, more)
}
