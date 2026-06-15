package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app/scim"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// SCIM schema URNs (RFC 7643/7644).
const (
	scimUserSchema    = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimListSchema    = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema   = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatchOpSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimContentType   = "application/scim+json"
)

// SCIMHandler implements the /scim/v2 User provisioning endpoints. The tenant is
// resolved by middleware.SCIMAuth (from the bearer token), never the body.
type SCIMHandler struct {
	provisioning *scim.ProvisioningService
	logger       *logger.Logger
}

// NewSCIMHandler creates the handler.
func NewSCIMHandler(provisioning *scim.ProvisioningService, log *logger.Logger) *SCIMHandler {
	return &SCIMHandler{provisioning: provisioning, logger: log.With("handler", "scim")}
}

// --- wire types ---

type scimName struct {
	Formatted string `json:"formatted,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}

type scimUserResource struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName,omitempty"`
	Name        *scimName   `json:"name,omitempty"`
	Emails      []scimEmail `json:"emails,omitempty"`
	Active      bool        `json:"active"`
	Meta        scimMeta    `json:"meta"`
}

type scimListResponse struct {
	Schemas      []string           `json:"schemas"`
	TotalResults int                `json:"totalResults"`
	StartIndex   int                `json:"startIndex"`
	ItemsPerPage int                `json:"itemsPerPage"`
	Resources    []scimUserResource `json:"Resources"`
}

type scimErrorBody struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

type scimUserRequest struct {
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName"`
	Name        *scimName   `json:"name"`
	Emails      []scimEmail `json:"emails"`
	Active      *bool       `json:"active"`
	ExternalID  string      `json:"externalId"`
}

type scimPatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

type scimPatchRequest struct {
	Schemas    []string      `json:"schemas"`
	Operations []scimPatchOp `json:"Operations"`
}

// --- helpers ---

func (h *SCIMHandler) tenant(r *http.Request) (shared.ID, bool) {
	return middleware.SCIMTenantID(r.Context())
}

func writeSCIM(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func (h *SCIMHandler) scimError(w http.ResponseWriter, status int, scimType, detail string) {
	writeSCIM(w, status, scimErrorBody{
		Schemas:  []string{scimErrorSchema},
		Status:   strconv.Itoa(status),
		ScimType: scimType,
		Detail:   detail,
	})
}

func toResource(u scim.ScimUser) scimUserResource {
	res := scimUserResource{
		Schemas:     []string{scimUserSchema},
		ID:          u.ID,
		UserName:    u.UserName,
		DisplayName: u.DisplayName,
		Active:      u.Active,
		Meta: scimMeta{
			ResourceType: "User",
			Location:     "/scim/v2/Users/" + u.ID,
		},
	}
	if u.DisplayName != "" {
		res.Name = &scimName{Formatted: u.DisplayName}
	}
	if u.Email != "" {
		res.Emails = []scimEmail{{Value: u.Email, Primary: true}}
	}
	if !u.CreatedAt.IsZero() {
		res.Meta.Created = u.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !u.UpdatedAt.IsZero() {
		res.Meta.LastModified = u.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return res
}

// emailFrom picks the primary email, else the first, else userName.
func emailFrom(req scimUserRequest) string {
	for _, e := range req.Emails {
		if e.Primary && e.Value != "" {
			return e.Value
		}
	}
	if len(req.Emails) > 0 {
		return req.Emails[0].Value
	}
	return req.UserName
}

func displayNameFrom(req scimUserRequest) string {
	if req.DisplayName != "" {
		return req.DisplayName
	}
	if req.Name != nil {
		return req.Name.Formatted
	}
	return ""
}

// --- handlers ---

// CreateUser handles POST /scim/v2/Users.
func (h *SCIMHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(r)
	if !ok {
		h.scimError(w, http.StatusUnauthorized, "", "no tenant context")
		return
	}
	var req scimUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.scimError(w, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
		return
	}
	email := emailFrom(req)
	if strings.TrimSpace(email) == "" {
		h.scimError(w, http.StatusBadRequest, "invalidValue", "userName or emails is required")
		return
	}
	active := true
	if req.Active != nil {
		active = *req.Active
	}

	res, created, err := h.provisioning.CreateOrActivate(r.Context(), tenantID, scim.ProvisionInput{
		UserName:    req.UserName,
		DisplayName: displayNameFrom(req),
		Email:       email,
		Active:      active,
	})
	if err != nil {
		h.writeProvisionError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeSCIM(w, status, toResource(res))
}

// GetUser handles GET /scim/v2/Users/{id}.
func (h *SCIMHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(r)
	if !ok {
		h.scimError(w, http.StatusUnauthorized, "", "no tenant context")
		return
	}
	userID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		h.scimError(w, http.StatusBadRequest, "invalidValue", "invalid user id")
		return
	}
	res, err := h.provisioning.Get(r.Context(), tenantID, userID)
	if err != nil {
		h.writeProvisionError(w, err)
		return
	}
	writeSCIM(w, http.StatusOK, toResource(res))
}

// ListUsers handles GET /scim/v2/Users (with optional filter + pagination).
func (h *SCIMHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(r)
	if !ok {
		h.scimError(w, http.StatusUnauthorized, "", "no tenant context")
		return
	}
	filterEmail, perr := parseUserNameFilter(r.URL.Query().Get("filter"))
	if perr != nil {
		h.scimError(w, http.StatusBadRequest, "invalidFilter", perr.Error())
		return
	}
	startIndex := atoiDefault(r.URL.Query().Get("startIndex"), 1)
	count := atoiDefault(r.URL.Query().Get("count"), 100)

	users, total, err := h.provisioning.List(r.Context(), tenantID, filterEmail, startIndex, count)
	if err != nil {
		h.logger.Error("scim list users failed", "error", err)
		h.scimError(w, http.StatusInternalServerError, "", "failed to list users")
		return
	}
	resources := make([]scimUserResource, 0, len(users))
	for _, u := range users {
		resources = append(resources, toResource(u))
	}
	writeSCIM(w, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListSchema},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

// ReplaceUser handles PUT /scim/v2/Users/{id} (active toggle).
func (h *SCIMHandler) ReplaceUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(r)
	if !ok {
		h.scimError(w, http.StatusUnauthorized, "", "no tenant context")
		return
	}
	userID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		h.scimError(w, http.StatusBadRequest, "invalidValue", "invalid user id")
		return
	}
	var req scimUserRequest
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		h.scimError(w, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
		return
	}
	active := true
	if req.Active != nil {
		active = *req.Active
	}
	res, err := h.provisioning.SetActive(r.Context(), tenantID, userID, active)
	if err != nil {
		h.writeProvisionError(w, err)
		return
	}
	writeSCIM(w, http.StatusOK, toResource(res))
}

// PatchUser handles PATCH /scim/v2/Users/{id} (RFC-7644 PatchOp; supports the
// active replace that IdPs use for deactivation/reactivation).
func (h *SCIMHandler) PatchUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(r)
	if !ok {
		h.scimError(w, http.StatusUnauthorized, "", "no tenant context")
		return
	}
	userID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		h.scimError(w, http.StatusBadRequest, "invalidValue", "invalid user id")
		return
	}
	var req scimPatchRequest
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		h.scimError(w, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
		return
	}
	active, found := activeFromPatch(req.Operations)
	if !found {
		h.scimError(w, http.StatusBadRequest, "invalidPath", "only 'active' replace is supported")
		return
	}
	res, err := h.provisioning.SetActive(r.Context(), tenantID, userID, active)
	if err != nil {
		h.writeProvisionError(w, err)
		return
	}
	writeSCIM(w, http.StatusOK, toResource(res))
}

// DeleteUser handles DELETE /scim/v2/Users/{id} (deprovision → deactivate).
func (h *SCIMHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(r)
	if !ok {
		h.scimError(w, http.StatusUnauthorized, "", "no tenant context")
		return
	}
	userID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		h.scimError(w, http.StatusBadRequest, "invalidValue", "invalid user id")
		return
	}
	if _, err := h.provisioning.SetActive(r.Context(), tenantID, userID, false); err != nil {
		h.writeProvisionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SCIMHandler) writeProvisionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		h.scimError(w, http.StatusNotFound, "", "user not found")
	case errors.Is(err, shared.ErrValidation):
		h.scimError(w, http.StatusBadRequest, "invalidValue", "invalid request")
	default:
		h.logger.Error("scim provisioning failed", "error", err)
		h.scimError(w, http.StatusInternalServerError, "", "provisioning failed")
	}
}

// --- discovery ---

// ServiceProviderConfig handles GET /scim/v2/ServiceProviderConfig.
func (h *SCIMHandler) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":                 map[string]any{"supported": true},
		"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]any{"supported": true, "maxResults": 200},
		"changePassword":        map[string]any{"supported": false},
		"sort":                  map[string]any{"supported": false},
		"etag":                  map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "OAuth Bearer Token", "description": "Per-tenant SCIM bearer token"}},
	})
}

// ResourceTypes handles GET /scim/v2/ResourceTypes.
func (h *SCIMHandler) ResourceTypes(w http.ResponseWriter, r *http.Request) {
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": 1,
		"Resources": []map[string]any{{
			"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":       "User",
			"name":     "User",
			"endpoint": "/Users",
			"schema":   scimUserSchema,
		}},
	})
}

// Schemas handles GET /scim/v2/Schemas.
func (h *SCIMHandler) Schemas(w http.ResponseWriter, r *http.Request) {
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": 1,
		"Resources": []map[string]any{{
			"id":         scimUserSchema,
			"name":       "User",
			"attributes": []map[string]any{{"name": "userName", "type": "string", "required": true}, {"name": "active", "type": "boolean", "required": false}},
		}},
	})
}

// --- parsing helpers ---

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// parseUserNameFilter parses a SCIM `userName eq "value"` filter. Empty filter →
// no filter. Unsupported filters return an error.
func parseUserNameFilter(filter string) (string, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return "", nil
	}
	lower := strings.ToLower(filter)
	if !strings.HasPrefix(lower, "username eq ") {
		return "", errors.New("only 'userName eq \"...\"' filtering is supported")
	}
	rest := strings.TrimSpace(filter[len("userName eq "):])
	rest = strings.Trim(rest, `"`)
	if rest == "" {
		return "", errors.New("empty filter value")
	}
	return rest, nil
}

// activeFromPatch extracts the desired active state from PatchOps. Supports both
// `{op:replace,path:active,value:false}` and `{op:replace,value:{active:false}}`.
func activeFromPatch(ops []scimPatchOp) (bool, bool) {
	for _, op := range ops {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		path := strings.ToLower(strings.TrimSpace(op.Path))
		if path == "active" {
			var b bool
			if err := json.Unmarshal(op.Value, &b); err == nil {
				return b, true
			}
		}
		if path == "" {
			var obj struct {
				Active *bool `json:"active"`
			}
			if err := json.Unmarshal(op.Value, &obj); err == nil && obj.Active != nil {
				return *obj.Active, true
			}
		}
	}
	return false, false
}
