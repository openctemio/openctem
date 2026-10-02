package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app/scim"
	"github.com/openctemio/api/pkg/domain/scimgroup"
	"github.com/openctemio/api/pkg/domain/shared"
)

const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"

// SetGroupService wires the SCIM Group service (Phase 9c). Kept as a setter so
// the SCIM handler stays constructable without groups.
func (h *SCIMHandler) SetGroupService(g *scim.GroupService) { h.groups = g }

// --- wire types ---

type scimGroupMemberRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

type scimGroupResource struct {
	Schemas     []string             `json:"schemas"`
	ID          string               `json:"id"`
	DisplayName string               `json:"displayName"`
	Members     []scimGroupMemberRef `json:"members"`
	Meta        scimMeta             `json:"meta"`
}

type scimGroupRequest struct {
	DisplayName string               `json:"displayName"`
	ExternalID  string               `json:"externalId"`
	Members     []scimGroupMemberRef `json:"members"`
}

func groupToResource(g *scimgroup.ScimGroup) scimGroupResource {
	members := make([]scimGroupMemberRef, 0, len(g.Members()))
	for _, uid := range g.Members() {
		members = append(members, scimGroupMemberRef{Value: uid.String(), Type: "User"})
	}
	return scimGroupResource{
		Schemas:     []string{scimGroupSchema},
		ID:          g.ID().String(),
		DisplayName: g.DisplayName(),
		Members:     members,
		Meta:        scimMeta{ResourceType: "Group", Location: "/scim/v2/Groups/" + g.ID().String()},
	}
}

// parseMemberIDs converts member refs to validated user IDs, skipping blanks.
func parseMemberIDs(refs []scimGroupMemberRef) ([]shared.ID, error) {
	out := make([]shared.ID, 0, len(refs))
	for _, m := range refs {
		if strings.TrimSpace(m.Value) == "" {
			continue
		}
		id, err := shared.IDFromString(m.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// CreateGroup handles POST /scim/v2/Groups.
func (h *SCIMHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(r)
	if !ok || h.groups == nil {
		h.scimError(w, http.StatusUnauthorized, "", "no tenant context")
		return
	}
	var req scimGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.scimError(w, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.DisplayName) == "" {
		h.scimError(w, http.StatusBadRequest, "invalidValue", "displayName is required")
		return
	}
	memberIDs, err := parseMemberIDs(req.Members)
	if err != nil {
		h.scimError(w, http.StatusBadRequest, "invalidValue", "member value must be a valid id")
		return
	}
	g, err := h.groups.Create(r.Context(), tenantID, scim.GroupInput{
		DisplayName: req.DisplayName, ExternalID: req.ExternalID, MemberIDs: memberIDs,
	})
	if err != nil {
		h.writeGroupError(w, err)
		return
	}
	writeSCIM(w, http.StatusCreated, groupToResource(g))
}

// GetGroup handles GET /scim/v2/Groups/{id}.
func (h *SCIMHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(r)
	if !ok || h.groups == nil {
		h.scimError(w, http.StatusUnauthorized, "", "no tenant context")
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		h.scimError(w, http.StatusBadRequest, "invalidValue", "invalid group id")
		return
	}
	g, err := h.groups.Get(r.Context(), tenantID, id)
	if err != nil {
		h.writeGroupError(w, err)
		return
	}
	writeSCIM(w, http.StatusOK, groupToResource(g))
}

// ListGroups handles GET /scim/v2/Groups.
func (h *SCIMHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(r)
	if !ok || h.groups == nil {
		h.scimError(w, http.StatusUnauthorized, "", "no tenant context")
		return
	}
	groups, err := h.groups.List(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("scim list groups failed", "error", err)
		h.scimError(w, http.StatusInternalServerError, "", "failed to list groups")
		return
	}
	resources := make([]scimGroupResource, 0, len(groups))
	for _, g := range groups {
		resources = append(resources, groupToResource(g))
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": len(resources),
		"startIndex":   1,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	})
}

// ReplaceGroup handles PUT /scim/v2/Groups/{id}.
func (h *SCIMHandler) ReplaceGroup(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(r)
	if !ok || h.groups == nil {
		h.scimError(w, http.StatusUnauthorized, "", "no tenant context")
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		h.scimError(w, http.StatusBadRequest, "invalidValue", "invalid group id")
		return
	}
	var req scimGroupRequest
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		h.scimError(w, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
		return
	}
	memberIDs, perr := parseMemberIDs(req.Members)
	if perr != nil {
		h.scimError(w, http.StatusBadRequest, "invalidValue", "member value must be a valid id")
		return
	}
	g, err := h.groups.Replace(r.Context(), tenantID, id, scim.GroupInput{
		DisplayName: req.DisplayName, ExternalID: req.ExternalID, MemberIDs: memberIDs,
	})
	if err != nil {
		h.writeGroupError(w, err)
		return
	}
	writeSCIM(w, http.StatusOK, groupToResource(g))
}

// DeleteGroup handles DELETE /scim/v2/Groups/{id}.
func (h *SCIMHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(r)
	if !ok || h.groups == nil {
		h.scimError(w, http.StatusUnauthorized, "", "no tenant context")
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		h.scimError(w, http.StatusBadRequest, "invalidValue", "invalid group id")
		return
	}
	if err := h.groups.Delete(r.Context(), tenantID, id); err != nil {
		h.writeGroupError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// memberRemovePathRe matches Azure-style `members[value eq "<id>"]` remove paths.
var memberRemovePathRe = regexp.MustCompile(`(?i)members\[value eq "([^"]+)"\]`)

// PatchGroup handles PATCH /scim/v2/Groups/{id} — add/remove/replace members,
// covering both Okta (value arrays) and Azure (path filter) styles.
func (h *SCIMHandler) PatchGroup(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(r)
	if !ok || h.groups == nil {
		h.scimError(w, http.StatusUnauthorized, "", "no tenant context")
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		h.scimError(w, http.StatusBadRequest, "invalidValue", "invalid group id")
		return
	}
	var req scimPatchRequest
	if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
		h.scimError(w, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
		return
	}

	var adds, removes []shared.ID
	var replaceSet []shared.ID
	hasReplace := false
	for _, op := range req.Operations {
		path := strings.ToLower(strings.TrimSpace(op.Path))
		switch {
		case strings.EqualFold(op.Op, "add") && strings.HasPrefix(path, "members"):
			adds = append(adds, h.memberValues(op.Value)...)
		case strings.EqualFold(op.Op, "remove"):
			if m := memberRemovePathRe.FindStringSubmatch(op.Path); m != nil {
				if uid, perr := shared.IDFromString(m[1]); perr == nil {
					removes = append(removes, uid)
				}
				continue
			}
			if strings.HasPrefix(path, "members") {
				removes = append(removes, h.memberValues(op.Value)...)
			}
		case strings.EqualFold(op.Op, "replace") && (path == "members" || path == ""):
			replaceSet = h.memberValues(op.Value)
			hasReplace = true
		default:
			h.scimError(w, http.StatusBadRequest, "invalidPath", "only member add/remove/replace is supported")
			return
		}
	}

	if hasReplace {
		if _, err := h.groups.ReplaceMembers(r.Context(), tenantID, id, replaceSet); err != nil {
			h.writeGroupError(w, err)
			return
		}
	}
	g, err := h.groups.PatchMembers(r.Context(), tenantID, id, adds, removes)
	if err != nil {
		h.writeGroupError(w, err)
		return
	}
	writeSCIM(w, http.StatusOK, groupToResource(g))
}

// memberValues extracts user IDs from a PatchOp value, which may be an array of
// member refs ([{value}]) or a single object containing a members array.
func (h *SCIMHandler) memberValues(raw json.RawMessage) []shared.ID {
	if len(raw) == 0 {
		return nil
	}
	var arr []scimGroupMemberRef
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		ids, _ := parseMemberIDs(arr)
		return ids
	}
	var obj struct {
		Members []scimGroupMemberRef `json:"members"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && len(obj.Members) > 0 {
		ids, _ := parseMemberIDs(obj.Members)
		return ids
	}
	return nil
}

func (h *SCIMHandler) writeGroupError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scimgroup.ErrNotFound), errors.Is(err, shared.ErrNotFound):
		h.scimError(w, http.StatusNotFound, "", "group not found")
	case errors.Is(err, shared.ErrValidation):
		h.scimError(w, http.StatusBadRequest, "invalidValue", "invalid request")
	default:
		h.logger.Error("scim group operation failed", "error", err)
		h.scimError(w, http.StatusInternalServerError, "", "group operation failed")
	}
}
