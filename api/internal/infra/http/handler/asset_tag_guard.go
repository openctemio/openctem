package handler

import (
	"context"
	"net/http"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/taggov"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TagGovernor answers the governing tags of a tenant (*taggov.Governor).
type TagGovernor interface {
	For(ctx context.Context, tenantID shared.ID) (taggov.Set, error)
}

// SetTagGovernor wires the guard for tags that rules read. Without it asset
// writes are limited by assets:write only (tests and stub builds).
func (h *AssetHandler) SetTagGovernor(g TagGovernor) { h.tagGovernor = g }

// SetTagGovernor wires the same guard for CSV imports.
func (h *AssetImportHandler) SetTagGovernor(g TagGovernor) { h.tagGovernor = g }

// tagRefusal says why a tag change is refused.
type tagRefusal struct {
	status  int
	message string
	changes []taggov.Change
}

// checkTagChange decides whether the caller may change the tags of an
// object from current to next. A tag that a team access rule, scan approval
// rule, scan window or assignment rule reads needs the permission that edits
// that kind of rule, not only assets:write: otherwise anyone who can edit an
// asset could remove a tag to leave an approval, or add one to pull an
// asset into a team's scope. It fails closed when the rules cannot be read.
func checkTagChange(ctx context.Context, g TagGovernor, tenantID string, current, next []string) ([]taggov.Change, *tagRefusal) {
	if g == nil {
		return nil, nil
	}
	added, removed := taggov.Diff(current, next)
	if len(added)+len(removed) == 0 {
		return nil, nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, &tagRefusal{status: http.StatusBadRequest, message: "Invalid tenant"}
	}
	set, err := g.For(ctx, tid)
	if err != nil {
		return nil, &tagRefusal{status: http.StatusServiceUnavailable, message: "Tag rules cannot be checked right now; try again"}
	}
	changes := set.Changes(added, removed)
	if len(changes) == 0 {
		return nil, nil
	}
	// An API key or an MCP token acts for its user without being the user's own
	// session: it never sets a tag that rules read, whatever its grants say.
	if middleware.IsDelegatedCredential(ctx) {
		return changes, &tagRefusal{
			status:  http.StatusForbidden,
			message: "Tags that rules read can only be changed in a signed-in session by a person with the permission to change that rule",
			changes: changes,
		}
	}
	if taggov.Allowed(changes, func(p string) bool { return middleware.HasPermission(ctx, p) }, middleware.IsAdmin(ctx)) {
		return changes, nil
	}
	// The message does not name the rule that reads the tag: a person who can
	// only edit assets learns nothing about the organization's rules.
	return changes, &tagRefusal{
		status:  http.StatusForbidden,
		message: "Changing tags that rules read needs the permission to change that rule, not only to edit assets",
		changes: changes,
	}
}

// refuseTagChange writes the refusal and records the attempt.
func (h *AssetHandler) refuseTagChange(w http.ResponseWriter, r *http.Request, assetID, assetName string, ref *tagRefusal) {
	if ref.status == http.StatusForbidden && h.auditService != nil {
		ev := auditapp.NewDeniedEvent(auditdom.ActionAssetGovernedTagsChanged, auditdom.ResourceTypeAsset, assetID, "governing tag change without the rule's permission").
			WithMetadata("tags", governedNames(ref.changes))
		if assetName != "" {
			ev = ev.WithResourceName(assetName)
		}
		auditapp.RecordOrWarn(r.Context(), h.logger, h.auditService, h.buildAuditContext(r), ev)
	}
	switch ref.status {
	case http.StatusForbidden:
		apierror.Forbidden(ref.message).WriteJSON(w)
	case http.StatusServiceUnavailable:
		apierror.ServiceUnavailable(ref.message).WriteJSON(w)
	default:
		apierror.BadRequest(ref.message).WriteJSON(w)
	}
}

// auditGovernedTags records an allowed change of governing tags.
func (h *AssetHandler) auditGovernedTags(r *http.Request, assetID, assetName string, changes []taggov.Change) {
	if len(changes) == 0 {
		return
	}
	h.auditAsset(r, auditdom.ActionAssetGovernedTagsChanged, assetID, assetName, "Tags read by rules changed",
		map[string]any{"tags": governedNames(changes)})
}

func governedNames(changes []taggov.Change) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		kinds := make([]string, 0, len(c.Reqs))
		for _, r := range c.Reqs {
			kinds = append(kinds, r.Rule)
		}
		out = append(out, c.Tag+" ("+strings.Join(kinds, ", ")+")")
	}
	return out
}
