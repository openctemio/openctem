package handler

import (
	"errors"
	"net/http"

	savedviewapp "github.com/openctemio/openctem/api/internal/app/savedview"
	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/savedview"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// applySavedView handles ?view=<id> on a list request (RFC-048 §3.8): the
// view's stored filter, re-validated now, is the base, and the request's own
// params override it field by field. The view must be one the caller may
// see; it runs as the caller (decision A5), so its query, not its owner's
// rows, is what is shared. Writes the error and returns false on failure.
func applySavedView(svc *savedviewapp.Service, page string, w http.ResponseWriter, r *http.Request, spec *filterspec.Spec) (*filterspec.Spec, bool) {
	raw := r.URL.Query().Get("view")
	if raw == "" {
		return spec, true
	}
	if svc == nil {
		apierror.NotFound("Saved view").WriteJSON(w)
		return nil, false
	}
	id, err := shared.IDFromString(raw)
	if err != nil {
		apierror.NotFound("Saved view").WriteJSON(w)
		return nil, false
	}
	stored, _, err := svc.Spec(r.Context(), savedViewCaller(r), id, page)
	if err != nil {
		if _, isFilter := filterspec.AsError(err); isFilter {
			filterquery.WriteError(w, err)
			return nil, false
		}
		if errors.Is(err, savedview.ErrNotFound) || errors.Is(err, savedview.ErrUnknownPage) {
			apierror.NotFound("Saved view").WriteJSON(w)
			return nil, false
		}
		apierror.InternalError(err).WriteJSON(w)
		return nil, false
	}
	merged, err := filterspec.Overlay(stored, spec)
	if err != nil {
		filterquery.WriteError(w, err)
		return nil, false
	}
	return merged, true
}
