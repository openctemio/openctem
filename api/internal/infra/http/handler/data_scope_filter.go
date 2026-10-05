package handler

import (
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// filterLinksInScope keeps the rows whose asset the request's caller may see,
// for handlers that read asset-keyed rows with their own SQL (business-service
// links, a CTEM cycle's scope snapshot). It resolves the caller through the
// one data-scope enforcer, with one query for all rows. A nil enforcer keeps
// every row; a row whose asset id does not parse is dropped (fail closed).
func filterLinksInScope[T any](r *http.Request, e *datascope.Enforcer, tenantID string, rows []T, assetOf func(T) string) ([]T, error) {
	if e == nil || len(rows) == 0 {
		return rows, nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, err
	}
	ids := make([]shared.ID, 0, len(rows))
	for _, row := range rows {
		if id, perr := shared.IDFromString(assetOf(row)); perr == nil {
			ids = append(ids, id)
		}
	}
	admit, err := e.FilterForCaller(r.Context(), tid, ids)
	if err != nil {
		return nil, err
	}
	out := make([]T, 0, len(rows))
	for _, row := range rows {
		if id, perr := shared.IDFromString(assetOf(row)); perr == nil && admit(id) {
			out = append(out, row)
		}
	}
	return out, nil
}
