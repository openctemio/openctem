package scan

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ListScansBySpec lists the tenant's scans selected by a decoded filter (the
// list query contract: GET /scans and POST /scans/search). The tenant
// predicate is the first condition; archived scans and, unless includeAdHoc
// or origin=system, quick scans that were never saved are always left out
// (scan.WithListVisibility). Scans are tenant configuration: like the list
// before it, this applies no data scope.
func (s *Service) ListScansBySpec(ctx context.Context, tenantID string, spec *filterspec.Spec, includeAdHoc bool) (pagination.Result[*scan.Scan], error) {
	var empty pagination.Result[*scan.Scan]
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return empty, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	reader, ok := s.scanRepo.(scan.WhereReader)
	if !ok {
		return empty, errors.New("scan repository does not read by filter")
	}
	actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tid})
	if err != nil {
		return empty, err
	}
	w, err := filterspec.Compile(scan.WithListVisibility(spec, includeAdHoc), scan.ListFields, actor)
	if err != nil {
		return empty, err
	}
	return reader.ListWhere(ctx, w, pagination.New(spec.Page, spec.PerPage))
}
