package scanrun

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ListRunsBySpec lists the tenant's runs selected by a decoded filter (the
// list query contract: GET /scan-runs). The tenant predicate is the first
// condition; scanrun.RunListRules adds the housekeeping and finding-run
// exclusions. Runs are the history of tenant scans: like the list before it,
// this applies no data scope.
func (s *Service) ListRunsBySpec(ctx context.Context, tenantID string, spec *filterspec.Spec, includeSystem, hideFindingRuns bool) (pagination.Result[*scanrun.Run], error) {
	var empty pagination.Result[*scanrun.Run]
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return empty, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	reader, ok := s.runRepo.(scanrun.RunWhereReader)
	if !ok {
		return empty, errors.New("run repository does not read by filter")
	}
	actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tid})
	if err != nil {
		return empty, err
	}
	w, err := filterspec.Compile(scanrun.RunListRules(spec, includeSystem, hideFindingRuns), scanrun.RunFields, actor)
	if err != nil {
		return empty, err
	}
	return reader.ListWhere(ctx, w, pagination.New(spec.Page, spec.PerPage))
}
