package module

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// maxSkipRounds bounds how many times a background sweep refetches after a
// whole batch belonged to tenants with the module off.
const maxSkipRounds = 8

// CollectEnabled returns the next batch of work rows of tenants that have the
// module on. A sweep that reads "the oldest N rows across all tenants" and
// skips the rows of a tenant with the module off would see the same N rows
// again on every pass (they stay the oldest) and starve every other tenant.
// So each tenant found off is added to the skip list handed to fetch, which
// must leave those tenants out of its query, and the fetch repeats until a row
// of an enabled tenant is found, the source is drained (fewer rows than
// limit) or maxSkipRounds is reached.
//
// off answers "is the module off for this tenant"; it must fail closed. A nil
// off keeps every row (no module wiring: the sweep runs as before).
func CollectEnabled[T any](
	ctx context.Context,
	limit int,
	fetch func(skip []shared.ID) ([]T, error),
	tenantOf func(T) shared.ID,
	off func(ctx context.Context, tenantID shared.ID) bool,
) ([]T, error) {
	var skip []shared.ID
	skipped := map[shared.ID]bool{}
	var kept []T
	for round := 0; round < maxSkipRounds; round++ {
		rows, err := fetch(skip)
		if err != nil {
			return nil, err
		}
		if off == nil {
			return rows, nil
		}
		for _, r := range rows {
			t := tenantOf(r)
			if skipped[t] {
				continue
			}
			if off(ctx, t) {
				skipped[t] = true
				skip = append(skip, t)
				continue
			}
			kept = append(kept, r)
		}
		if len(kept) > 0 || len(rows) < limit {
			break
		}
	}
	return kept, nil
}
