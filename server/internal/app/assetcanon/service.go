package assetcanon

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Asset is one stored asset the runner looks at.
type Asset struct {
	ID      string
	Type    string
	SubType string
	Name    string
}

// Types are the stored asset types whose names have a CTIS 2.0 canonical
// form.
var Types = []string{
	"domain", "subdomain", "host", "ip_address", "network", "service", "container", "repository", "certificate",
}

// Store is what the runner reads and changes (postgres.AssetCanonicalRepository).
type Store interface {
	Tenants(ctx context.Context) ([]shared.ID, error)
	Page(ctx context.Context, tenantID shared.ID, afterID string, limit int) ([]Asset, error)
	Holder(ctx context.Context, tenantID shared.ID, name string) (*Asset, error)
	Rename(ctx context.Context, tenantID shared.ID, a Asset, newName string) (bool, error)
	Merge(ctx context.Context, tenantID shared.ID, a, keep Asset) (bool, error)
	Conflict(ctx context.Context, tenantID shared.ID, a Asset, newName, holderID string) error
	Revert(ctx context.Context, tenantID shared.ID) (reverted, kept int, err error)
}

// Report counts what one tenant's run did (or, dry, would do). Counts only:
// no names, so it can be logged and audited.
type Report struct {
	TenantID  string `json:"tenant_id"`
	Scanned   int    `json:"scanned"`
	Unchanged int    `json:"unchanged"`
	Renamed   int    `json:"renamed"`
	Merged    int    `json:"merged"`
	Conflicts int    `json:"conflicts"`
	Raced     int    `json:"raced"`
}

// Changed reports whether the run changed (or would change) anything.
func (r Report) Changed() bool { return r.Renamed+r.Merged > 0 }

// pageSize is how many assets one page reads.
const pageSize = 1000

// Service runs the canonical-name migration.
type Service struct {
	store Store
}

// NewService creates the service.
func NewService(store Store) *Service { return &Service{store: store} }

// RunAll runs every tenant, calling each with the tenant's report.
func (s *Service) RunAll(ctx context.Context, apply bool, each func(Report)) error {
	tenants, err := s.store.Tenants(ctx)
	if err != nil {
		return err
	}
	for _, t := range tenants {
		rep, err := s.Run(ctx, t, apply)
		if err != nil {
			return fmt.Errorf("tenant %s: %w", t.String(), err)
		}
		if each != nil {
			each(rep)
		}
	}
	return nil
}

// Run moves the tenant's asset names to their canonical form. Dry (apply
// false) it only counts. Idempotent: an asset already canonical is
// unchanged, so a second run changes nothing. Every read and write is
// scoped by tenantID; a merge joins only assets of the same tenant, type and
// sub-type.
func (s *Service) Run(ctx context.Context, tenantID shared.ID, apply bool) (Report, error) {
	rep := Report{TenantID: tenantID.String()}
	planned := map[string]string{} // dry run: canonical name -> asset that would hold it
	after := ""
	for {
		page, err := s.store.Page(ctx, tenantID, after, pageSize)
		if err != nil {
			return rep, err
		}
		if len(page) == 0 {
			return rep, nil
		}
		for _, a := range page {
			if err := ctx.Err(); err != nil {
				return rep, err
			}
			rep.Scanned++
			if err := s.one(ctx, tenantID, a, apply, planned, &rep); err != nil {
				return rep, err
			}
		}
		after = page[len(page)-1].ID
	}
}

func (s *Service) one(ctx context.Context, tenantID shared.ID, a Asset, apply bool,
	planned map[string]string, rep *Report,
) error {
	name, ok := CanonicalName(asset.AssetType(a.Type), a.SubType, a.Name)
	if !ok || name == a.Name {
		rep.Unchanged++
		return nil
	}
	holder, err := s.store.Holder(ctx, tenantID, name)
	if err != nil {
		return err
	}
	if !apply {
		switch {
		case holder != nil && (holder.Type != a.Type || holder.SubType != a.SubType):
			rep.Conflicts++
		case holder != nil || planned[name] != "":
			rep.Merged++
		default:
			planned[name] = a.ID
			rep.Renamed++
		}
		return nil
	}
	switch {
	case holder == nil:
		done, err := s.store.Rename(ctx, tenantID, a, name)
		if err != nil {
			return err
		}
		if !done {
			rep.Raced++
			return nil
		}
		rep.Renamed++
	case holder.Type != a.Type || holder.SubType != a.SubType:
		// Another kind of asset holds the name: two different things, not
		// a duplicate. Left as it is and recorded.
		if err := s.store.Conflict(ctx, tenantID, a, name, holder.ID); err != nil {
			return err
		}
		rep.Conflicts++
	default:
		done, err := s.store.Merge(ctx, tenantID, a, *holder)
		if err != nil {
			return err
		}
		if !done {
			rep.Raced++
			return nil
		}
		rep.Merged++
	}
	return nil
}

// Revert gives the tenant's renamed assets their old names back (merges
// are not undone).
func (s *Service) Revert(ctx context.Context, tenantID shared.ID) (reverted, kept int, err error) {
	return s.store.Revert(ctx, tenantID)
}
