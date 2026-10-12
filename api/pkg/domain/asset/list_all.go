package asset

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/pagination"
)

// KeysetLister is implemented by a Repository that can page by id without a
// total count (postgres AssetRepository.ListAfterID).
type KeysetLister interface {
	ListAfterID(ctx context.Context, filter Filter, afterID string, limit int) ([]*Asset, error)
}

// PageLister is the List method of Repository, all ListAll needs.
type PageLister interface {
	List(ctx context.Context, filter Filter, opts ListOptions, page pagination.Pagination) (pagination.Result[*Asset], error)
}

// ListAll reads every asset matching filter (which must name the tenant) in
// batches of batch. It pages by id when the repository supports it, so a
// full read costs one indexed query per batch; otherwise it falls back to
// List pages.
func ListAll(ctx context.Context, repo PageLister, filter Filter, batch int) ([]*Asset, error) {
	if batch <= 0 {
		batch = 500
	}
	var all []*Asset
	if k, ok := repo.(KeysetLister); ok {
		after := ""
		for {
			page, err := k.ListAfterID(ctx, filter, after, batch)
			if err != nil {
				return nil, err
			}
			all = append(all, page...)
			if len(page) < batch {
				return all, nil
			}
			after = page[len(page)-1].ID().String()
		}
	}
	for pageNum := 1; ; pageNum++ {
		res, err := repo.List(ctx, filter, ListOptions{}, pagination.New(pageNum, batch))
		if err != nil {
			return nil, err
		}
		all = append(all, res.Data...)
		if len(res.Data) == 0 || int64(len(all)) >= res.Total {
			return all, nil
		}
	}
}
