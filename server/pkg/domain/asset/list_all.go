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
	var all []*Asset
	err := ForEachPage(ctx, repo, filter, batch, func(page []*Asset) error {
		all = append(all, page...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return all, nil
}

// ForEachPage calls fn with every asset matching filter (which must name the
// tenant), one batch at a time, without holding them all in memory. It pages
// by id when the repository supports it (the last page costs what the first
// does, and an asset added meanwhile is never read twice); otherwise it reads
// List pages until the total is reached, whatever page size List grants (a
// List page is capped below batch). An error from fn stops the walk.
func ForEachPage(ctx context.Context, repo PageLister, filter Filter, batch int, fn func([]*Asset) error) error {
	if batch <= 0 {
		batch = 500
	}
	if k, ok := repo.(KeysetLister); ok {
		after := ""
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			page, err := k.ListAfterID(ctx, filter, after, batch)
			if err != nil {
				return err
			}
			if len(page) > 0 {
				if err := fn(page); err != nil {
					return err
				}
			}
			if len(page) < batch {
				return nil
			}
			after = page[len(page)-1].ID().String()
		}
	}
	var read int64
	for pageNum := 1; ; pageNum++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		res, err := repo.List(ctx, filter, ListOptions{}, pagination.New(pageNum, batch))
		if err != nil {
			return err
		}
		if len(res.Data) == 0 {
			return nil
		}
		if err := fn(res.Data); err != nil {
			return err
		}
		read += int64(len(res.Data))
		if read >= res.Total {
			return nil
		}
	}
}
