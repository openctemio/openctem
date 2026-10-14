package scanrun

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// WithToolFacts wires the organization's tool catalog at construction.
func WithToolFacts(src stage.Source) Option {
	return func(s *Service) { s.tools = src }
}

// SetToolFacts wires the organization's tool catalog (internal/app/toolfacts).
func (s *Service) SetToolFacts(src stage.Source) { s.tools = src }

// catalog is the organization's stage catalog.
func (s *Service) catalog(ctx context.Context, tenantID shared.ID) (stage.Catalog, error) {
	cat, err := stage.CatalogOf(ctx, s.tools, tenantID)
	if err != nil {
		return stage.Catalog{}, fmt.Errorf("read the organization's tool contracts: %w", err)
	}
	return cat, nil
}
