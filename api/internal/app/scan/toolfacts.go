package scan

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// WithToolFacts wires the organization's tool catalog at construction.
func WithToolFacts(src stage.Source) ServiceOption {
	return func(s *Service) { s.tools = src }
}

// SetToolFacts wires the organization's tool catalog (internal/app/toolfacts).
func (s *Service) SetToolFacts(src stage.Source) { s.tools = src }

// ToolFacts is the wired catalog source (nil when none is wired).
func (s *Service) ToolFacts() stage.Source { return s.tools }

// Catalog is the organization's stage catalog: the capability catalog with
// the tools its sensors' (and the platform's sensors') contracts declare.
func (s *Service) Catalog(ctx context.Context, tenantID shared.ID) (stage.Catalog, error) {
	return s.catalog(ctx, tenantID)
}

// catalog is the organization's stage catalog.
func (s *Service) catalog(ctx context.Context, tenantID shared.ID) (stage.Catalog, error) {
	if s == nil {
		return stage.Catalog{}, nil
	}
	cat, err := stage.CatalogOf(ctx, s.tools, tenantID)
	if err != nil {
		return stage.Catalog{}, fmt.Errorf("read the organization's tool contracts: %w", err)
	}
	return cat, nil
}
