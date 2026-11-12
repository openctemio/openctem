// Package compliancecheck serves the reads of benchmark check states
// (docs/architecture/compliance-checks.md, "Reads"): the posture per
// benchmark, a benchmark's controls, the assets of a control and the history
// of the control a finding fails. Every read runs in the caller's data scope
// and fails closed when the scope cannot be resolved.
package compliancecheck

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	ccdom "github.com/openctemio/openctem/api/pkg/domain/compliancecheck"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ErrNotConfigured: the service has no reader or no data scope enforcer.
var ErrNotConfigured = errors.New("compliance checks: not configured")

// Service reads compliance check states in the caller's scope.
type Service struct {
	reader ccdom.Reader
	scope  *datascope.Enforcer
}

// NewService creates a Service.
func NewService(reader ccdom.Reader, scope *datascope.Enforcer) *Service {
	return &Service{reader: reader, scope: scope}
}

// viewerScope is the caller's data scope (nil: unrestricted). It never falls
// back to unrestricted: an unwired enforcer is an error.
func (s *Service) viewerScope(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error) {
	if s == nil || s.reader == nil || s.scope == nil {
		return nil, ErrNotConfigured
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant id is required", shared.ErrValidation)
	}
	return s.scope.ResolveStrict(ctx, tenantID)
}

// validBenchmarkKey checks a benchmark key from a request: the shape
// BenchmarkKey produces.
func validBenchmarkKey(k string) error {
	if k == "" || len(k) > ccdom.MaxBenchmarkKeyLen || ccdom.BenchmarkKey(k) != k {
		return fmt.Errorf("%w: invalid benchmark", shared.ErrValidation)
	}
	return nil
}

// ParseResults parses a comma list of results ("" is none).
func ParseResults(s string) ([]ccdom.Result, error) {
	var out []ccdom.Result
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" {
			continue
		}
		r := ccdom.Result(p)
		if !r.IsValid() {
			return nil, fmt.Errorf("%w: unknown result", shared.ErrValidation)
		}
		out = append(out, r)
	}
	return out, nil
}

// ListBenchmarks returns the posture of each benchmark over the caller's
// assets, or over one asset (which must be in the caller's scope; an asset
// outside it reads as no benchmark).
func (s *Service) ListBenchmarks(ctx context.Context, tenantID shared.ID, assetID *shared.ID) ([]ccdom.BenchmarkPosture, error) {
	scope, err := s.viewerScope(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return s.reader.ListBenchmarks(ctx, tenantID, scope, assetID)
}

// ListControls returns a benchmark's controls over the caller's assets.
func (s *Service) ListControls(ctx context.Context, tenantID shared.ID, benchmarkKey string, f ccdom.ControlFilter,
	page pagination.Pagination) (pagination.Result[ccdom.ControlSummary], error) {
	if err := validBenchmarkKey(benchmarkKey); err != nil {
		return pagination.Result[ccdom.ControlSummary]{}, err
	}
	scope, err := s.viewerScope(ctx, tenantID)
	if err != nil {
		return pagination.Result[ccdom.ControlSummary]{}, err
	}
	return s.reader.ListControls(ctx, tenantID, scope, benchmarkKey, f, page)
}

// ListControlAssets returns one control's state on each of the caller's
// assets.
func (s *Service) ListControlAssets(ctx context.Context, tenantID shared.ID, benchmarkKey, controlID string, results []ccdom.Result,
	page pagination.Pagination) (pagination.Result[ccdom.ControlAsset], error) {
	if err := validBenchmarkKey(benchmarkKey); err != nil {
		return pagination.Result[ccdom.ControlAsset]{}, err
	}
	controlID = strings.TrimSpace(controlID)
	if controlID == "" || len(controlID) > ccdom.MaxControlIDLen {
		return pagination.Result[ccdom.ControlAsset]{}, fmt.Errorf("%w: invalid control", shared.ErrValidation)
	}
	scope, err := s.viewerScope(ctx, tenantID)
	if err != nil {
		return pagination.Result[ccdom.ControlAsset]{}, err
	}
	return s.reader.ListControlAssets(ctx, tenantID, scope, benchmarkKey, controlID, results, page)
}

// FindingControlHistory returns the history of the control a finding
// fails. The caller has already read the finding in the caller's scope
// (the finding detail's access check).
func (s *Service) FindingControlHistory(ctx context.Context, tenantID, findingID shared.ID) (*ccdom.ControlHistory, error) {
	if s == nil || s.reader == nil {
		return nil, ErrNotConfigured
	}
	return s.reader.FindingControlHistory(ctx, tenantID, findingID, ccdom.MaxHistory)
}
