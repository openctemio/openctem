// Package apispec manages the API descriptions of origin assets and their
// drift against what scans observed (docs/rfcs/RFC-056-web-attack-surface.md
// WS13). Every read and write is tenant-scoped and limited to origins the
// caller may see; another tenant's or an out-of-scope id answers "not
// found".
package apispec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/openctemio/ctis/weburl"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/apispec"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
)

// AssetReader reads an asset of a tenant.
type AssetReader interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*asset.Asset, error)
}

// Service manages API descriptions.
type Service struct {
	repo      apispec.Repository
	assets    AssetReader
	dataScope *datascope.Enforcer
}

// NewService creates a Service.
func NewService(repo apispec.Repository, assets AssetReader, dataScope *datascope.Enforcer) *Service {
	return &Service{repo: repo, assets: assets, dataScope: dataScope}
}

// maxSpecsListed bounds one origin's list.
const maxSpecsListed = 100

// origin checks that originID is an http_service asset of the tenant the
// caller may see; anything else is not found.
func (s *Service) origin(ctx context.Context, tenantID, originID shared.ID) (*asset.Asset, error) {
	if s.dataScope != nil {
		if err := s.dataScope.AssertAsset(ctx, tenantID, originID); err != nil {
			return nil, shared.ErrNotFound
		}
	}
	a, err := s.assets.GetByID(ctx, tenantID, originID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	if a.TenantID() != tenantID {
		return nil, shared.ErrNotFound
	}
	if a.Type() != asset.AssetTypeService || !strings.EqualFold(a.SubType(), "http") {
		return nil, fmt.Errorf("%w: an API description belongs to a web origin (http service) asset", shared.ErrValidation)
	}
	return a, nil
}

// UploadInput is one uploaded description.
type UploadInput struct {
	TenantID      shared.ID
	OriginAssetID shared.ID
	Name          string
	GraphQLPath   string
	Data          []byte
	UploadedBy    *shared.ID
}

func cleanName(n string) string {
	n = strings.TrimSpace(n)
	n = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, n)
	if len(n) > 200 {
		n = n[:200]
	}
	return n
}

// Upload parses and stores a description for an origin.
func (s *Service) Upload(ctx context.Context, in UploadInput) (*apispec.Record, error) {
	if _, err := s.origin(ctx, in.TenantID, in.OriginAssetID); err != nil {
		return nil, err
	}
	gqlPath := ""
	if in.GraphQLPath != "" {
		p, err := weburl.NormalizePath(in.GraphQLPath)
		if err != nil {
			return nil, fmt.Errorf("%w: graphql_path must be an absolute path", shared.ErrValidation)
		}
		gqlPath = p
	}
	spec, err := apispec.Parse(in.Data, gqlPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", shared.ErrValidation, err)
	}
	sum := sha256.Sum256(in.Data)
	name := cleanName(in.Name)
	if name == "" {
		name = cleanName(spec.Title)
	}
	if name == "" {
		name = string(spec.Format)
	}
	rec := &apispec.Record{
		TenantID: in.TenantID, OriginAssetID: in.OriginAssetID, Name: name, Format: spec.Format,
		Title: cleanName(spec.Title), SpecVersion: cleanName(spec.Version), Digest: hex.EncodeToString(sum[:]),
		SizeBytes: len(in.Data), OperationCount: len(spec.Operations), Truncated: spec.Truncated, UploadedBy: in.UploadedBy,
	}
	if len(rec.SpecVersion) > 64 {
		rec.SpecVersion = rec.SpecVersion[:64]
	}
	if err := s.repo.Create(ctx, rec, spec.Operations); err != nil {
		return nil, err
	}
	return rec, nil
}

// List lists an origin's descriptions.
func (s *Service) List(ctx context.Context, tenantID, originID shared.ID) ([]*apispec.Record, error) {
	if _, err := s.origin(ctx, tenantID, originID); err != nil {
		return nil, err
	}
	return s.repo.ListByOrigin(ctx, tenantID, originID, maxSpecsListed)
}

// Get returns one description the caller may see.
func (s *Service) Get(ctx context.Context, tenantID, id shared.ID) (*apispec.Record, error) {
	rec, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if s.dataScope != nil {
		if err := s.dataScope.AssertAsset(ctx, tenantID, rec.OriginAssetID); err != nil {
			return nil, shared.ErrNotFound
		}
	}
	return rec, nil
}

// Drift compares a description with the endpoints scans observed on its
// origin.
func (s *Service) Drift(ctx context.Context, tenantID, id shared.ID) (*apispec.Record, apispec.Drift, error) {
	rec, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return nil, apispec.Drift{}, err
	}
	ops, err := s.repo.Operations(ctx, tenantID, id)
	if err != nil {
		return nil, apispec.Drift{}, err
	}
	observed, err := s.repo.Observed(ctx, tenantID, rec.OriginAssetID, webendpoint.MaxActivePerOrigin)
	if err != nil {
		return nil, apispec.Drift{}, err
	}
	return rec, apispec.ComputeDrift(ops, observed), nil
}

// Delete removes a description the caller may see.
func (s *Service) Delete(ctx context.Context, tenantID, id shared.ID) (*apispec.Record, error) {
	rec, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	return rec, s.repo.Delete(ctx, tenantID, id)
}
