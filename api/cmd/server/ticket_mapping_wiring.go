package main

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	appticketmap "github.com/openctemio/openctem/api/internal/app/ticketmap"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// campaignMemberLister lists a remediation task's members through the
// caller's data scope (implemented by the remediation campaign service).
type campaignMemberLister interface {
	ListCampaignFindings(ctx context.Context, tenantID, campaignID string, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error)
}

// ticketMappingObjects loads the objects a mapping preview renders. Every
// read is tenant-scoped; task members come through the caller's data scope.
type ticketMappingObjects struct {
	findings  *postgres.FindingRepository
	assets    *postgres.AssetRepository
	users     *postgres.UserRepository
	campaigns *postgres.RemediationCampaignRepository
	members   campaignMemberLister
}

var _ appticketmap.ObjectSource = ticketMappingObjects{}

func (o ticketMappingObjects) Finding(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error) {
	return o.findings.GetByID(ctx, tenantID, id)
}

func (o ticketMappingObjects) Asset(ctx context.Context, tenantID, id shared.ID) (*appticketmap.AssetInfo, error) {
	a, err := o.assets.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	return &appticketmap.AssetInfo{Name: a.Name(), Type: string(a.Type()), Criticality: string(a.Criticality())}, nil
}

func (o ticketMappingObjects) User(ctx context.Context, _ shared.ID, id shared.ID) (*appticketmap.UserInfo, error) {
	u, err := o.users.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return &appticketmap.UserInfo{ID: id.String(), Email: u.Email(), Name: u.Name()}, nil
}

func (o ticketMappingObjects) Task(ctx context.Context, tenantID, id shared.ID) (*remediation.Campaign, error) {
	return o.campaigns.GetByID(ctx, tenantID, id)
}

func (o ticketMappingObjects) TaskMembers(ctx context.Context, tenantID, id shared.ID, limit int) ([]*vulnerability.Finding, int64, error) {
	if o.members == nil {
		return nil, 0, nil
	}
	res, err := o.members.ListCampaignFindings(ctx, tenantID.String(), id.String(), pagination.New(1, limit))
	if err != nil {
		return nil, 0, err
	}
	return res.Data, res.Total, nil
}

// ticketMappingScope adapts the data-scope enforcer to the mapping service.
type ticketMappingScope struct{ e *datascope.Enforcer }

var _ appticketmap.ScopeChecker = ticketMappingScope{}

func (s ticketMappingScope) AssertFinding(ctx context.Context, tenantID, findingID shared.ID) error {
	return s.e.AssertFinding(ctx, tenantID, findingID)
}

func (s ticketMappingScope) FilterFindings(ctx context.Context, tenantID shared.ID, ids []shared.ID) (func(shared.ID) bool, bool, error) {
	scope, err := s.e.Resolve(ctx, tenantID)
	if err != nil {
		return nil, false, err
	}
	keep, err := s.e.FilterFindings(ctx, scope, ids)
	if err != nil {
		return nil, false, err
	}
	return keep, scope.Restricted(), nil
}
