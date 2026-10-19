package main

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	appticketmap "github.com/openctemio/openctem/api/internal/app/ticketmap"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ticketMappingObjects loads the objects a mapping preview renders. Every
// read is tenant-scoped; a task is read through the caller's data scope (a
// restricted caller sees it only with a finding in scope) and its members are
// filtered by scope again in the mapping service.
type ticketMappingObjects struct {
	findings *postgres.FindingRepository
	assets   *postgres.AssetRepository
	users    *postgres.UserRepository
	tasks    *remediationapp.TaskService
	taskRepo *postgres.RemediationTaskRepository
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

func (o ticketMappingObjects) Task(ctx context.Context, tenantID, id shared.ID) (*remediation.Task, error) {
	return o.tasks.GetTask(ctx, tenantID, id)
}

func (o ticketMappingObjects) TaskMembers(ctx context.Context, tenantID, id shared.ID, limit int) ([]*vulnerability.Finding, int64, error) {
	res, err := o.taskRepo.ListMembers(ctx, tenantID, id,
		remediation.MemberFilter{Role: remediation.MemberRolePrimary}, pagination.New(1, limit))
	if err != nil {
		return nil, 0, err
	}
	ids := make([]shared.ID, 0, len(res.Data))
	for _, m := range res.Data {
		ids = append(ids, m.FindingID)
	}
	findings, err := o.findings.GetByIDs(ctx, tenantID, ids)
	if err != nil {
		return nil, 0, err
	}
	return findings, res.Total, nil
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
