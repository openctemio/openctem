package exposure

// A campaign owner must be an active member of the campaign tenant
// (research doc 21b, C2 / L-15): any platform user id used to be accepted.

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type campaignMembers map[[2]shared.ID]bool

func (m campaignMembers) IsActiveTenantMember(_ context.Context, tenantID, userID shared.ID) (bool, error) {
	return m[[2]shared.ID{tenantID, userID}], nil
}

// Groups are keyed the same way: (tenant, group).
func (m campaignMembers) IsGroupInTenant(_ context.Context, tenantID, groupID shared.ID) (bool, error) {
	return m[[2]shared.ID{tenantID, groupID}], nil
}

func TestCampaign_AssigneeMustBeActiveMember(t *testing.T) {
	tenant := shared.NewID()
	member, outsider := shared.NewID(), shared.NewID()
	svc := newService(newFakeCampaignRepo(), nil)
	svc.SetAssigneeChecker(campaignMembers{{tenant, member}: true})
	ctx := context.Background()
	create := func(assignee string) error {
		_, err := svc.CreateCampaign(ctx, CreateRemediationCampaignInput{
			TenantID: tenant.String(), Name: "c", Priority: "high", AssignedTo: assignee,
		}, auditapp.AuditContext{})
		return err
	}

	if err := create(outsider.String()); !errors.Is(err, ErrInvalidCampaignAssignee) {
		t.Fatalf("create with an outsider: err = %v, want ErrInvalidCampaignAssignee", err)
	}
	c, err := svc.CreateCampaign(ctx, CreateRemediationCampaignInput{
		TenantID: tenant.String(), Name: "c", Priority: "high", AssignedTo: member.String(),
	}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("create with a member: %v", err)
	}
	out, empty := outsider.String(), ""
	if _, err := svc.UpdateCampaign(ctx, tenant.String(), c.ID().String(), UpdateRemediationCampaignInput{AssignedTo: &out}, auditapp.AuditContext{}); !errors.Is(err, ErrInvalidCampaignAssignee) {
		t.Fatalf("update to an outsider: err = %v, want ErrInvalidCampaignAssignee", err)
	}
	if got := c.AssignedTo(); got == nil || *got != member {
		t.Fatalf("owner after a refused update = %v, want %s", got, member)
	}
	if _, err := svc.UpdateCampaign(ctx, tenant.String(), c.ID().String(), UpdateRemediationCampaignInput{AssignedTo: &empty}, auditapp.AuditContext{}); err != nil {
		t.Fatalf("unassign: %v", err)
	}

	svc.SetAssigneeChecker(nil)
	if err := create(member.String()); !errors.Is(err, ErrInvalidCampaignAssignee) {
		t.Fatalf("no checker: err = %v, want ErrInvalidCampaignAssignee (fail closed)", err)
	}
	if err := create(""); err != nil {
		t.Fatalf("no owner needs no checker: %v", err)
	}
}

// The validator team (assigned_team) must be a group of the campaign's
// organization; any group id used to be stored (research doc 21b, C2
// follow-up).
func TestCampaign_TeamMustBeTenantGroup(t *testing.T) {
	tenant := shared.NewID()
	ownGroup, foreignGroup := shared.NewID(), shared.NewID()
	svc := newService(newFakeCampaignRepo(), nil)
	svc.SetAssigneeChecker(campaignMembers{{tenant, ownGroup}: true})
	ctx := context.Background()

	if _, err := svc.CreateCampaign(ctx, CreateRemediationCampaignInput{
		TenantID: tenant.String(), Name: "c", Priority: "high", AssignedTeam: foreignGroup.String(),
	}, auditapp.AuditContext{}); !errors.Is(err, ErrInvalidCampaignTeam) {
		t.Fatalf("create with a foreign team: err = %v, want ErrInvalidCampaignTeam", err)
	}
	c, err := svc.CreateCampaign(ctx, CreateRemediationCampaignInput{
		TenantID: tenant.String(), Name: "c", Priority: "high", AssignedTeam: ownGroup.String(),
	}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("create with an own team: %v", err)
	}
	foreign, empty := foreignGroup.String(), ""
	if _, err := svc.UpdateCampaign(ctx, tenant.String(), c.ID().String(), UpdateRemediationCampaignInput{AssignedTeam: &foreign}, auditapp.AuditContext{}); !errors.Is(err, ErrInvalidCampaignTeam) {
		t.Fatalf("update to a foreign team: err = %v, want ErrInvalidCampaignTeam", err)
	}
	if got := c.AssignedTeam(); got == nil || *got != ownGroup {
		t.Fatalf("team after a refused update = %v, want %s", got, ownGroup)
	}
	if _, err := svc.UpdateCampaign(ctx, tenant.String(), c.ID().String(), UpdateRemediationCampaignInput{AssignedTeam: &empty}, auditapp.AuditContext{}); err != nil {
		t.Fatalf("clear team: %v", err)
	}
	svc.SetAssigneeChecker(nil)
	if _, err := svc.CreateCampaign(ctx, CreateRemediationCampaignInput{
		TenantID: tenant.String(), Name: "c", Priority: "high", AssignedTeam: ownGroup.String(),
	}, auditapp.AuditContext{}); !errors.Is(err, ErrInvalidCampaignTeam) {
		t.Fatalf("no checker: err = %v, want ErrInvalidCampaignTeam (fail closed)", err)
	}
}
