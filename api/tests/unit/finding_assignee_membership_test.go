package unit

// Naming an assignee (research doc 21b C2, research doc 15 L-15): the user
// must be an active member of the finding's tenant. Before the check any
// platform user's id was accepted, and that user's name and email were
// written into the tenant's activity log and returned by GET /findings/{id}.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// anyMember admits every user (tests that are not about membership).
type anyMember struct{}

func (anyMember) IsActiveTenantMember(context.Context, shared.ID, shared.ID) (bool, error) {
	return true, nil
}

// members admits exactly the listed (tenant, user) pairs.
type members map[[2]shared.ID]bool

func (m members) IsActiveTenantMember(_ context.Context, tenantID, userID shared.ID) (bool, error) {
	return m[[2]shared.ID{tenantID, userID}], nil
}

func TestVulnerabilityService_AssigneeMustBeActiveMember(t *testing.T) {
	tenant := shared.NewID()
	member, outsider := shared.NewID(), shared.NewID()

	newSvc := func(checker app.AssigneeChecker) (*app.VulnerabilityService, string) {
		svc, _, _ := newVulnTestService()
		svc.SetAssigneeChecker(checker)
		f := createTestFindingViaService(t, svc, tenant.String())
		return svc, f.ID().String()
	}
	only := members{{tenant, member}: true}

	t.Run("single: member accepted", func(t *testing.T) {
		svc, id := newSvc(only)
		if _, err := svc.AssignFinding(context.Background(), id, tenant.String(), member.String(), ""); err != nil {
			t.Fatalf("member: %v", err)
		}
	})
	for name, user := range map[string]shared.ID{"outsider": outsider, "unknown": shared.NewID()} {
		t.Run("single: "+name+" refused", func(t *testing.T) {
			svc, id := newSvc(only)
			f, err := svc.AssignFinding(context.Background(), id, tenant.String(), user.String(), "")
			if !errors.Is(err, app.ErrInvalidAssignee) {
				t.Fatalf("err = %v, want ErrInvalidAssignee", err)
			}
			if f != nil {
				t.Error("a finding was returned for a refused assignment")
			}
			got, _ := svc.GetFinding(context.Background(), tenant.String(), id)
			if got != nil && got.AssignedTo() != nil {
				t.Errorf("finding assigned to %s after a refusal", got.AssignedTo())
			}
		})
	}
	t.Run("no checker: refused (fail closed)", func(t *testing.T) {
		svc, id := newSvc(nil)
		if _, err := svc.AssignFinding(context.Background(), id, tenant.String(), member.String(), ""); !errors.Is(err, app.ErrInvalidAssignee) {
			t.Fatalf("err = %v, want ErrInvalidAssignee", err)
		}
	})
	t.Run("bulk: outsider refused before any write", func(t *testing.T) {
		svc, id := newSvc(only)
		res, err := svc.BulkAssignFindings(context.Background(), tenant.String(), app.BulkAssignInput{
			FindingIDs: []string{id}, UserID: outsider.String(),
		})
		if !errors.Is(err, app.ErrInvalidAssignee) {
			t.Fatalf("err = %v, want ErrInvalidAssignee", err)
		}
		if res != nil {
			t.Errorf("a result was returned: %+v", res)
		}
		got, _ := svc.GetFinding(context.Background(), tenant.String(), id)
		if got != nil && got.AssignedTo() != nil {
			t.Errorf("finding assigned to %s after a refused bulk assign", got.AssignedTo())
		}
	})
	t.Run("visibility", func(t *testing.T) {
		svc, _ := newSvc(only)
		if !svc.AssigneeVisible(context.Background(), tenant.String(), member.String()) {
			t.Error("an active member's profile must be visible")
		}
		if svc.AssigneeVisible(context.Background(), tenant.String(), outsider.String()) {
			t.Error("an outsider's profile must not be visible")
		}
		if svc.AssigneeVisible(context.Background(), shared.NewID().String(), member.String()) {
			t.Error("a member of another tenant must not be visible here")
		}
	})
}
