package unit

// User groups on a pentest campaign team (service layer): role rules, the
// tenant check, ordering of the "newly covered" read, and the audit trail.
// The access resolution itself is tested against Postgres in
// internal/infra/postgres/pentest_campaign_access_db_test.go.

import (
	"context"
	"errors"
	"strings"
	"testing"

	auditsvc "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/app/compliance"
	"github.com/openctemio/openctem/server/internal/app/integration"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/pentest"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type mockGroupGrantRepo struct {
	calls       []string
	createErr   error
	uncovered   []shared.ID
	grants      []*pentest.CampaignGroupGrant
	updatedRole pentest.CampaignRole
	deleteErr   error
}

func (m *mockGroupGrantRepo) Create(_ context.Context, g *pentest.CampaignGroupGrant) error {
	m.calls = append(m.calls, "create")
	if m.createErr != nil {
		return m.createErr
	}
	g.GroupName = "Red team"
	m.grants = append(m.grants, g)
	return nil
}

func (m *mockGroupGrantRepo) UpdateRole(_ context.Context, _, _, _ shared.ID, role pentest.CampaignRole) (pentest.CampaignRole, error) {
	m.calls = append(m.calls, "update")
	m.updatedRole = role
	return pentest.CampaignRoleObserver, nil
}

func (m *mockGroupGrantRepo) Delete(_ context.Context, tid, cid, gid shared.ID) (*pentest.CampaignGroupGrant, error) {
	m.calls = append(m.calls, "delete")
	if m.deleteErr != nil {
		return nil, m.deleteErr
	}
	return &pentest.CampaignGroupGrant{TenantID: tid, CampaignID: cid, GroupID: gid, Role: pentest.CampaignRoleTester, GroupName: "Red team"}, nil
}

func (m *mockGroupGrantRepo) ListByCampaign(_ context.Context, _, _ shared.ID) ([]*pentest.CampaignGroupGrant, error) {
	return m.grants, nil
}

func (m *mockGroupGrantRepo) ListGrantableGroups(_ context.Context, _, _ shared.ID, _ string, _ int) ([]pentest.GrantableGroup, error) {
	m.calls = append(m.calls, "grantable")
	return nil, nil
}

func (m *mockGroupGrantRepo) MembersWithoutAccess(_ context.Context, _, _, _ shared.ID) ([]shared.ID, error) {
	m.calls = append(m.calls, "uncovered")
	return m.uncovered, nil
}

type groupHarness struct {
	svc       *compliance.PentestService
	campaigns *teamMockCampaignRepo
	grants    *mockGroupGrantRepo
	audit     *recordingAuthAuditRepo
	tenant    shared.ID
	campaign  shared.ID
}

func newGroupHarness(t *testing.T) *groupHarness {
	t.Helper()
	svc, campaigns, _ := newTeamTestService(t)
	grants := &mockGroupGrantRepo{}
	svc.SetCampaignGroupGrantRepository(grants)
	rec := &recordingAuthAuditRepo{}
	svc.SetAuditService(auditsvc.NewAuditService(rec, logger.NewNop()))
	tenant := shared.NewID()
	c, _ := pentest.NewCampaign(tenant, "Engagement")
	campaigns.getByID = c
	return &groupHarness{svc: svc, campaigns: campaigns, grants: grants, audit: rec, tenant: tenant, campaign: c.ID()}
}

func (h *groupHarness) input(role string) compliance.CampaignGroupInput {
	return compliance.CampaignGroupInput{
		TenantID: h.tenant.String(), CampaignID: h.campaign.String(),
		GroupID: shared.NewID().String(), Role: role, ActorID: shared.NewID().String(),
	}
}

func (h *groupHarness) audited(action audit.Action) []*audit.AuditLog {
	var out []*audit.AuditLog
	for _, l := range h.audit.logs {
		if l.Action() == action {
			out = append(out, l)
		}
	}
	return out
}

func TestAddCampaignGroup_LeadRoleRefused(t *testing.T) {
	h := newGroupHarness(t)
	_, err := h.svc.AddCampaignGroup(context.Background(), h.input("lead"))
	if !errors.Is(err, pentest.ErrGroupLeadRole) || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrGroupLeadRole (validation), got %v", err)
	}
	if len(h.grants.calls) != 0 {
		t.Fatalf("no repository call expected, got %v", h.grants.calls)
	}
}

func TestAddCampaignGroup_UnknownRoleRefused(t *testing.T) {
	h := newGroupHarness(t)
	if _, err := h.svc.AddCampaignGroup(context.Background(), h.input("owner")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation error, got %v", err)
	}
}

func TestAddCampaignGroup_EveryNonLeadRoleAccepted(t *testing.T) {
	for _, role := range []string{"tester", "reviewer", "observer", "client"} {
		h := newGroupHarness(t)
		g, err := h.svc.AddCampaignGroup(context.Background(), h.input(role))
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		if string(g.Role) != role {
			t.Fatalf("%s: grant role %s", role, g.Role)
		}
	}
}

// A campaign of another tenant is not found: the grant is never written.
func TestAddCampaignGroup_CampaignOfAnotherTenant(t *testing.T) {
	h := newGroupHarness(t)
	h.campaigns.getByID, h.campaigns.getByIDErr = nil, pentest.ErrCampaignNotFound
	_, err := h.svc.AddCampaignGroup(context.Background(), h.input("tester"))
	if !errors.Is(err, pentest.ErrCampaignNotFound) {
		t.Fatalf("want ErrCampaignNotFound, got %v", err)
	}
	if len(h.grants.calls) != 0 {
		t.Fatalf("no repository call expected, got %v", h.grants.calls)
	}
}

// A group of another tenant (or an inactive one) is refused by the
// repository as not found, and nothing is audited as added.
func TestAddCampaignGroup_GroupOfAnotherTenant(t *testing.T) {
	h := newGroupHarness(t)
	h.grants.createErr = pentest.ErrGroupNotInTenant
	_, err := h.svc.AddCampaignGroup(context.Background(), h.input("tester"))
	if !errors.Is(err, pentest.ErrGroupNotInTenant) || !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrGroupNotInTenant (not found), got %v", err)
	}
	if n := len(h.audited(audit.ActionCampaignGroupAdded)); n != 0 {
		t.Fatalf("refused grant audited as added %d times", n)
	}
}

// The people a grant newly covers are read before the grant exists (after,
// they would already be on the team), and the add is audited once with the
// count.
func TestAddCampaignGroup_NewlyCoveredReadFirstAndAudited(t *testing.T) {
	h := newGroupHarness(t)
	h.grants.uncovered = []shared.ID{shared.NewID(), shared.NewID()}
	in := h.input("reviewer")
	if _, err := h.svc.AddCampaignGroup(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if len(h.grants.calls) < 2 || h.grants.calls[0] != "uncovered" || h.grants.calls[1] != "create" {
		t.Fatalf("want uncovered then create, got %v", h.grants.calls)
	}
	logs := h.audited(audit.ActionCampaignGroupAdded)
	if len(logs) != 1 {
		t.Fatalf("want one audit row, got %d", len(logs))
	}
	md := logs[0].Metadata()
	if md["group_id"] != in.GroupID || md["role"] != "reviewer" || md["members_added"] != 2 {
		t.Fatalf("audit metadata %v", md)
	}
}

func TestAddCampaignGroup_DuplicateIsConflict(t *testing.T) {
	h := newGroupHarness(t)
	h.grants.createErr = pentest.ErrGroupGrantExists
	if _, err := h.svc.AddCampaignGroup(context.Background(), h.input("tester")); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
}

func TestUpdateCampaignGroupRole_LeadRefusedAndChangeAudited(t *testing.T) {
	h := newGroupHarness(t)
	if err := h.svc.UpdateCampaignGroupRole(context.Background(), h.input("lead")); !errors.Is(err, pentest.ErrGroupLeadRole) {
		t.Fatalf("want ErrGroupLeadRole, got %v", err)
	}
	if err := h.svc.UpdateCampaignGroupRole(context.Background(), h.input("tester")); err != nil {
		t.Fatal(err)
	}
	logs := h.audited(audit.ActionCampaignGroupRoleChanged)
	if len(logs) != 1 || logs[0].Metadata()["previous_role"] != "observer" || logs[0].Metadata()["new_role"] != "tester" {
		t.Fatalf("role change audit %v", logs)
	}
}

// Removal deletes first, then reads who was left without access (they are
// notified), and is audited with the count.
func TestRemoveCampaignGroup_AuditedAfterDelete(t *testing.T) {
	h := newGroupHarness(t)
	h.grants.uncovered = []shared.ID{shared.NewID()}
	if err := h.svc.RemoveCampaignGroup(context.Background(), h.input("")); err != nil {
		t.Fatal(err)
	}
	if len(h.grants.calls) != 2 || h.grants.calls[0] != "delete" || h.grants.calls[1] != "uncovered" {
		t.Fatalf("want delete then uncovered, got %v", h.grants.calls)
	}
	logs := h.audited(audit.ActionCampaignGroupRemoved)
	if len(logs) != 1 || logs[0].Metadata()["members_removed"] != 1 || logs[0].Metadata()["previous_role"] != "tester" {
		t.Fatalf("removal audit %v", logs)
	}
}

func TestRemoveCampaignGroup_NotOnTeam(t *testing.T) {
	h := newGroupHarness(t)
	h.grants.deleteErr = pentest.ErrGroupGrantNotFound
	if err := h.svc.RemoveCampaignGroup(context.Background(), h.input("")); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	if n := len(h.audited(audit.ActionCampaignGroupRemoved)); n != 0 {
		t.Fatalf("failed removal audited %d times", n)
	}
}

func TestListGrantableCampaignGroups_CampaignOfAnotherTenant(t *testing.T) {
	h := newGroupHarness(t)
	h.campaigns.getByID, h.campaigns.getByIDErr = nil, pentest.ErrCampaignNotFound
	if _, err := h.svc.ListGrantableCampaignGroups(context.Background(), h.tenant.String(), h.campaign.String(), ""); !errors.Is(err, pentest.ErrCampaignNotFound) {
		t.Fatalf("want ErrCampaignNotFound, got %v", err)
	}
}

func TestCampaignRoleRank_Precedence(t *testing.T) {
	order := []pentest.CampaignRole{pentest.CampaignRoleClient, pentest.CampaignRoleObserver, pentest.CampaignRoleReviewer, pentest.CampaignRoleTester, pentest.CampaignRoleLead}
	for i := 1; i < len(order); i++ {
		if order[i].Rank() <= order[i-1].Rank() {
			t.Fatalf("%s must outrank %s", order[i], order[i-1])
		}
		if pentest.HigherCampaignRole(order[i-1], order[i]) != order[i] || pentest.HigherCampaignRole(order[i], order[i-1]) != order[i] {
			t.Fatalf("HigherCampaignRole(%s, %s)", order[i-1], order[i])
		}
	}
	if pentest.CampaignRole("bogus").Rank() != 0 {
		t.Fatal("unknown role must rank 0")
	}
}

// notifyCounter counts the notification rows a team change inserts.
type notifyCounter struct {
	notification.Repository
	created int
}

func (n *notifyCounter) Create(_ context.Context, _ *notification.Notification) error {
	n.created++
	return nil
}

func manyUsers(n int) []shared.ID {
	out := make([]shared.ID, n)
	for i := range out {
		out[i] = shared.NewID()
	}
	return out
}

// A group of thousands must not become thousands of inserts on the request:
// at most 50 people are told one by one, and the audit row carries both the
// number who gained access and the number notified.
func TestAddCampaignGroup_NotificationsCapped(t *testing.T) {
	h := newGroupHarness(t)
	counter := &notifyCounter{}
	h.svc.SetUserNotificationService(integration.NewNotificationService(counter, nil, logger.NewNop()))
	h.grants.uncovered = manyUsers(5000)
	if _, err := h.svc.AddCampaignGroup(context.Background(), h.input("tester")); err != nil {
		t.Fatal(err)
	}
	if counter.created != 50 {
		t.Fatalf("notifications inserted: %d, want 50", counter.created)
	}
	md := h.audited(audit.ActionCampaignGroupAdded)[0].Metadata()
	if md["members_added"] != 5000 || md["members_notified"] != 50 {
		t.Fatalf("audit metadata %v", md)
	}
}

func TestRemoveCampaignGroup_NotificationsCapped(t *testing.T) {
	h := newGroupHarness(t)
	counter := &notifyCounter{}
	h.svc.SetUserNotificationService(integration.NewNotificationService(counter, nil, logger.NewNop()))
	h.grants.uncovered = manyUsers(5000)
	if err := h.svc.RemoveCampaignGroup(context.Background(), h.input("")); err != nil {
		t.Fatal(err)
	}
	if counter.created != 50 {
		t.Fatalf("notifications inserted: %d, want 50", counter.created)
	}
	md := h.audited(audit.ActionCampaignGroupRemoved)[0].Metadata()
	if md["members_removed"] != 5000 || md["members_notified"] != 50 {
		t.Fatalf("audit metadata %v", md)
	}
}

// A group whose name cannot be found is named "a group" in the audit text:
// the id is in the metadata, never in the message.
func TestCampaignGroupAudit_MessageCarriesNoGroupID(t *testing.T) {
	h := newGroupHarness(t)
	in := h.input("observer")
	if err := h.svc.UpdateCampaignGroupRole(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	logs := h.audited(audit.ActionCampaignGroupRoleChanged)
	if len(logs) != 1 {
		t.Fatalf("want one audit row, got %d", len(logs))
	}
	if strings.Contains(logs[0].Message(), in.GroupID) {
		t.Fatalf("audit message carries the group id: %q", logs[0].Message())
	}
	if logs[0].Metadata()["group_id"] != in.GroupID {
		t.Fatalf("group id missing from metadata: %v", logs[0].Metadata())
	}
}
