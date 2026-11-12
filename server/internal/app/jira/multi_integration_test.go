package jira

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// siteClient is the client of one integration on its own site.
type siteClient struct {
	recordingClient
	intg shared.ID
	site string
}

func (c *siteClient) IntegrationID() shared.ID { return c.intg }
func (c *siteClient) SiteURL() string          { return c.site }
func (c *siteClient) IssueIdentity(context.Context, string) (string, string, error) {
	return "", "", ErrIssueNotVisible
}

// twoSites resolves a tenant's two Jira integrations by id; the default
// (Resolve) is the first.
type twoSites struct {
	tenant shared.ID
	byID   map[shared.ID]*siteClient
	first  *siteClient
}

func (r *twoSites) Resolve(_ context.Context, tenantID shared.ID) (Client, error) {
	if tenantID != r.tenant {
		return nil, ErrNoTicketingIntegration
	}
	return r.first, nil
}

func (r *twoSites) ResolveByID(_ context.Context, tenantID, id shared.ID) (Client, error) {
	if c, ok := r.byID[id]; ok && tenantID == r.tenant {
		return c, nil
	}
	return nil, ErrNoTicketingIntegration
}

func (r *twoSites) ResolveMapping(ctx context.Context, tenantID shared.ID) (MappingConfig, error) {
	return r.ResolveMappingByID(ctx, tenantID, r.first.intg)
}

func (r *twoSites) ResolveMappingByID(_ context.Context, tenantID, id shared.ID) (MappingConfig, error) {
	c, ok := r.byID[id]
	if !ok || tenantID != r.tenant {
		return MappingConfig{}, ErrNoTicketingIntegration
	}
	m := DefaultMappingConfig()
	m.SiteURL, m.DefaultProjectKey = c.site, "SEC"
	return m, nil
}

func newTwoSites(tenant shared.ID) (*twoSites, *siteClient, *siteClient) {
	a := &siteClient{intg: shared.NewID(), site: "https://a.atlassian.net"}
	b := &siteClient{intg: shared.NewID(), site: "https://b.atlassian.net"}
	return &twoSites{tenant: tenant, byID: map[shared.ID]*siteClient{a.intg: a, b.intg: b}, first: a}, a, b
}

func findingLink(t *testing.T, tenant, intg, finding shared.ID, site, key, issueID string) *ticketlink.Link {
	t.Helper()
	l, err := ticketlink.New(tenant, intg, ticketlink.ForFinding(finding), key, issueID, site, ticketlink.BrowseURL(site, key),
		ticketlink.RoleOwn, ticketlink.SourcePlatform, nil)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// Two integrations, both with an issue SEC-1: a delivery for B moves only
// B's linked finding, and the refusal comment goes to B's site; a delivery
// for A moves only A's.
func TestInbound_TwoIntegrationsSameKey(t *testing.T) {
	tenant := shared.NewID()
	res, a, b := newTwoSites(tenant)
	fA, fB := shared.NewID(), shared.NewID()
	links := &memLinks{rows: []*ticketlink.Link{
		findingLink(t, tenant, a.intg, fA, a.site, "SEC-1", "100"),
		findingLink(t, tenant, b.intg, fB, b.site, "SEC-1", "200"),
	}}
	s := NewSyncService(&stubFindingRepo{finding: buildFinding(t)}, nil, logger.NewNop())
	s.SetClientResolver(res)
	s.SetMappingResolver(res)
	s.SetLinkStore(links)
	s.SetWorkItemFindingLister(noURLLinks{})
	app := &applierStub{refuse: []InboundRefusal{{FindingID: "f", Reason: "kept"}}}
	s.SetInboundApplier(app)

	p := doneWebhook()
	p.Issue.ID = "200"
	if err := s.HandleJiraWebhook(context.Background(), tenant, b.intg, p); err != nil {
		t.Fatal(err)
	}
	if len(app.ids) != 1 || app.ids[0] != fB {
		t.Fatalf("delivery for B moved %v, want only B's finding %s", app.ids, fB)
	}
	if len(b.comments) != 1 || len(a.comments) != 0 {
		t.Fatalf("refusal comments: A %d, B %d; want them on B only", len(a.comments), len(b.comments))
	}

	app.ids = nil
	p.Issue.ID = "100"
	if err := s.HandleJiraWebhook(context.Background(), tenant, a.intg, p); err != nil {
		t.Fatal(err)
	}
	if len(app.ids) != 1 || app.ids[0] != fA {
		t.Fatalf("delivery for A moved %v, want only A's finding %s", app.ids, fA)
	}

	// Another tenant naming B's integration resolves nothing and moves
	// nothing.
	app.ids = nil
	if err := s.HandleJiraWebhook(context.Background(), shared.NewID(), b.intg, p); err != nil {
		t.Fatal(err)
	}
	if len(app.ids) != 0 {
		t.Fatalf("a delivery for another tenant moved %v", app.ids)
	}
}

// A moved issue (new key, same id) is still matched by its id; a key now
// worn by another issue (another id) does not match a link that has an id;
// a link recorded without an id is matched by key, within its integration.
func TestInbound_MatchByIssueIDThenKey(t *testing.T) {
	tenant := shared.NewID()
	res, a, b := newTwoSites(tenant)
	fMoved, fNoID, fOtherSite := shared.NewID(), shared.NewID(), shared.NewID()
	links := &memLinks{rows: []*ticketlink.Link{
		findingLink(t, tenant, b.intg, fMoved, b.site, "OLD-4", "200"),
		findingLink(t, tenant, b.intg, fNoID, b.site, "SEC-9", ""),
		findingLink(t, tenant, a.intg, fOtherSite, a.site, "SEC-9", ""),
	}}
	s := NewSyncService(&stubFindingRepo{finding: buildFinding(t)}, nil, logger.NewNop())
	s.SetClientResolver(res)
	s.SetMappingResolver(res)
	s.SetLinkStore(links)
	s.SetWorkItemFindingLister(noURLLinks{})
	app := &applierStub{}
	s.SetInboundApplier(app)

	deliver := func(id, key string) []shared.ID {
		t.Helper()
		app.ids = nil
		p := doneWebhook()
		p.Issue.ID, p.Issue.Key = id, key
		if err := s.HandleJiraWebhook(context.Background(), tenant, b.intg, p); err != nil {
			t.Fatal(err)
		}
		return app.ids
	}
	if got := deliver("200", "SEC-50"); len(got) != 1 || got[0] != fMoved {
		t.Fatalf("moved issue: %v, want %s", got, fMoved)
	}
	if got := deliver("777", "OLD-4"); len(got) != 0 {
		t.Fatalf("old key worn by another issue matched %v", got)
	}
	if got := deliver("300", "SEC-9"); len(got) != 1 || got[0] != fNoID {
		t.Fatalf("key fallback: %v, want only B's link %s", got, fNoID)
	}
}

// A delivery must name its integration.
func TestInbound_RequiresIntegration(t *testing.T) {
	s := NewSyncService(&stubFindingRepo{finding: buildFinding(t)}, nil, logger.NewNop())
	if err := s.HandleJiraWebhook(context.Background(), shared.NewID(), shared.ID{}, doneWebhook()); !errors.Is(err, ErrInboundNoIntegration) {
		t.Fatalf("err = %v, want ErrInboundNoIntegration", err)
	}
}

// A task issue is pushed through its link's own integration, not the
// tenant's default one.
func TestSyncTaskIssue_UsesTheLinksIntegration(t *testing.T) {
	tenant := shared.NewID()
	res, a, b := newTwoSites(tenant)
	task := newTask(remediation.TaskStateInProgress)
	l, err := ticketlink.New(tenant, b.intg, ticketlink.ForTask(task.ID), "SEC-3", "300", b.site, ticketlink.BrowseURL(b.site, "SEC-3"),
		ticketlink.RoleOwn, ticketlink.SourcePerson, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.LastPushedState = string(remediation.TaskStateOpen)
	links := &memLinks{rows: []*ticketlink.Link{l}}
	s := NewSyncService(&stubFindingRepo{finding: buildFinding(t)}, nil, logger.NewNop())
	s.SetClientResolver(res)
	s.SetMappingResolver(res)
	s.SetLinkStore(links)
	store := &taskStore{tasks: map[shared.ID]*remediation.Task{task.ID: task}, members: map[shared.ID][]shared.ID{}}
	s.SetTaskSources(store, store)

	if err := s.SyncTaskIssue(context.Background(), tenant, task.ID); err != nil {
		t.Fatal(err)
	}
	if len(b.transitions) != 1 || len(a.transitions) != 0 {
		t.Fatalf("moves: A %v, B %v; want the move on B (the link's integration)", a.transitions, b.transitions)
	}
}

// A finding's outbound push uses its link's integration; a ticket URL on
// another site than the default integration's is never pushed through the
// default integration.
func TestFindingIssue_LinkIntegrationOrDefaultSite(t *testing.T) {
	tenant := shared.NewID()
	res, a, b := newTwoSites(tenant)
	s := NewSyncService(&stubFindingRepo{}, nil, logger.NewNop())
	s.SetMappingResolver(res)
	links := &memLinks{}
	s.SetLinkStore(links)

	f := buildFinding(t, b.site+"/browse/SEC-5")
	if intg, key, err := s.findingIssue(context.Background(), tenant, f); err != nil || key != "" || !intg.IsZero() {
		t.Fatalf("URL on B's site with no link: (%s, %q, %v), want no issue (the default is A)", intg, key, err)
	}
	links.rows = append(links.rows, findingLink(t, tenant, b.intg, f.ID(), b.site, "SEC-5", "500"))
	if intg, key, err := s.findingIssue(context.Background(), tenant, f); err != nil || key != "SEC-5" || intg != b.intg {
		t.Fatalf("linked: (%s, %q, %v), want B's SEC-5", intg, key, err)
	}
	g := buildFinding(t, a.site+"/browse/SEC-6")
	if intg, key, err := s.findingIssue(context.Background(), tenant, g); err != nil || key != "SEC-6" || !intg.IsZero() {
		t.Fatalf("URL on the default site: (%s, %q, %v), want SEC-6 on the default", intg, key, err)
	}
}
