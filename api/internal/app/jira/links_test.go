package jira

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
)

type linkClient struct {
	recordingClient
	intg    shared.ID
	issues  map[string][2]string // asked key → id, current key
	queried []string
}

func (c *linkClient) IntegrationID() shared.ID { return c.intg }
func (c *linkClient) SiteURL() string          { return "https://acme.atlassian.net" }
func (c *linkClient) IssueIdentity(_ context.Context, key string) (string, string, error) {
	c.queried = append(c.queried, key)
	v, ok := c.issues[key]
	if !ok {
		return "", "", ErrIssueNotVisible
	}
	return v[0], v[1], nil
}

type memLinks struct {
	rows      []*ticketlink.Link
	createErr error
}

type fixedMapping MappingConfig

func (m fixedMapping) ResolveMapping(context.Context, shared.ID) (MappingConfig, error) {
	return MappingConfig(m), nil
}

// configured wires the projects the integration is set up for: SEC as the
// default, NEW through a routing rule and MAP through a mapping profile.
func configured(s *SyncService) {
	m := DefaultMappingConfig()
	m.DefaultProjectKey = "SEC"
	m.Routing = []RoutingRule{{Severity: []string{"critical"}, ProjectKey: "new"}}
	s.SetMappingResolver(fixedMapping(m))
	s.SetProfileSource(&stubProfiles{projects: []string{"MAP"}})
}

func (m *memLinks) Create(_ context.Context, l *ticketlink.Link) error {
	if m.createErr != nil {
		return m.createErr
	}
	for _, r := range m.rows {
		if r.State == ticketlink.StateActive && r.ExternalKey == l.ExternalKey && *r.FindingID == *l.FindingID {
			return ticketlink.ErrAlreadyLinked
		}
	}
	m.rows = append(m.rows, l)
	return nil
}
func (m *memLinks) Get(_ context.Context, tenantID, id shared.ID) (*ticketlink.Link, error) {
	for _, r := range m.rows {
		if r.ID == id && r.TenantID == tenantID {
			return r, nil
		}
	}
	return nil, ticketlink.ErrNotFound
}
func (m *memLinks) ListForFinding(context.Context, shared.ID, shared.ID) ([]*ticketlink.Link, error) {
	return m.rows, nil
}
func (m *memLinks) ListForCampaign(context.Context, shared.ID, shared.ID) ([]*ticketlink.Link, error) {
	return nil, nil
}
func (m *memLinks) FindByIssue(context.Context, shared.ID, shared.ID, string) ([]*ticketlink.Link, error) {
	return nil, nil
}
func (m *memLinks) SetState(_ context.Context, _, id shared.ID, state string) error {
	for _, r := range m.rows {
		if r.ID == id {
			r.State = state
			return nil
		}
	}
	return ticketlink.ErrNotFound
}
func (m *memLinks) RecordSync(context.Context, shared.ID, shared.ID, string, string, time.Time) error {
	return nil
}

func TestLinkExistingIssue(t *testing.T) {
	c := &linkClient{intg: shared.NewID(), issues: map[string][2]string{"SEC-12": {"10012", "SEC-12"}, "OLD-3": {"10003", "NEW-9"}}}
	repo := &stubFindingRepo{finding: buildFinding(t)}
	links := &memLinks{}
	s := newSync(repo, c)
	s.SetLinkStore(links)
	configured(s)
	tid, fid := shared.NewID(), shared.NewID()
	by := shared.NewID()

	l, err := s.LinkExistingIssue(context.Background(), tid, fid, "sec-12", &by)
	if err != nil {
		t.Fatal(err)
	}
	if l.ExternalKey != "SEC-12" || l.ExternalID != "10012" || l.IntegrationID != c.intg || l.Source != ticketlink.SourcePerson || *l.CreatedBy != by {
		t.Fatalf("link: %+v", l)
	}
	if len(repo.updatedURIs) != 1 || repo.updatedURIs[0] != "https://acme.atlassian.net/browse/SEC-12" {
		t.Fatalf("display list: %v", repo.updatedURIs)
	}
	// The same issue again: conflict.
	if _, err := s.LinkExistingIssue(context.Background(), tid, fid, "https://acme.atlassian.net/browse/SEC-12", &by); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	// A moved issue is linked under its current key.
	if l, err := s.LinkExistingIssue(context.Background(), tid, fid, "OLD-3", &by); err != nil || l.ExternalKey != "NEW-9" {
		t.Fatalf("moved: %+v %v", l, err)
	}
	// Refusals, before any tracker call for URLs on another site.
	before := len(c.queried)
	for _, bad := range []string{
		"https://evil.example/browse/SEC-1",
		"https://acme.atlassian.net.evil.test/browse/SEC-1",
		"not a key",
	} {
		if _, err := s.LinkExistingIssue(context.Background(), tid, fid, bad, &by); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if len(c.queried) != before {
		t.Fatal("the tracker was asked about an issue of another site")
	}
	if _, err := s.LinkExistingIssue(context.Background(), tid, fid, "SEC-999", &by); !errors.Is(err, ErrIssueNotVisible) {
		t.Fatalf("invisible issue: %v", err)
	}
}

func TestUnlinkIssue_OnlyTheFindingsOwnLink(t *testing.T) {
	c := &linkClient{intg: shared.NewID(), issues: map[string][2]string{"SEC-12": {"1", "SEC-12"}}}
	repo := &stubFindingRepo{finding: buildFinding(t, "https://acme.atlassian.net/browse/SEC-12", "https://other.example/x")}
	links := &memLinks{}
	s := newSync(repo, c)
	s.SetLinkStore(links)
	tid, fid := shared.NewID(), shared.NewID()
	l, err := ticketlink.New(tid, c.intg, &fid, nil, "SEC-12", "1", "https://acme.atlassian.net", "https://acme.atlassian.net/browse/SEC-12", ticketlink.RoleOwn, ticketlink.SourcePerson, nil)
	if err != nil {
		t.Fatal(err)
	}
	links.rows = append(links.rows, l)

	if _, err := s.UnlinkIssue(context.Background(), tid, shared.NewID(), l.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another finding's link: %v", err)
	}
	if _, err := s.UnlinkIssue(context.Background(), shared.NewID(), fid, l.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant: %v", err)
	}
	if _, err := s.UnlinkIssue(context.Background(), tid, fid, l.ID); err != nil {
		t.Fatal(err)
	}
	if l.State != ticketlink.StateUnlinked || strings.Join(repo.updatedURIs, ",") != "https://other.example/x" {
		t.Fatalf("state %s, display %v", l.State, repo.updatedURIs)
	}
}

func TestCreateTicket_RecordsThePlatformLink(t *testing.T) {
	c := &linkClient{intg: shared.NewID()}
	links := &memLinks{}
	s := newSync(&stubFindingRepo{finding: buildFinding(t)}, c)
	s.SetLinkStore(links)
	if _, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{
		TenantID: shared.NewID().String(), FindingID: shared.NewID().String(), ProjectKey: "PROJ",
	}); err != nil {
		t.Fatal(err)
	}
	if len(links.rows) != 1 || links.rows[0].Source != ticketlink.SourcePlatform || links.rows[0].ExternalKey != "PROJ-999" {
		t.Fatalf("links: %+v", links.rows)
	}
}

func TestLinkExistingIssue_OnlyConfiguredProjects(t *testing.T) {
	c := &linkClient{intg: shared.NewID(), issues: map[string][2]string{
		"HR-7": {"7", "HR-7"}, "MAP-1": {"8", "MAP-1"}, "NEW-2": {"9", "NEW-2"}, "SEC-3": {"10", "HR-4"},
	}}
	s := newSync(&stubFindingRepo{finding: buildFinding(t)}, c)
	links := &memLinks{}
	s.SetLinkStore(links)
	configured(s)
	tid, fid := shared.NewID(), shared.NewID()

	// A project the organization never configured: refused, nothing recorded.
	if _, err := s.LinkExistingIssue(context.Background(), tid, fid, "HR-7", nil); !errors.Is(err, ErrProjectNotConfigured) || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("HR-7: %v", err)
	}
	// An issue moved out of a configured project is judged by where it is now.
	if _, err := s.LinkExistingIssue(context.Background(), tid, fid, "SEC-3", nil); !errors.Is(err, ErrProjectNotConfigured) {
		t.Fatalf("moved to HR: %v", err)
	}
	if len(links.rows) != 0 {
		t.Fatalf("recorded %d links for refused issues", len(links.rows))
	}
	// Mapping-profile and routing projects are allowed.
	for _, k := range []string{"MAP-1", "NEW-2"} {
		if _, err := s.LinkExistingIssue(context.Background(), tid, fid, k, nil); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
}

func TestLinkExistingIssue_ListAndLinkStayTogether(t *testing.T) {
	c := &linkClient{intg: shared.NewID(), issues: map[string][2]string{"SEC-1": {"1", "SEC-1"}}}
	tid, fid := shared.NewID(), shared.NewID()

	// The finding's ticket list cannot be written: no link either.
	repo := &stubFindingRepo{finding: buildFinding(t), updateErr: errors.New("db down")}
	links := &memLinks{}
	s := newSync(repo, c)
	s.SetLinkStore(links)
	configured(s)
	if _, err := s.LinkExistingIssue(context.Background(), tid, fid, "SEC-1", nil); err == nil || len(links.rows) != 0 {
		t.Fatalf("err %v, links %d", err, len(links.rows))
	}

	// The link cannot be recorded: the list is put back.
	repo = &stubFindingRepo{finding: buildFinding(t, "https://other.example/x")}
	s = newSync(repo, c)
	s.SetLinkStore(&memLinks{createErr: errors.New("db down")})
	configured(s)
	if _, err := s.LinkExistingIssue(context.Background(), tid, fid, "SEC-1", nil); err == nil {
		t.Fatal("expected the link error")
	}
	if len(repo.updatedURIs) != 1 || repo.updatedURIs[0] != "https://other.example/x" {
		t.Fatalf("list not restored: %v", repo.updatedURIs)
	}
}
