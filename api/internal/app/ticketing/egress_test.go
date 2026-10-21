package ticketing

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/integration"
	pentestdom "github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type fakeLimit struct {
	tlp string
	err error
}

func (f fakeLimit) TrackerMaxTLP(context.Context, shared.ID) (string, error) { return f.tlp, f.err }

// fakeCampaigns is tenant-keyed: a campaign of another tenant is not found.
type fakeCampaigns struct {
	byTenant map[shared.ID]map[shared.ID]*pentestdom.Campaign
	err      error
}

func (f fakeCampaigns) GetByID(_ context.Context, tenantID, id shared.ID) (*pentestdom.Campaign, error) {
	if f.err != nil {
		return nil, f.err
	}
	if c, ok := f.byTenant[tenantID][id]; ok {
		return c, nil
	}
	return nil, shared.ErrNotFound
}

func egressCampaign(t *testing.T, tenantID shared.ID, tlp pentestdom.TLP) *pentestdom.Campaign {
	t.Helper()
	c, err := pentestdom.NewCampaign(tenantID, "engagement")
	if err != nil {
		t.Fatal(err)
	}
	c.SetProfile(nil, "", "", tlp)
	return c
}

func pentestFinding(t *testing.T, tenantID shared.ID, campaignID *shared.ID) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenantID, shared.NewID(), vulnerability.FindingSourcePentest, "manual", vulnerability.SeverityHigh, "SQL injection in login")
	if err != nil {
		t.Fatal(err)
	}
	f.SetPentestCampaignID(campaignID)
	return f
}

func refusal(t *testing.T, err error) EgressReason {
	t.Helper()
	var r *EgressRefusedError
	if !errors.As(err, &r) {
		t.Fatalf("want a refusal, got %v", err)
	}
	if !errors.Is(err, ErrEgressRefused) || !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("refusal must match ErrEgressRefused and ErrForbidden: %v", err)
	}
	return r.Reason
}

func TestEgressGate_PentestRoutes(t *testing.T) {
	tenant := shared.NewID()
	amber := egressCampaign(t, tenant, pentestdom.TLPAmber)
	id := amber.ID()
	gate := NewEgressGate(fakeLimit{}, fakeCampaigns{byTenant: map[shared.ID]map[shared.ID]*pentestdom.Campaign{tenant: {id: amber}}})
	f := pentestFinding(t, tenant, &id)
	ctx := context.Background()

	for _, route := range []Route{RouteFinding, RouteAutomation, RouteTask} {
		if got := refusal(t, gate.Check(ctx, tenant, route, f)); got != ReasonPentestCampaignOnly {
			t.Fatalf("route %q: reason %q", route, got)
		}
	}
	for _, route := range []Route{RouteCampaign, RouteStatusSync} {
		if err := gate.Check(ctx, tenant, route, f); err != nil {
			t.Fatalf("route %q: amber campaign under the default limit must pass: %v", route, err)
		}
	}
}

// A finding that names a campaign counts as pentest even with another source.
func TestEgressGate_CampaignReferenceIsPentest(t *testing.T) {
	tenant := shared.NewID()
	cid := shared.NewID()
	f, err := vulnerability.NewFinding(tenant, shared.NewID(), vulnerability.FindingSourceDAST, "zap", vulnerability.SeverityLow, "x")
	if err != nil {
		t.Fatal(err)
	}
	f.SetPentestCampaignID(&cid)
	if got := refusal(t, NewEgressGate(nil, nil).Check(context.Background(), tenant, RouteFinding, f)); got != ReasonPentestCampaignOnly {
		t.Fatalf("reason %q", got)
	}
}

func TestEgressGate_TLP(t *testing.T) {
	tenant := shared.NewID()
	ctx := context.Background()
	cases := []struct {
		name  string
		tlp   pentestdom.TLP
		limit string
		want  EgressReason // "" = allowed
	}{
		{"red never, default limit", pentestdom.TLPRed, "", ReasonTLPRed},
		{"red never, widest stored limit", pentestdom.TLPRed, "amber_strict", ReasonTLPRed},
		{"red never, even a stored red limit", pentestdom.TLPRed, "red", ReasonTLPRed},
		{"amber+strict above default amber", pentestdom.TLPAmberStrict, "", ReasonTLPAboveLimit},
		{"amber+strict within amber+strict", pentestdom.TLPAmberStrict, "amber_strict", ""},
		{"amber above green", pentestdom.TLPAmber, "green", ReasonTLPAboveLimit},
		{"green within amber", pentestdom.TLPGreen, "amber", ""},
		{"clear within clear", pentestdom.TLPClear, "clear", ""},
		{"unknown stored limit fails closed to clear", pentestdom.TLPGreen, "bogus", ReasonTLPAboveLimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := egressCampaign(t, tenant, tc.tlp)
			id := c.ID()
			gate := NewEgressGate(fakeLimit{tlp: tc.limit}, fakeCampaigns{byTenant: map[shared.ID]map[shared.ID]*pentestdom.Campaign{tenant: {id: c}}})
			err := gate.Check(ctx, tenant, RouteCampaign, pentestFinding(t, tenant, &id))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("want allowed, got %v", err)
				}
				return
			}
			if got := refusal(t, err); got != tc.want {
				t.Fatalf("reason %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEgressGate_FailsClosed(t *testing.T) {
	tenant := shared.NewID()
	ctx := context.Background()
	c := egressCampaign(t, tenant, pentestdom.TLPGreen)
	id := c.ID()
	known := map[shared.ID]map[shared.ID]*pentestdom.Campaign{tenant: {id: c}}

	// No gate, no campaign reader, no campaign id: refused.
	var nilGate *EgressGate
	if got := refusal(t, nilGate.Check(ctx, tenant, RouteCampaign, pentestFinding(t, tenant, &id))); got != ReasonPentestNoCampaign {
		t.Fatalf("nil gate: %q", got)
	}
	if got := refusal(t, NewEgressGate(nil, nil).Check(ctx, tenant, RouteCampaign, pentestFinding(t, tenant, &id))); got != ReasonPentestNoCampaign {
		t.Fatalf("no reader: %q", got)
	}
	gate := NewEgressGate(nil, fakeCampaigns{byTenant: known})
	if got := refusal(t, gate.Check(ctx, tenant, RouteCampaign, pentestFinding(t, tenant, nil))); got != ReasonPentestNoCampaign {
		t.Fatalf("no campaign id: %q", got)
	}

	// Cross-tenant: tenant B's request naming tenant A's campaign finds no
	// campaign, so it is refused.
	other := shared.NewID()
	if got := refusal(t, gate.Check(ctx, other, RouteCampaign, pentestFinding(t, other, &id))); got != ReasonPentestNoCampaign {
		t.Fatalf("cross-tenant: %q", got)
	}

	// Read errors are returned (not a pass).
	boom := errors.New("db down")
	err := NewEgressGate(nil, fakeCampaigns{err: boom}).Check(ctx, tenant, RouteCampaign, pentestFinding(t, tenant, &id))
	if !errors.Is(err, boom) {
		t.Fatalf("campaign read error: %v", err)
	}
	err = NewEgressGate(fakeLimit{err: boom}, fakeCampaigns{byTenant: known}).Check(ctx, tenant, RouteCampaign, pentestFinding(t, tenant, &id))
	if !errors.Is(err, boom) {
		t.Fatalf("limit read error: %v", err)
	}
}

func TestEgressGate_NonPentestPasses(t *testing.T) {
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "x")
	if err != nil {
		t.Fatal(err)
	}
	if err := (*EgressGate)(nil).Check(context.Background(), shared.NewID(), RouteAutomation, f); err != nil {
		t.Fatalf("non-pentest finding must pass every route: %v", err)
	}
}

func TestFindingContent(t *testing.T) {
	mk := func(src vulnerability.FindingSource) *vulnerability.Finding {
		f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), src, "tool", vulnerability.SeverityHigh, "msg")
		if err != nil {
			t.Fatal(err)
		}
		f.SetTitle("Leaked records of jane@example.com")
		return f
	}
	if got := FindingContent(mk(vulnerability.FindingSourceSecret)); got != ContentSecret {
		t.Fatalf("secret: %v", got)
	}
	pii := mk(vulnerability.FindingSourceDAST)
	if err := pii.SetDataExposureRisk(vulnerability.DataExposureRiskHigh); err != nil {
		t.Fatal(err)
	}
	if got := FindingContent(pii); got != ContentPersonalData {
		t.Fatalf("data exposure: %v", got)
	}
	if strings.Contains(OutboundTitle(pii), "jane@") {
		t.Fatalf("data exposure title leaked: %q", OutboundTitle(pii))
	}
	plain := mk(vulnerability.FindingSourceDAST)
	if got := FindingContent(plain); got != ContentFull || OutboundTitle(plain) != plain.Title() {
		t.Fatalf("plain finding: %v %q", got, OutboundTitle(plain))
	}
}

// GitHub: a pentest finding is refused on the generic and automation routes
// (no issue), allowed on the campaign route within the limit; a TLP:RED
// campaign's status push is skipped.
func TestGitHubTicket_EgressGate(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	green := egressCampaign(t, tenant, pentestdom.TLPGreen)
	red := egressCampaign(t, tenant, pentestdom.TLPRed)
	gid, rid := green.ID(), red.ID()
	gate := NewEgressGate(nil, fakeCampaigns{byTenant: map[shared.ID]map[shared.ID]*pentestdom.Campaign{tenant: {gid: green, rid: red}}})
	ir := &fakeIntegrationRepo{list: []*integration.Integration{connectedGitHubIntegration(t, tenant)}}

	for _, route := range []Route{RouteFinding, RouteAutomation} {
		ic := &fakeIssueCreator{number: 1, url: "https://github.com/octo/repo/issues/1"}
		s := newService(t, &fakeFindingRepo{finding: pentestFinding(t, tenant, &gid)}, ir, ic)
		s.SetEgressGate(gate)
		_, err := s.CreateTicketFromFinding(ctx, GitHubTicketInput{TenantID: tenant.String(), FindingID: shared.NewID().String(), Owner: "octo", Repo: "repo", Route: route})
		if got := refusal(t, err); got != ReasonPentestCampaignOnly || ic.calls != 0 {
			t.Fatalf("route %q: reason %q, calls %d", route, got, ic.calls)
		}
	}

	ic := &fakeIssueCreator{number: 2, url: "https://github.com/octo/repo/issues/2"}
	s := newService(t, &fakeFindingRepo{finding: pentestFinding(t, tenant, &gid)}, ir, ic)
	s.SetEgressGate(gate)
	if _, err := s.CreateTicketFromFinding(ctx, GitHubTicketInput{TenantID: tenant.String(), FindingID: shared.NewID().String(), Owner: "octo", Repo: "repo", Route: RouteCampaign}); err != nil || ic.calls != 1 {
		t.Fatalf("campaign route: %v, calls %d", err, ic.calls)
	}

	redFinding := pentestFinding(t, tenant, &rid)
	redFinding.AddWorkItemURI("https://github.com/octo/repo/issues/3")
	ic = &fakeIssueCreator{}
	s = newService(t, &fakeFindingRepo{finding: redFinding}, ir, ic)
	s.SetEgressGate(gate)
	if err := s.SyncFindingStatus(ctx, tenant, redFinding.ID()); err != nil || ic.stateCalls != 0 {
		t.Fatalf("TLP:RED status push: %v, calls %d", err, ic.stateCalls)
	}
}

func TestBuildIssueBody_DataExposureHasNoFreeText(t *testing.T) {
	f := newTestFinding(t, vulnerability.FindingSourceDAST)
	f.SetTitle("Customer list exposes jane@example.com")
	f.SetDescription("rows: jane@example.com")
	if err := f.SetDataExposureRisk(vulnerability.DataExposureRiskMedium); err != nil {
		t.Fatal(err)
	}
	if body, title := buildIssueBody(f), issueTitle(f); strings.Contains(body+title, "jane@") {
		t.Fatalf("data exposure issue carries free text:\n%s\n%s", title, body)
	}
}
