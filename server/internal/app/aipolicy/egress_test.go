package aipolicy

import (
	"context"
	"errors"
	"testing"

	pentestdom "github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type fakePolicies struct {
	maxTLP string
	err    error
}

func (f fakePolicies) MCPPolicy(context.Context, shared.ID) (tenantdom.MCPSettings, error) {
	return tenantdom.MCPSettings{MaxTLP: f.maxTLP}, f.err
}

type fakeCampaigns struct {
	byID map[shared.ID]*pentestdom.Campaign
	err  error
	// tenants records the tenant of every read.
	tenants []shared.ID
}

func (f *fakeCampaigns) GetByID(_ context.Context, tenantID, id shared.ID) (*pentestdom.Campaign, error) {
	f.tenants = append(f.tenants, tenantID)
	if f.err != nil {
		return nil, f.err
	}
	c, ok := f.byID[id]
	if !ok || c.TenantID() != tenantID {
		return nil, shared.ErrNotFound
	}
	return c, nil
}

func campaign(t *testing.T, tenantID shared.ID, tlp pentestdom.TLP, aiOff bool) *pentestdom.Campaign {
	t.Helper()
	c, err := pentestdom.NewCampaign(tenantID, "c")
	if err != nil {
		t.Fatal(err)
	}
	c.SetProfile(nil, "", "", tlp)
	c.SetAIAssistantsDisabled(aiOff)
	return c
}

func finding(t *testing.T, tenantID shared.ID, src vulnerability.FindingSource, campaignID *shared.ID) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenantID, shared.NewID(), src, "tool", vulnerability.SeverityHigh, "m")
	if err != nil {
		t.Fatal(err)
	}
	f.SetPentestCampaignID(campaignID)
	return f
}

func reason(err error) Reason {
	var re *RestrictedError
	if errors.As(err, &re) {
		return re.Reason
	}
	return ""
}

func TestCampaignAllowed(t *testing.T) {
	tid := shared.NewID()
	cases := []struct {
		name   string
		max    pentestdom.TLP
		tlp    pentestdom.TLP
		aiOff  bool
		reason Reason
	}{
		{"amber under amber", pentestdom.TLPAmber, pentestdom.TLPAmber, false, ""},
		{"clear under amber", pentestdom.TLPAmber, pentestdom.TLPClear, false, ""},
		{"amber+strict over amber", pentestdom.TLPAmber, pentestdom.TLPAmberStrict, false, ReasonCampaignTLP},
		{"red over amber", pentestdom.TLPAmber, pentestdom.TLPRed, false, ReasonCampaignTLP},
		{"red under red", pentestdom.TLPRed, pentestdom.TLPRed, false, ""},
		{"lead switch wins", pentestdom.TLPRed, pentestdom.TLPClear, true, ReasonCampaignAIOff},
		{"unknown limit fails closed", "bogus", pentestdom.TLPClear, false, ReasonCampaignTLP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CampaignAllowed(campaign(t, tid, tc.tlp, tc.aiOff), tc.max)
			if got := reason(err); got != tc.reason {
				t.Fatalf("reason = %q, want %q (err %v)", got, tc.reason, err)
			}
			if tc.reason != "" && !errors.Is(err, ErrRestricted) {
				t.Fatalf("refusal must match ErrRestricted: %v", err)
			}
		})
	}
	if reason(CampaignAllowed(nil, pentestdom.TLPRed)) != ReasonNoCampaign {
		t.Fatal("a missing campaign must be refused")
	}
}

func TestEgress_CheckFinding(t *testing.T) {
	ctx := context.Background()
	tenantA, tenantB := shared.NewID(), shared.NewID()
	red := campaign(t, tenantA, pentestdom.TLPRed, false)
	amber := campaign(t, tenantA, pentestdom.TLPAmber, false)
	off := campaign(t, tenantA, pentestdom.TLPClear, true)
	other := campaign(t, tenantB, pentestdom.TLPClear, false)
	repo := &fakeCampaigns{byID: map[shared.ID]*pentestdom.Campaign{
		red.ID(): red, amber.ID(): amber, off.ID(): off, other.ID(): other,
	}}
	e := New(fakePolicies{}, repo)
	id := func(c *pentestdom.Campaign) *shared.ID { v := c.ID(); return &v }

	if err := e.CheckFinding(ctx, tenantA, finding(t, tenantA, vulnerability.FindingSourceSAST, nil)); err != nil {
		t.Fatalf("a scanner finding passes: %v", err)
	}
	if err := e.CheckFinding(ctx, tenantA, finding(t, tenantA, vulnerability.FindingSourcePentest, id(amber))); err != nil {
		t.Fatalf("an amber campaign passes the default limit: %v", err)
	}
	for name, tc := range map[string]struct {
		f    *vulnerability.Finding
		want Reason
	}{
		"red campaign":                 {finding(t, tenantA, vulnerability.FindingSourcePentest, id(red)), ReasonCampaignTLP},
		"AI off":                       {finding(t, tenantA, vulnerability.FindingSourcePentest, id(off)), ReasonCampaignAIOff},
		"no campaign":                  {finding(t, tenantA, vulnerability.FindingSourcePentest, nil), ReasonNoCampaign},
		"another tenant's campaign id": {finding(t, tenantA, vulnerability.FindingSourcePentest, id(other)), ReasonNoCampaign},
	} {
		if got := reason(e.CheckFinding(ctx, tenantA, tc.f)); got != tc.want {
			t.Errorf("%s: reason = %q, want %q", name, got, tc.want)
		}
	}
	for _, tid := range repo.tenants {
		if tid != tenantA {
			t.Fatalf("campaign read with tenant %s, want the caller's tenant only", tid)
		}
	}

	// The organization's own limit applies.
	if err := New(fakePolicies{maxTLP: "red"}, repo).CheckFinding(ctx, tenantA,
		finding(t, tenantA, vulnerability.FindingSourcePentest, id(red))); err != nil {
		t.Fatalf("red limit lets a red campaign through: %v", err)
	}
}

func TestEgress_FailsClosed(t *testing.T) {
	ctx := context.Background()
	tid := shared.NewID()
	c := campaign(t, tid, pentestdom.TLPClear, false)
	cid := c.ID()
	pentest := finding(t, tid, vulnerability.FindingSourcePentest, &cid)

	// Policy read error: refused (error returned, never nil).
	e := New(fakePolicies{err: errors.New("db down")}, &fakeCampaigns{byID: map[shared.ID]*pentestdom.Campaign{cid: c}})
	if err := e.CheckFinding(ctx, tid, pentest); err == nil {
		t.Fatal("a policy read error must refuse")
	}
	// Campaign read error: refused.
	e = New(fakePolicies{}, &fakeCampaigns{err: errors.New("db down")})
	if err := e.CheckFinding(ctx, tid, pentest); err == nil {
		t.Fatal("a campaign read error must refuse")
	}
	// No campaign reader, or no policy at all: pentest refused.
	if reason(New(nil, nil).CheckFinding(ctx, tid, pentest)) != ReasonNoCampaign {
		t.Fatal("without a campaign reader a pentest finding is refused")
	}
	var nilEgress *Egress
	if reason(nilEgress.CheckFinding(ctx, tid, pentest)) != ReasonNoCampaign {
		t.Fatal("a nil policy refuses pentest findings")
	}
	if err := nilEgress.CheckFinding(ctx, tid, finding(t, tid, vulnerability.FindingSourceDAST, nil)); err != nil {
		t.Fatalf("a nil policy passes scanner findings: %v", err)
	}
}
