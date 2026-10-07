package easm

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeAddrStore struct {
	resolved map[string][]string
	props    map[string]map[string]any
	scope    *shared.ID
}

func (f *fakeAddrStore) ResolvedFrom(_ context.Context, _ shared.ID, scopeUser *shared.ID, _ []string) (map[string][]string, error) {
	f.scope = scopeUser
	return f.resolved, nil
}

func (f *fakeAddrStore) AddressProps(context.Context, shared.ID, []string) (map[string]map[string]any, error) {
	return f.props, nil
}

type coverNames map[string]bool

func (c coverNames) CoverOf(_ context.Context, _ shared.ID, names []string) (map[string]scopeauth.Via, error) {
	out := map[string]scopeauth.Via{}
	for _, n := range names {
		if c[n] {
			out[n] = scopeauth.Via{Kind: scopeauth.KindScopeTarget, Pattern: "*.vndirect.com.vn"}
		}
	}
	return out, nil
}

func explainPage(t *testing.T, caller ReviewCaller, props map[string]any, org string) *ReviewPage {
	t.Helper()
	store := &fakeAddrStore{
		resolved: map[string][]string{"202.160.124.20": {"vndirect.com.vn", "www.vndirect.com.vn", "other.example.net"}},
		props:    map[string]map[string]any{"202.160.124.20": props},
	}
	s := &ReviewService{coverage: coverNames{"vndirect.com.vn": true, "www.vndirect.com.vn": true}}
	s.SetAddressExplainer(store, func(context.Context, shared.ID) (string, error) { return org, nil })
	page := &ReviewPage{Items: []ReviewItem{
		{AssetID: "1", Name: "202.160.124.20", Type: "ip_address"},
		{AssetID: "2", Name: "202.160.124.20:443:tcp", Type: "service"},
		{AssetID: "3", Name: "app.vndirect.com.vn", Type: "subdomain"},
	}}
	if err := s.explainAddresses(context.Background(), shared.NewID(), nil, caller, page); err != nil {
		t.Fatal(err)
	}
	return page
}

func TestExplainAddresses_ApproverInMatchingOrg(t *testing.T) {
	page := explainPage(t, ReviewCaller{CanApprove: true, CanRequest: true},
		map[string]any{"asn": float64(131386), "asn_org": "VNDIRECT Securities Corporation"}, "VNDIRECT")
	for _, it := range page.Items[:2] {
		if len(it.ResolvedFrom) != 2 || it.ResolvedFrom[0] != "vndirect.com.vn" {
			t.Fatalf("%s resolved_from = %v (only in-scope names)", it.Name, it.ResolvedFrom)
		}
		if it.Hint != HintIPNeedsIPEntry || it.Network == nil || !it.Network.OrgMatches || it.Network.Shared || it.Network.ASN != "AS131386" {
			t.Fatalf("%s: hint %q network %+v", it.Name, it.Hint, it.Network)
		}
		if len(it.Fixes) != 2 || it.Fixes[0].Pattern != "202.160.124.20" || it.Fixes[0].TargetType != "ip_address" ||
			it.Fixes[1].Pattern != "202.160.124.0/24" || it.Fixes[1].TargetType != "cidr" ||
			it.Fixes[0].Action != scopedom.FixAddEntry || it.Fixes[0].Requires != "attack_surface:scope:approve" {
			t.Fatalf("%s fixes = %+v", it.Name, it.Fixes)
		}
	}
	if n := page.Items[2]; n.Hint != "" || n.Fixes != nil || n.ResolvedFrom != nil {
		t.Fatalf("a name row was explained as an address: %+v", n)
	}
}

func TestExplainAddresses_RangeOnlyWhenTheOrgMatches(t *testing.T) {
	page := explainPage(t, ReviewCaller{CanApprove: true},
		map[string]any{"asn_org": "Some Hosting Provider JSC"}, "VNDIRECT")
	if f := page.Items[0].Fixes; len(f) != 1 || f[0].TargetType != "ip_address" {
		t.Fatalf("fixes = %+v, want the single IP only", f)
	}
}

func TestExplainAddresses_SharedSpaceGetsNoFix(t *testing.T) {
	for _, props := range []map[string]any{
		{"cdn": "cloudflare"},
		{"asn_org": "Amazon.com, Inc. VNDIRECT"},
	} {
		page := explainPage(t, ReviewCaller{CanApprove: true}, props, "VNDIRECT")
		it := page.Items[0]
		if it.Network == nil || !it.Network.Shared || it.Network.OrgMatches || len(it.Fixes) != 0 {
			t.Fatalf("%v: network %+v fixes %+v", props, it.Network, it.Fixes)
		}
	}
}

func TestExplainAddresses_FixesFollowTheCaller(t *testing.T) {
	member := explainPage(t, ReviewCaller{CanRequest: true}, map[string]any{"asn_org": "VNDIRECT"}, "VNDIRECT").Items[0]
	if len(member.Fixes) != 1 || member.Fixes[0].Action != scopedom.FixRequestAccess || member.Fixes[0].Days != 7 ||
		member.Fixes[0].Pattern != "202.160.124.20" {
		t.Fatalf("member fixes = %+v", member.Fixes)
	}
	viewer := explainPage(t, ReviewCaller{}, map[string]any{"asn_org": "VNDIRECT"}, "VNDIRECT").Items[0]
	if len(viewer.Fixes) != 0 || viewer.Hint != HintIPNeedsIPEntry {
		t.Fatalf("viewer: %+v", viewer)
	}
}

func TestExplainAddresses_CoveredRowNeedsNoFix(t *testing.T) {
	store := &fakeAddrStore{resolved: map[string][]string{}, props: map[string]map[string]any{}}
	s := &ReviewService{}
	s.SetAddressExplainer(store, nil)
	via := scopeauth.Via{Kind: scopeauth.KindScopeTarget, Pattern: "202.160.124.0/24"}
	page := &ReviewPage{Items: []ReviewItem{{AssetID: "1", Name: "202.160.124.20", CoveredBy: &via}}}
	user := shared.NewID()
	if err := s.explainAddresses(context.Background(), shared.NewID(), &user, ReviewCaller{CanApprove: true}, page); err != nil {
		t.Fatal(err)
	}
	if it := page.Items[0]; it.Hint != "" || len(it.Fixes) != 0 {
		t.Fatalf("covered row: %+v", it)
	}
	if store.scope == nil || *store.scope != user {
		t.Fatal("the caller's data scope did not reach the store")
	}
}

func TestOrgMatches(t *testing.T) {
	for _, c := range []struct {
		org, asn string
		want     bool
	}{
		{"VNDIRECT", "VNDIRECT Securities Corporation", true},
		{"VNDirect Securities", "VNDIRECT-AS-VN", true},
		{"Acme Corp", "ACME Holdings Ltd", true},
		{"Acme Corp", "Some Hosting JSC", false},
		{"Viet Nam Group", "VIETNAM POSTS AND TELECOMMUNICATIONS GROUP", false},
		{"", "VNDIRECT", false},
		{"VNDIRECT", "", false},
	} {
		if got := orgMatches(c.org, c.asn); got != c.want {
			t.Errorf("orgMatches(%q, %q) = %v, want %v", c.org, c.asn, got, c.want)
		}
	}
}
