package routes

// GET /findings?asset_ip=: the address filter runs inside the caller's data
// scope and the tenant; an address of another tenant's asset never matches.

import (
	"fmt"
	"math/rand/v2"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestFindingsAssetIP_ScopeAndTenant(t *testing.T) {
	h := newGroupScopeHarness(t)
	n := rand.IntN(200) //nolint:gosec // test fixture, not security relevant
	ipA, ipB := fmt.Sprintf("10.%d.1.5", n), fmt.Sprintf("10.%d.2.9", n)
	h.exec(`UPDATE assets SET name = $2, asset_type = 'ip_address' WHERE id = $1`, h.assetA.String(), ipA)
	h.exec(`UPDATE assets SET name = $2, asset_type = 'ip_address' WHERE id = $1`, h.assetB.String(), ipB)
	// Another tenant: an address inside every range below, with a finding.
	other, oa, of := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "ip-other-"+other.String())
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'ip_address')`, oa.String(), other.String(), fmt.Sprintf("10.%d.1.6", n))
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sca', 'ip-test', 'm', 'high', $1::text, 'new')`, of.String(), other.String(), oa.String())

	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}
	fa, fb, ofs := h.findingA.String(), h.findingB.String(), of.String()
	cases := []struct {
		name, ip   string
		admin, mem []string // must contain
		never      []string // must not contain, for both callers
	}{
		{"the /16", fmt.Sprintf("10.%d.0.0/16", n), []string{fa, fb}, []string{fa}, []string{ofs}},
		{"one address", ipA, []string{fa}, []string{fa}, []string{fb, ofs}},
		{"B's /24", fmt.Sprintf("10.%d.2.0/24", n), []string{fb}, nil, []string{fa, ofs}},
		{"two values", ipB + "," + ipA, []string{fa, fb}, []string{fa}, []string{ofs}},
	}
	for _, c := range cases {
		for _, who := range []struct {
			caller flCaller
			want   []string
		}{{admin, c.admin}, {memberA, c.mem}} {
			ids, _, _ := h.listIDs(t, who.caller, "state=all&per_page=100&asset_ip="+url.QueryEscape(c.ip))
			for _, w := range who.want {
				if !slices.Contains(ids, w) {
					t.Errorf("%s: %s misses %s (%v)", c.name, who.caller.name, w, ids)
				}
			}
			never := c.never
			if who.caller.user == h.memberA {
				never = append(never, fb) // out of memberA's scope
			}
			for _, x := range never {
				if slices.Contains(ids, x) {
					t.Errorf("%s: %s sees %s", c.name, who.caller.name, x)
				}
			}
		}
	}
	// A bad address is a 400 naming the param.
	status, _, body := h.listFindings(t, admin, "asset_ip=10.0.0.999")
	if status != 400 || !strings.Contains(body, "asset_ip") {
		t.Errorf("bad address = %d %s", status, body)
	}
}
