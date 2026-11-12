package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type nbBody struct {
	AssetID   string `json:"asset_id"`
	Depth     int    `json:"depth"`
	Direction string `json:"direction"`
	MaxNodes  int    `json:"max_nodes"`
	Nodes     []struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Type            string `json:"type"`
		Distance        *int   `json:"distance"`
		Expanded        bool   `json:"expanded"`
		HiddenNeighbors int    `json:"hidden_neighbors"`
	} `json:"nodes"`
	Edges []struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Type   string `json:"type"`
	} `json:"edges"`
	Clusters []struct {
		ID        string         `json:"id"`
		Anchor    string         `json:"anchor"`
		Type      string         `json:"type"`
		Direction string         `json:"direction"`
		Count     int            `json:"count"`
		ByType    map[string]int `json:"by_type"`
	} `json:"clusters"`
	Lineage     lineageBody `json:"lineage"`
	Truncated   bool        `json:"truncated"`
	HiddenCount int         `json:"hidden_count"`
}

// Names that must never reach a caller who may not see them.
const (
	nbDomainMarker  = "nb-HIDDEN-root.example.com"
	nbServiceMarker = "nb-HIDDEN-svc:443"
	nbSharedIP      = "198.51.100.10"
	nbForeignSub    = "nbX-FOREIGN.example.org"
)

// nbFixture is the estate around one address: the domain contains the mail
// name, the mail name resolves to eleven addresses (ip0 is the one viewed),
// ip0 exposes a service and the service serves a certificate.
type nbFixture struct {
	domain, sub, svc, cert shared.ID
	ips                    []shared.ID
}

func (h *dsHarness) seedNeighborhood() nbFixture {
	h.t.Helper()
	tn := h.tenant.String()
	f := nbFixture{domain: shared.NewID(), sub: shared.NewID(), svc: shared.NewID(), cert: shared.NewID()}
	ins := func(id shared.ID, name, typ string) {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, $4, 'public', 'high')`,
			id.String(), tn, name, typ)
	}
	rel := func(src, tgt shared.ID, typ string) {
		h.exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, $4)`,
			tn, src.String(), tgt.String(), typ)
	}
	ins(f.domain, nbDomainMarker, "domain")
	ins(f.sub, "nb-mail.example.com", "subdomain")
	ins(f.svc, nbServiceMarker, "service")
	ins(f.cert, "nb-cert-sha256", "certificate")
	rel(f.domain, f.sub, "contains")
	for i := 0; i < 11; i++ {
		id := shared.NewID()
		f.ips = append(f.ips, id)
		name := fmt.Sprintf("198.51.100.%d", 10+i)
		ins(id, name, "ip_address")
		rel(f.sub, id, "resolves_to")
	}
	rel(f.ips[0], f.svc, "exposes")
	rel(f.svc, f.cert, "serves_certificate")
	return f
}

func (h *dsHarness) neighborhood(user shared.ID, admin bool, assetID, query string) (int, string, nbBody) {
	h.t.Helper()
	path := "/api/v1/assets/" + assetID + "/neighborhood"
	if query != "" {
		path += "?" + query
	}
	code, body := h.do(user, admin, http.MethodGet, path, nil)
	var b nbBody
	if code == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &b); err != nil {
			h.t.Fatalf("neighborhood body: %v: %.300s", err, body)
		}
	}
	return code, body, b
}

func (b nbBody) node(id shared.ID) (int, bool) {
	for i, n := range b.Nodes {
		if n.ID == id.String() {
			return i, true
		}
	}
	return -1, false
}

func (b nbBody) hasEdge(src, tgt shared.ID, typ string) bool {
	for _, e := range b.Edges {
		if e.Source == src.String() && e.Target == tgt.String() && e.Type == typ {
			return true
		}
	}
	return false
}

func TestAssetNeighborhood_TwoHopsLineageAndCluster(t *testing.T) {
	h := newDSHarness(t)
	f := h.seedNeighborhood()
	ip0 := f.ips[0]

	code, body, got := h.neighborhood(h.owner, true, ip0.String(), "")
	if code != http.StatusOK {
		t.Fatalf("owner: %d %s", code, body)
	}
	if got.Depth != 2 || got.Direction != "both" || got.MaxNodes != 150 || got.Truncated {
		t.Fatalf("defaults: %+v", got)
	}
	if got.Nodes[0].ID != ip0.String() || *got.Nodes[0].Distance != 0 || !got.Nodes[0].Expanded {
		t.Fatalf("first node is the asset: %+v", got.Nodes[0])
	}
	// The root domain is two hops up: drawn, with the edges that lead to it.
	want := map[shared.ID]int{f.sub: 1, f.svc: 1, f.domain: 2, f.cert: 2}
	for id, d := range want {
		i, ok := got.node(id)
		if !ok || got.Nodes[i].Distance == nil || *got.Nodes[i].Distance != d {
			t.Fatalf("node %s at distance %d missing: %s", id, d, body)
		}
	}
	if !got.hasEdge(f.sub, ip0, "resolves_to") || !got.hasEdge(f.domain, f.sub, "contains") ||
		!got.hasEdge(ip0, f.svc, "exposes") || !got.hasEdge(f.svc, f.cert, "serves_certificate") {
		t.Fatalf("edges: %+v", got.Edges)
	}
	// The ten other addresses of the mail name are one cluster, not ten nodes.
	if len(got.Nodes) != 5 {
		t.Fatalf("want 5 nodes, got %d: %s", len(got.Nodes), body)
	}
	if len(got.Clusters) != 1 {
		t.Fatalf("clusters: %+v", got.Clusters)
	}
	c := got.Clusters[0]
	if c.Anchor != f.sub.String() || c.Type != "resolves_to" || c.Direction != "outgoing" || c.Count != 10 || c.ByType["ip_address"] != 10 {
		t.Fatalf("cluster: %+v", c)
	}
	// The lineage goes asset, mail name, domain.
	l := got.Lineage.Nodes
	if len(l) != 3 || l[1].ID != f.sub.String() || l[1].Via != "resolves_to" || l[2].ID != f.domain.String() || l[2].Via != "contains" {
		t.Fatalf("lineage: %+v", l)
	}

	// Depth 1: the domain is beyond the walk but still drawn from the lineage.
	_, body, got = h.neighborhood(h.owner, true, ip0.String(), "depth=1")
	i, ok := got.node(f.domain)
	if !ok || got.Nodes[i].Distance != nil || got.Nodes[i].Expanded {
		t.Fatalf("depth 1 lineage root: %s", body)
	}
	if _, ok := got.node(f.cert); ok {
		t.Fatalf("depth 1 walked two hops: %s", body)
	}

	// Direction out from the mail name: only what it points at.
	_, body, got = h.neighborhood(h.owner, true, f.sub.String(), "depth=1&direction=out")
	if got.hasEdge(f.domain, f.sub, "contains") || len(got.Clusters) != 1 || got.Clusters[0].Count != 11 {
		t.Fatalf("direction out: %s", body)
	}

	// Filters: relations and types narrow the walk.
	_, body, got = h.neighborhood(h.owner, true, ip0.String(), "depth=3&relations=exposes,serves_certificate")
	if _, ok := got.node(f.cert); !ok || got.hasEdge(f.sub, ip0, "resolves_to") || len(got.Clusters) != 0 {
		t.Fatalf("relations filter: %s", body)
	}
	_, body, got = h.neighborhood(h.owner, true, ip0.String(), "depth=3&types=service")
	if _, ok := got.node(f.svc); !ok {
		t.Fatalf("types filter: %s", body)
	}
	if _, ok := got.node(f.cert); ok {
		t.Fatalf("types filter let a certificate in: %s", body)
	}
}

func TestAssetNeighborhood_BoundsAndCycles(t *testing.T) {
	h := newDSHarness(t)
	f := h.seedNeighborhood()
	ip0 := f.ips[0]
	tn := h.tenant.String()

	// A depth over the cap is clamped to 3, a limit over the cap to 300.
	code, body, got := h.neighborhood(h.owner, true, ip0.String(), "depth=9&limit=5000")
	if code != http.StatusOK || got.Depth != 3 || got.MaxNodes != 300 {
		t.Fatalf("clamp: %d %s", code, body)
	}

	// Node cap: what does not fit is counted in a cluster on its anchor and
	// the answer is truncated (the lineage never counts toward the cap).
	_, body, got = h.neighborhood(h.owner, true, ip0.String(), "depth=2&limit=2")
	if _, ok := got.node(f.cert); ok || !got.Truncated {
		t.Fatalf("cap: %s", body)
	}
	capped := false
	for _, c := range got.Clusters {
		if c.Anchor == f.svc.String() && c.Type == "serves_certificate" && c.Count == 1 && c.ByType["certificate"] == 1 {
			capped = true
		}
	}
	if !capped {
		t.Fatalf("cap cluster: %+v", got.Clusters)
	}

	// Cycles: the certificate "contains" the domain closes a loop; every
	// asset still appears once and the walk ends.
	h.exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'contains')`,
		tn, f.cert.String(), f.domain.String())
	h.exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'depends_on')`,
		tn, ip0.String(), f.sub.String())
	code, body, got = h.neighborhood(h.owner, true, ip0.String(), "depth=3")
	if code != http.StatusOK {
		t.Fatalf("cycle: %d %s", code, body)
	}
	seen := map[string]bool{}
	for _, n := range got.Nodes {
		if seen[n.ID] {
			t.Fatalf("node twice: %s", body)
		}
		seen[n.ID] = true
	}
	if !got.hasEdge(f.cert, f.domain, "contains") || !got.hasEdge(ip0, f.sub, "depends_on") {
		t.Fatalf("cycle edges not drawn: %+v", got.Edges)
	}

	// Bad input is refused.
	for _, q := range []string{"direction=sideways", "depth=0", "depth=x", "limit=-1", "types=bogus", "relations=bogus"} {
		if code, body, _ := h.neighborhood(h.owner, true, ip0.String(), q); code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", q, code, body)
		}
	}
}

func TestAssetNeighborhood_DataScope(t *testing.T) {
	h := newDSHarness(t)
	f := h.seedNeighborhood()
	ip0 := f.ips[0]
	tn := h.tenant.String()
	// memberA may see ip0 and the mail name only.
	for _, id := range []shared.ID{ip0, f.sub} {
		h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
			h.memberA.String(), tn, id.String())
	}

	for _, q := range []string{"depth=3", "depth=3&types=service", "depth=3&relations=exposes", "depth=3&direction=out"} {
		code, body, got := h.neighborhood(h.memberA, false, ip0.String(), q)
		if code != http.StatusOK {
			t.Fatalf("member %s: %d %s", q, code, body)
		}
		for _, leak := range []string{nbDomainMarker, nbServiceMarker, "nb-cert-sha256", f.domain.String(), f.svc.String(), f.cert.String(), "198.51.100.11"} {
			if strings.Contains(body, leak) {
				t.Fatalf("member %s learned %q: %s", q, leak, body)
			}
		}
		// The service is counted on ip0, whatever the filters (a filter
		// cannot tell what or how the hidden asset is).
		if got.Nodes[0].HiddenNeighbors != 1 {
			t.Fatalf("member %s hidden on ip0: %s", q, body)
		}
	}

	code, body, got := h.neighborhood(h.memberA, false, ip0.String(), "depth=2")
	if code != http.StatusOK || len(got.Nodes) != 2 || len(got.Clusters) != 0 {
		t.Fatalf("member nodes: %d %s", code, body)
	}
	i, _ := got.node(f.sub)
	// The mail name hangs off ten out-of-scope addresses and the domain.
	if got.Nodes[i].HiddenNeighbors != 11 || got.HiddenCount != 12 {
		t.Fatalf("member hidden counts: %s", body)
	}
	// The lineage root is a hidden hop with no identity.
	l := got.Lineage.Nodes
	if len(l) != 3 || !l[2].Hidden || l[2].ID != "" || l[2].Name != "" || l[2].Type != "" {
		t.Fatalf("member lineage: %+v", l)
	}

	// Out of the member's scope, or a member with no scope: not found.
	if code, body, _ := h.neighborhood(h.memberA, false, f.domain.String(), ""); code != http.StatusNotFound {
		t.Fatalf("out-of-scope asset: %d %s", code, body)
	}
	if code, body, _ := h.neighborhood(h.memberFree, false, ip0.String(), ""); code != http.StatusNotFound {
		t.Fatalf("member with no scope: %d %s", code, body)
	}
	// A full-data-access role sees everything.
	if _, body, got := h.neighborhood(h.memberFull, false, ip0.String(), ""); len(got.Nodes) != 5 {
		t.Fatalf("global reader: %s", body)
	}
}

func TestAssetNeighborhood_TenantIsolation(t *testing.T) {
	h := newDSHarness(t)
	f := h.seedNeighborhood()
	ip0 := f.ips[0]

	// Another tenant holds the same address name, related to its own name.
	other, foreignIP, foreignSub := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "nbx-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES
		($1, $3, $4, 'ip_address', 'public', 'high'), ($2, $3, $5, 'subdomain', 'public', 'high')`,
		foreignIP.String(), foreignSub.String(), other.String(), nbSharedIP, nbForeignSub)
	h.exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'resolves_to')`,
		other.String(), foreignSub.String(), foreignIP.String())

	code, body, _ := h.neighborhood(h.owner, true, ip0.String(), "depth=3")
	if code != http.StatusOK || strings.Contains(body, nbForeignSub) || strings.Contains(body, foreignIP.String()) {
		t.Fatalf("foreign asset via a shared address name: %d %s", code, body)
	}
	// Another tenant's asset is not found, even for an owner.
	if code, body, _ := h.neighborhood(h.owner, true, foreignIP.String(), ""); code != http.StatusNotFound {
		t.Fatalf("foreign asset: %d %s", code, body)
	}

	// An edge stored across tenants (the tenant-bound foreign keys refuse
	// one; stored here with triggers off, as a corrupted row would be) is
	// never followed.
	ctx := context.Background()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Skipf("cannot store a cross-tenant edge without superuser: %v", err)
	}
	for _, q := range []string{
		`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'resolves_to')`,
		`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $3, $2, 'exposes')`,
	} {
		if _, err := tx.ExecContext(ctx, q, h.tenant.String(), foreignSub.String(), ip0.String()); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	code, body, _ = h.neighborhood(h.owner, true, ip0.String(), "depth=3")
	if code != http.StatusOK || strings.Contains(body, nbForeignSub) || strings.Contains(body, foreignSub.String()) {
		t.Fatalf("cross-tenant edge followed: %d %s", code, body)
	}
}
