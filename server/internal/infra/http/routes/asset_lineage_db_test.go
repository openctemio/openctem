package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type lineageBody struct {
	Nodes []struct {
		Depth           int    `json:"depth"`
		Hidden          bool   `json:"hidden"`
		Via             string `json:"via"`
		ID              string `json:"id"`
		Name            string `json:"name"`
		Type            string `json:"type"`
		DiscoverySource string `json:"discovery_source"`
		DiscoveryTool   string `json:"discovery_tool"`
	} `json:"nodes"`
	MaxDepth  int  `json:"max_depth"`
	Truncated bool `json:"truncated"`
}

const linMidMarker = "lin-HIDDEN-mid.example.com"

// linFixture: assetA's parent_id is mid, and root contains mid. memberA's
// scope holds assetA and root, not mid.
type linFixture struct{ mid, root shared.ID }

func (h *dsHarness) seedLineage() linFixture {
	h.t.Helper()
	t := h.tenant.String()
	f := linFixture{mid: shared.NewID(), root: shared.NewID()}
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality, discovery_source, discovery_tool) VALUES
		($1, $3, $4, 'subdomain', 'public', 'high', 'dns', 'dnsx'),
		($2, $3, 'lin-root.example.com', 'domain', 'public', 'high', 'manual', NULL)`,
		f.mid.String(), f.root.String(), t, linMidMarker)
	h.exec(`UPDATE assets SET parent_id = $1, discovery_source = 'dns', discovery_tool = 'subfinder'
		WHERE tenant_id = $2 AND id = $3`, f.mid.String(), t, h.assetA.String())
	h.exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type)
		VALUES ($1, $2, $3, 'contains')`, t, f.root.String(), f.mid.String())
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.memberA.String(), t, f.root.String())
	return f
}

func (h *dsHarness) lineage(user shared.ID, admin bool, assetID string) (int, string, lineageBody) {
	h.t.Helper()
	code, body := h.do(user, admin, http.MethodGet, "/api/v1/assets/"+assetID+"/lineage", nil)
	var b lineageBody
	if code == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &b); err != nil {
			h.t.Fatalf("lineage body: %v: %.300s", err, body)
		}
	}
	return code, body, b
}

func TestAssetLineage_ChainAndDataScopeRedaction(t *testing.T) {
	h := newDSHarness(t)
	f := h.seedLineage()

	// The owner sees the whole chain, asset first, with how each hop leads down.
	code, body, got := h.lineage(h.owner, true, h.assetA.String())
	if code != http.StatusOK {
		t.Fatalf("owner: %d %s", code, body)
	}
	if len(got.Nodes) != 3 || got.Truncated || got.MaxDepth != 5 {
		t.Fatalf("owner chain: %+v", got)
	}
	a, mid, root := got.Nodes[0], got.Nodes[1], got.Nodes[2]
	if a.ID != h.assetA.String() || a.DiscoverySource != "dns" || a.DiscoveryTool != "subfinder" || a.Via != "" {
		t.Fatalf("asset node: %+v", a)
	}
	if mid.ID != f.mid.String() || mid.Name != linMidMarker || mid.Via != "parent" || mid.Hidden {
		t.Fatalf("mid node: %+v", mid)
	}
	if root.ID != f.root.String() || root.Via != "contains" || root.Type != "domain" || root.Depth != 2 {
		t.Fatalf("root node: %+v", root)
	}

	// memberA may see assetA and root but not mid: mid is a hidden node with
	// no name, id or type, and the root above it is still shown.
	code, body, got = h.lineage(h.memberA, false, h.assetA.String())
	if code != http.StatusOK {
		t.Fatalf("member: %d %s", code, body)
	}
	if len(got.Nodes) != 3 {
		t.Fatalf("member chain: %+v", got)
	}
	m := got.Nodes[1]
	if !m.Hidden || m.ID != "" || m.Name != "" || m.Type != "" || m.DiscoverySource != "" || m.Via != "parent" {
		t.Fatalf("out-of-scope ancestor not redacted: %+v", m)
	}
	if got.Nodes[2].Name != "lin-root.example.com" || got.Nodes[2].Hidden {
		t.Fatalf("in-scope root: %+v", got.Nodes[2])
	}
	if strings.Contains(body, linMidMarker) || strings.Contains(body, f.mid.String()) || strings.Contains(body, "dnsx") {
		t.Fatalf("member learned an out-of-scope ancestor: %s", body)
	}
}

func TestAssetLineage_CycleGuardAndDepthCap(t *testing.T) {
	h := newDSHarness(t)
	f := h.seedLineage()
	tn := h.tenant.String()

	// assetA contains root closes a loop (root -> mid -> assetA -> root): the
	// walk stops before revisiting an asset.
	h.exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type)
		VALUES ($1, $2, $3, 'contains')`, tn, h.assetA.String(), f.root.String())
	code, body, got := h.lineage(h.owner, true, h.assetA.String())
	if code != http.StatusOK || len(got.Nodes) != 3 || got.Truncated {
		t.Fatalf("cycle: %d %s", code, body)
	}

	// A chain of eight: the asset plus five ancestors, and truncated.
	ids := make([]shared.ID, 8)
	for i := range ids {
		ids[i] = shared.NewID()
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			ids[i].String(), tn, "lin-deep-"+string(rune('a'+i))+".example.com")
		if i > 0 {
			h.exec(`UPDATE assets SET parent_id = $1 WHERE tenant_id = $2 AND id = $3`, ids[i].String(), tn, ids[i-1].String())
		}
	}
	code, body, got = h.lineage(h.owner, true, ids[0].String())
	if code != http.StatusOK || len(got.Nodes) != 6 || !got.Truncated {
		t.Fatalf("deep: %d %s", code, body)
	}
	if got.Nodes[5].ID != ids[5].String() {
		t.Fatalf("deep chain order: %+v", got.Nodes)
	}
}

func TestAssetLineage_TenantAndScopeRefusals(t *testing.T) {
	h := newDSHarness(t)
	h.seedLineage()

	// Out of the member's scope: not found (the route guard).
	if code, body, _ := h.lineage(h.memberA, false, h.assetB.String()); code != http.StatusNotFound {
		t.Fatalf("out-of-scope asset: %d %s", code, body)
	}
	// A member with no scope row sees nothing.
	if code, body, _ := h.lineage(h.memberFree, false, h.assetA.String()); code != http.StatusNotFound {
		t.Fatalf("member with no scope: %d %s", code, body)
	}

	// Another tenant's asset is not found, even for an owner.
	other, foreign := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "linx-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'linX-FOREIGN.example.com', 'domain', 'public', 'high')`,
		foreign.String(), other.String())
	if code, body, _ := h.lineage(h.owner, true, foreign.String()); code != http.StatusNotFound {
		t.Fatalf("foreign asset: %d %s", code, body)
	}

	// An edge pointing across tenants (the schema's tenant-bound foreign
	// keys refuse one; stored here with triggers off, as a corrupted row
	// would be) is never followed.
	ctx := context.Background()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Skipf("cannot store a cross-tenant edge without superuser: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type)
		VALUES ($1, $2, $3, 'contains')`, h.tenant.String(), foreign.String(), h.assetB.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET parent_id = $1 WHERE id = $2`, foreign.String(), h.assetB.String()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	code, body, got := h.lineage(h.owner, true, h.assetB.String())
	if code != http.StatusOK || len(got.Nodes) != 1 || strings.Contains(body, "linX-FOREIGN") {
		t.Fatalf("cross-tenant parent followed: %d %s", code, body)
	}
}
