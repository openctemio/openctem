//go:build authzmatrix

package authzmatrix

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// Custom roles every fully seeded tenant gets, besides one role per
// built-in template.
var customRoles = []struct {
	slug     string
	fullData bool
	perms    []string
}{
	// Read-only on assets and findings; no data scope bypass.
	{"narrow-readonly", false, []string{"assets:read", "findings:read", "dashboard:read"}},
	// Writes findings but may not approve anything (four-eyes candidates).
	// It also mints the narrow API keys (members cannot).
	{"writer-no-approve", false, []string{"assets:read", "assets:write", "findings:read", "findings:write",
		"findings:comment", "findings:status", "findings:assign", "dashboard:read",
		"integrations:api_keys:read", "integrations:api_keys:write"}},
}

// nearAdminPerms is every permission an owner may put in a custom role.
func nearAdminPerms() []string {
	all := permission.AllPermissions()
	out := make([]string, 0, len(all))
	for _, p := range all {
		if permission.IsAdminOnly(string(p)) {
			continue
		}
		out = append(out, string(p))
	}
	return out
}

func toSet(ps []string) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		m[p] = true
	}
	return m
}

func union(a, b map[string]bool) map[string]bool {
	m := map[string]bool{}
	for k := range a {
		m[k] = true
	}
	for k := range b {
		m[k] = true
	}
	return m
}

// seedResources creates the tenant data the matrix points at.
func (w *world) seedResources(t testing.TB, ten *tenant) {
	t.Helper()
	o := ten.owner.cred
	call := func(what, method, path string, body any, want ...int) response {
		t.Helper()
		return must(t, ten.Name+": "+what, want...)(w.c.do(o, method, path, body))
	}
	d := func(label string) string { return label + "." + ten.Slug + ".example.com" }

	for _, a := range []string{"scoped", "oos", "victim"} {
		r := call("asset "+a, "POST", "/api/v1/assets", map[string]any{"name": d(a + "-asset"), "type": "domain",
			"criticality": "high", "description": ten.Name + " " + a + " asset"})
		ten.set("asset."+a, jsonID(r, "id"))
	}
	call("scope target", "POST", "/api/v1/scope/targets", map[string]any{"target_type": "domain",
		"pattern": "*." + ten.Slug + ".example.com", "description": "matrix scope"})

	// Sensors: the matrix sensor principal pushes findings for the scoped
	// and the out-of-scope asset; the victim sensor may be deleted.
	call("result policy", "PUT", "/api/v1/sensors/result-policy", map[string]any{"mode": "warn"})
	call("identity policy", "PUT", "/api/v1/sensors/identity-policy", map[string]any{"bearer_keys_allowed": true})
	for _, s := range []string{"matrix", "victim"} {
		r := call("sensor "+s, "POST", "/api/v1/sensors", map[string]any{"name": ten.Slug + "-" + s + "-sensor",
			"type": "worker", "execution_mode": "daemon", "tools": []string{"nuclei"}, "capabilities": []string{"vulnerability"}})
		ten.set("sensor."+s, jsonID(r, "sensor", "id"))
		ten.set("sensorkey."+s, jsonID(r, "api_key"))
	}
	sid := ten.get("sensor.matrix")
	r := call("sensor grant", "GET", "/api/v1/sensors/"+sid+"/grant", nil)
	var grant map[string]any
	_ = json.Unmarshal(r.Body, &grant)
	for _, k := range []string{"sensor_id", "legacy_broad", "updated_at", "effective", "profile"} {
		delete(grant, k)
	}
	grant["trust_level"], grant["allow_push_ingest"], grant["tier_ceiling"] = "trusted", true, 2
	call("sensor grant", "PUT", "/api/v1/sensors/"+sid+"/grant", grant)
	key := bearer(ten.get("sensorkey.matrix"))
	must(t, ten.Name+": heartbeat")(w.c.do(key, "POST", "/api/v2/sensor/heartbeat", map[string]any{"status": "online",
		"scanners": []string{"nuclei"}, "tools": []map[string]any{{"name": "nuclei", "kind": "scanner", "installed": true}}}))
	w.ingest(t, ten, key)

	// Findings arrive asynchronously; wait for both.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		r := call("findings", "GET", "/api/v1/findings?per_page=100", nil)
		var list struct {
			Data []struct {
				ID      string `json:"id"`
				Title   string `json:"title"`
				AssetID string `json:"asset_id"`
			} `json:"data"`
		}
		_ = r.json(&list)
		for _, f := range list.Data {
			switch {
			case strings.HasPrefix(f.Title, ten.Name+" scoped finding"):
				ten.set("finding.scoped", f.ID)
				ten.set("asset.scoped.ingest", f.AssetID)
			case strings.HasPrefix(f.Title, ten.Name+" oos finding"):
				ten.set("finding.oos", f.ID)
				ten.set("asset.oos.ingest", f.AssetID)
			case strings.HasPrefix(f.Title, ten.Name+" victim finding"):
				ten.set("finding.victim", f.ID)
			}
		}
		if ten.get("finding.scoped") != "" && ten.get("finding.oos") != "" && ten.get("finding.victim") != "" {
			break
		}
		time.Sleep(time.Second)
	}
	if ten.get("finding.scoped") == "" || ten.get("finding.oos") == "" {
		t.Fatalf("%s: ingested findings not visible", ten.Name)
	}
	call("comment", "POST", "/api/v1/findings/"+ten.get("finding.scoped")+"/comments", map[string]any{"content": ten.Name + " matrix comment"}, 200, 201)

	// Groups: the scope group gives the scoped member its one asset; the
	// role group grants a role through membership; the victim may go.
	for _, g := range []string{"scope", "role", "victim"} {
		r := call("group "+g, "POST", "/api/v1/groups", map[string]any{"name": ten.Name + " " + g + " group",
			"slug": ten.Slug + "-" + g + "-group", "group_type": "team"})
		ten.set("group."+g, jsonID(r, "id"))
	}
	for _, a := range []string{"asset.scoped", "asset.scoped.ingest"} {
		if id := ten.get(a); id != "" {
			call("group asset", "POST", "/api/v1/groups/"+ten.get("group.scope")+"/assets",
				map[string]any{"asset_id": id, "ownership_type": "primary"}, 200, 201, 204, 409)
		}
	}

	// Other tenant data, so most {id} routes find a real row to point at.
	r = call("asset group", "POST", "/api/v1/asset-groups", map[string]any{"name": ten.Name + " asset group",
		"environment": "production", "criticality": "high", "description": "matrix"}, 200, 201)
	ten.set("assetgroup", jsonID(r, "id"))
	r = call("scan", "POST", "/api/v1/scans/", map[string]any{"name": ten.Name + " scan", "scan_type": "single",
		"scanner_name": "nuclei", "targets": []string{d("scoped-asset")}, "schedule_type": "manual"}, 200, 201)
	ten.set("scan", jsonID(r, "id"))
	r = call("remediation campaign", "POST", "/api/v1/remediation/campaigns", map[string]any{"name": ten.Name + " campaign",
		"description": "matrix", "priority": "high"}, 200, 201)
	ten.set("campaign", jsonID(r, "id"))
	r = call("victim role", "POST", "/api/v1/roles", map[string]any{"slug": "victim-role", "name": "victim-role",
		"hierarchy_level": 10, "permissions": []string{"assets:read"}})
	ten.set("role.victim", jsonID(r, "id"))
}

// ingest pushes one CTIS report from the matrix sensor: a finding on the
// scoped asset, one on the out-of-scope asset and one to delete.
func (w *world) ingest(t testing.TB, ten *tenant, key credential) {
	t.Helper()
	id := uuid.NewString()
	report := map[string]any{
		"version":  "1.0",
		"metadata": map[string]any{"id": id, "timestamp": time.Now().UTC().Format(time.RFC3339), "source_type": "scanner"},
		"tool":     map[string]any{"name": "nuclei", "version": "3.3.0"},
		"assets": []map[string]any{
			{"id": "a1", "type": "domain", "value": "scoped-asset." + ten.Slug + ".example.com"},
			{"id": "a2", "type": "domain", "value": "oos-asset." + ten.Slug + ".example.com"},
			{"id": "a3", "type": "domain", "value": "victim-asset." + ten.Slug + ".example.com"},
		},
		"findings": []map[string]any{
			{"type": "vulnerability", "title": ten.Name + " scoped finding", "severity": "high", "rule_id": "matrix-1", "asset_ref": "a1", "description": "matrix"},
			{"type": "vulnerability", "title": ten.Name + " oos finding", "severity": "high", "rule_id": "matrix-2", "asset_ref": "a2", "description": "matrix"},
			{"type": "vulnerability", "title": ten.Name + " victim finding", "severity": "medium", "rule_id": "matrix-3", "asset_ref": "a3", "description": "matrix"},
		},
	}
	raw, _ := json.Marshal(report)
	sum := sha256.Sum256(raw)
	cred := func(r *http.Request) {
		key(r)
		r.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":")
	}
	req := func(r *http.Request) {
		cred(r)
		r.Header.Set("Content-Type", "application/vnd.openctem.ctis.v1+json")
	}
	resp, err := w.c.doRaw(req, "PUT", "/api/v2/sensor/results/"+id, raw)
	must(t, ten.Name+": ingest", 200, 201, 202)(resp, err)
}

// seedPrincipals creates every user principal of a tenant. full=false
// creates only the system roles (enough for cross-tenant checks).
func (w *world) seedPrincipals(t testing.TB, ten *tenant, full bool) {
	t.Helper()
	sys := func(local, slug, roleID string) *principal {
		p := w.invite(t, ten, local, []string{roleID})
		p.perms, p.fullData = systemRolePerms(slug)
		p.teamRole = slug
		p.adminBypass = slug == "admin" || slug == "owner"
		p.scoped = !p.fullData
		return p
	}
	sys("admin", "admin", roleAdmin)
	member := sys("member", "member", roleMember)
	sys("viewer", "viewer", roleViewer)
	// The plain member is in no group: it sees no asset data at all.
	member.scoped = true
	// Victim account the matrix may suspend, offboard, demote or erase.
	v := w.invite(t, ten, "victim", []string{roleMember})
	ten.set("user.victim", v.userID)
	ten.set("member.victim", w.membershipID(t, ten, v.userID))
	w.drop(v)

	// A suspended member keeps the access token it held before: every
	// route must refuse it.
	s := w.invite(t, ten, "suspended", []string{roleMember})
	must(t, "suspend member")(w.as(t, ten.owner, "POST", "/api/v1/tenants/"+ten.Slug+"/members/"+w.membershipID(t, ten, s.userID)+"/suspend", map[string]any{"reason": "authz matrix"}))
	s.Kind, s.perms = kindRevoked, map[string]bool{}
	if !full {
		return
	}

	scoped := sys("scoped-member", "member", roleMember)
	scoped.scoped = true
	must(t, "scope group member")(w.as(t, ten.owner, "POST", "/api/v1/groups/"+ten.get("group.scope")+"/members",
		map[string]any{"user_id": scoped.userID, "role": "member"}))

	for _, cr := range customRoles {
		id := w.createRole(t, ten, cr.slug, cr.fullData, cr.perms, "")
		p := w.invite(t, ten, "custom-"+cr.slug, []string{id})
		p.perms, p.fullData, p.teamRole = toSet(cr.perms), cr.fullData, teamMember
		p.scoped = !cr.fullData
	}
	near := nearAdminPerms()
	id := w.createRole(t, ten, "near-admin", true, near, "")
	p := w.invite(t, ten, "custom-near-admin", []string{id})
	p.perms, p.fullData, p.teamRole = toSet(near), true, teamMember

	for _, tpl := range permission.RoleTemplates() {
		perms := permission.ToStrings(tpl.Permissions)
		id := w.createRole(t, ten, "tpl-"+tpl.ID, tpl.HasFullDataAccess, perms, tpl.ID)
		p := w.invite(t, ten, "tpl-"+tpl.ID, []string{id})
		p.perms, p.fullData, p.teamRole = toSet(perms), tpl.HasFullDataAccess, teamMember
		p.scoped = !tpl.HasFullDataAccess
	}

	// Group-derived permissions: a viewer whose group carries the
	// writer-no-approve role.
	gp := sys("group-derived", "viewer", roleViewer)
	must(t, "role group member")(w.as(t, ten.owner, "POST", "/api/v1/groups/"+ten.get("group.role")+"/members",
		map[string]any{"user_id": gp.userID, "role": "member"}))
	must(t, "group role", 200, 201, 204)(w.as(t, ten.owner, "POST", "/api/v1/groups/"+ten.get("group.role")+"/roles",
		map[string]any{"role_id": ten.get("role.writer-no-approve")}))
	gp.perms = union(gp.perms, toSet(customRoles[1].perms))
	gp.scoped = true
	w.resignIn(t, gp)
}

// drop removes a principal from the matrix roster (it stays signed in).
func (w *world) drop(p *principal) {
	delete(w.byName, p.Name)
	for i, q := range w.order {
		if q == p {
			w.order = append(w.order[:i], w.order[i+1:]...)
			return
		}
	}
}

// seedMachines adds the API keys, the sensor and the anonymous caller.
func (w *world) seedMachines(t testing.TB, ten *tenant) {
	t.Helper()
	writer := w.byName[ten.Name+"/custom-writer-no-approve"]
	admin := w.byName[ten.Name+"/admin"]
	mint := func(owner *principal, name string, scopes []string) (string, response) {
		r, err := w.c.do(owner.cred, "POST", "/api/v1/api-keys", map[string]any{"name": name, "scopes": scopes, "expires_in_days": 30, "rate_limit": 100000})
		if err != nil {
			t.Fatalf("mint %s: %v", name, err)
		}
		k := jsonID(r, "key")
		if k == "" {
			k = jsonID(r, "api_key")
		}
		return k, r
	}
	addKey := func(name string, owner *principal, scopes []string) *principal {
		k, r := mint(owner, ten.Slug+"-"+name, scopes)
		if k == "" {
			t.Logf("%s: mint %s refused: %s", ten.Name, name, r)
			return nil
		}
		// The key may exercise its scopes narrowed to its owner's grant.
		eff := map[string]bool{}
		for _, s := range scopes {
			if owner.holds(s) {
				eff[s] = true
			}
		}
		return w.add(&principal{Name: ten.Name + "/key-" + name, T: ten, Kind: kindAPIKey, cred: bearer(k),
			perms: eff, teamRole: "", fullData: false, scoped: true, userID: owner.userID})
	}
	if writer != nil {
		addKey("writer-narrow", writer, []string{"assets:read"})
		// Scopes beyond the creator's own grant: minting must refuse (or
		// narrow the key to what the creator holds).
		if k, r := mint(writer, ten.Slug+"-writer-overreach", []string{"assets:read", "team:roles:write", "audit:read", "assets:delete"}); k != "" {
			ten.set("key.overreach", k)
			w.add(&principal{Name: ten.Name + "/key-writer-overreach", T: ten, Kind: kindAPIKey, cred: bearer(k),
				perms: map[string]bool{"assets:read": true}, scoped: true, userID: writer.userID})
		} else {
			ten.ids["key.overreach.refused"] = fmt.Sprint(r.Status)
		}
	}
	if admin != nil {
		addKey("admin-broad", admin, []string{"assets:read", "findings:read", "team:members:read", "audit:read", "settings:read"})
	}
	w.add(&principal{Name: ten.Name + "/sensor", T: ten, Kind: kindSensor, cred: bearer(ten.get("sensorkey.matrix")), perms: map[string]bool{}})
}

var _ = fmt.Sprintf
