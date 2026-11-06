//go:build authzmatrix

package authzmatrix

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
)

var (
	paramRe = regexp.MustCompile(`\{[A-Za-z_]+\}`)
	uuidRe  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// harvestIDs collects the "id" values of a JSON document, in order.
func harvestIDs(body []byte) []string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			if s, ok := t["id"].(string); ok && uuidRe.MatchString(s) {
				out = append(out, s)
			}
			for _, c := range t {
				walk(c)
			}
		case []any:
			for _, c := range t {
				walk(c)
			}
		}
	}
	walk(v)
	return out
}

// fixedIDs maps a collection to a seeded resource of the tenant, for
// collections the list harvest may not reach.
var fixedIDs = map[string]string{
	"/api/v1/assets": "asset.scoped", "/api/v1/findings": "finding.scoped", "/api/v1/sensors": "sensor.victim",
	"/api/v1/groups": "group.victim", "/api/v1/roles": "role.victim", "/api/v1/asset-groups": "assetgroup",
	"/api/v1/scans": "scan", "/api/v1/remediation/campaigns": "campaign", "/api/v1/users": "user.victim",
	"/api/v1/tenants/{tenant}/members": "user.victim", "/api/v1/organization/members": "user.victim",
}

// byParam names a seeded resource by the parameter's own name, for
// collections that have no list route of their own.
var byParam = map[string]string{
	"findingId": "finding.scoped", "finding_id": "finding.scoped", "assetId": "asset.scoped", "asset_id": "asset.scoped",
	"groupId": "group.victim", "group_id": "group.victim", "roleId": "role.victim", "role_id": "role.victim",
	"userId": "user.victim", "user_id": "user.victim", "sensorId": "sensor.victim", "sensor_id": "sensor.victim",
	"member_id": "member.victim",
}

// paramValue is the tenant's value for one parameter of a route.
func (ten *tenant) paramValue(path, name string) string {
	if v := ten.coll[templateUpTo(path, name)]; v != "" {
		return v
	}
	if k, ok := byParam[name]; ok {
		return ten.get(k)
	}
	return ""
}

// harvest lists every parameterless GET collection as the owner, then the
// collections one level down, and keeps the first id of each as the value
// the matrix puts in that collection's parameter.
func (w *world) harvest(t testing.TB, routes []route) {
	t.Helper()
	for _, ten := range w.tenants {
		ten.coll = map[string]string{}
		for c, k := range fixedIDs {
			if id := ten.get(k); id != "" {
				ten.coll[c] = id
			}
		}
	}
	for pass := 0; pass < 2; pass++ {
		for _, r := range routes {
			if r.Method != "GET" || r.console() || strings.HasPrefix(r.Path, "/api/v2/") || strings.HasPrefix(r.Path, "/scim/") {
				continue
			}
			for _, ten := range w.tenants {
				if _, done := ten.coll[r.Path]; done {
					continue
				}
				p, ok := ten.fill(r.Path, false)
				if !ok {
					continue
				}
				resp, err := w.c.do(ten.owner.cred, "GET", p, nil)
				if err != nil || resp.Status != 200 {
					continue
				}
				ids := harvestIDs(resp.Body)
				for _, id := range ids {
					ten.addMarker(id)
				}
				if len(ids) > 0 {
					ten.coll[r.Path] = ids[0]
				}
			}
		}
	}
	// An id both organizations see is a shared catalog row, not tenant data.
	if len(w.tenants) == 2 {
		a, b := w.tenants[0], w.tenants[1]
		for _, m := range a.markerList() {
			if b.markers[m] {
				a.mu.Lock()
				delete(a.markers, m)
				a.mu.Unlock()
				b.mu.Lock()
				delete(b.markers, m)
				b.mu.Unlock()
			}
		}
	}
}

// fill puts the tenant's values in a route's parameters. strict=false
// leaves unknown parameters unresolved (ok=false); the matrix calls it with
// strict=true and gets a fresh random id for those.
func (ten *tenant) fill(path string, strict bool) (string, bool) {
	ok := true
	out := path
	for {
		idx := paramRe.FindStringIndex(out)
		if idx == nil {
			break
		}
		name := out[idx[0]+1 : idx[1]-1]
		val := ""
		switch name {
		case "tenant", "org":
			val = ten.Slug
		default:
			val = ten.paramValue(path, name)
		}
		if val == "" {
			if !strict {
				ok = false
			}
			val = uuid.NewString()
		}
		out = out[:idx[0]] + val + out[idx[1]:]
	}
	return out, ok
}

// templateUpTo is the route template up to (not including) the named
// parameter.
func templateUpTo(path, name string) string {
	i := strings.Index(path, "{"+name+"}")
	if i < 0 {
		return ""
	}
	return strings.TrimSuffix(path[:i], "/")
}

// fillCross fills a route with this tenant's values and reports whether at
// least one parameter got a real value of this tenant.
func (ten *tenant) fillCross(path string) (string, bool) {
	real := false
	out := paramRe.ReplaceAllStringFunc(path, func(m string) string {
		name := m[1 : len(m)-1]
		if name == "tenant" || name == "org" {
			real = true
			return ten.Slug
		}
		if v := ten.paramValue(path, name); v != "" {
			real = true
			return v
		}
		return uuid.NewString()
	})
	return out, real
}
