package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const baseSpec = `
basePath: /api/v1
paths:
  /assets:
    get:
      parameters:
        - {name: page, in: query, type: integer}
      responses:
        "200": {description: OK, schema: {$ref: "#/definitions/handler.AssetList"}}
    post:
      parameters:
        - {name: body, in: body, required: true, schema: {$ref: "#/definitions/handler.CreateAsset"}}
      responses:
        "201": {description: Created, schema: {$ref: "#/definitions/handler.Asset"}}
  /assets/{id}:
    delete:
      parameters:
        - {name: id, in: path, required: true, type: string}
      responses:
        "204": {description: No Content}
definitions:
  handler.Asset:
    type: object
    properties:
      id: {type: string}
  handler.AssetList:
    type: object
  handler.CreateAsset:
    type: object
    properties:
      name: {type: string}
`

const headSpec = `
basePath: /api/v1
paths:
  /assets:
    get:
      parameters:
        - {name: page, in: query, type: integer, description: reworded}
        - {name: tenant_hint, in: query, required: true, type: string}
      responses:
        "200": {description: OK, schema: {$ref: "#/definitions/handler.AssetList"}}
    post:
      parameters:
        - {name: body, in: body, required: true, schema: {$ref: "#/definitions/handler.CreateAsset"}}
      responses:
        "201": {description: Created, schema: {$ref: "#/definitions/handler.AssetV2"}}
  /assets/{id}/archive:
    post:
      parameters:
        - {name: id, in: path, required: true, type: string}
      responses:
        "204": {description: No Content}
definitions:
  handler.Asset:
    type: object
    properties:
      id: {type: string}
      name: {type: string}
  handler.AssetV2:
    type: object
  handler.AssetList:
    type: object
  handler.CreateAsset:
    type: object
    properties:
      name: {type: string}
`

func writeBundle(t *testing.T, spec, perms, routes string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{"swagger.yaml": spec, "api-route-permissions.json": perms, "routes.txt": routes} {
		if body == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func load(t *testing.T, dir string) *bundle {
	t.Helper()
	b, err := loadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func contains(t *testing.T, section string, items []string, want string) {
	t.Helper()
	for _, it := range items {
		if strings.Contains(it, want) {
			return
		}
	}
	t.Errorf("%s: no line contains %q in %q", section, want, items)
}

func TestCompareReportsContractChanges(t *testing.T) {
	base := load(t, writeBundle(t, baseSpec,
		`{"DELETE /api/v1/assets/{id}": {"permissions":["assets:delete"]}, "POST /api/v1/assets": {"permissions":["assets:write"]}}`,
		"# generated\nGET /api/v1/assets\nPOST /api/v1/assets\nDELETE /api/v1/assets/{}\n"))
	head := load(t, writeBundle(t, headSpec,
		`{"POST /api/v1/assets": {"permissions":["assets:write"],"min_role":"admin"}, "POST /api/v1/assets/{id}/archive": {"permissions":["assets:write"]}}`,
		"GET /api/v1/assets\nPOST /api/v1/assets\nPOST /api/v1/assets/{}/archive\n"))
	r := compare(base, head)

	contains(t, "breaking", r.Breaking, "`DELETE /api/v1/assets/{id}`: operation removed")
	contains(t, "breaking", r.Breaking, "new required query parameter `tenant_hint`")
	contains(t, "breaking", r.Breaking, "`POST /api/v1/assets`: response 201 schema changed")
	contains(t, "additions", r.Additions, "`POST /api/v1/assets/{id}/archive`: operation added")
	contains(t, "additions", r.Additions, "`handler.Asset.name`: property added")
	contains(t, "additions", r.Additions, "`handler.AssetV2`: definition added")
	for _, it := range r.Breaking {
		if strings.Contains(it, "page") {
			t.Errorf("a reworded description was reported as a change: %s", it)
		}
	}

	gates := map[string]gateChange{}
	for _, g := range r.Gates {
		gates[g.Route] = g
	}
	if g := gates["POST /api/v1/assets"]; g.Before == "" || g.After == "" || !strings.Contains(g.After, "admin") {
		t.Errorf("tightened gate not reported: %+v", g)
	}
	if g := gates["DELETE /api/v1/assets/{id}"]; g.After != "" {
		t.Errorf("removed route gate not reported: %+v", g)
	}
	if g := gates["POST /api/v1/assets/{id}/archive"]; g.Before != "" || g.After == "" {
		t.Errorf("new route gate not reported: %+v", g)
	}
	if len(r.RoutesAdd) != 1 || len(r.RoutesDel) != 1 {
		t.Errorf("routes: +%v -%v", r.RoutesAdd, r.RoutesDel)
	}

	out := render(r, "abc", "def")
	for _, want := range []string{Marker, "Potentially breaking", "Route gates", "| `POST /api/v1/assets` |"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
}

func TestIdenticalBundlesReportNothing(t *testing.T) {
	dir := writeBundle(t, baseSpec, `{"POST /api/v1/assets": {"permissions":["assets:write"]}}`, "GET /api/v1/assets\n")
	r := compare(load(t, dir), load(t, dir))
	if !r.empty() {
		t.Fatalf("identical bundles differ: %+v", r)
	}
	if out := render(r, "a", "b"); !strings.Contains(out, "No change") {
		t.Fatalf("unexpected report:\n%s", out)
	}
}

func TestMissingBaseFilesCountAsEmpty(t *testing.T) {
	r := compare(load(t, t.TempDir()), load(t, writeBundle(t, baseSpec, "", "")))
	if len(r.Additions) == 0 || len(r.Breaking) != 0 {
		t.Fatalf("got %+v", r)
	}
}

func TestReportIsCapped(t *testing.T) {
	var r report
	for i := 0; i < maxLines+50; i++ {
		r.Additions = append(r.Additions, "x")
	}
	if out := render(r, "a", "b"); !strings.Contains(out, "… 50 more") {
		t.Fatalf("not capped:\n%s", out[len(out)-200:])
	}
}
