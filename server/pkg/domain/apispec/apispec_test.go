package apispec

import (
	"strconv"
	"strings"
	"testing"
)

func ops(t *testing.T, s *Spec) map[string]Operation {
	t.Helper()
	out := map[string]Operation{}
	for _, o := range s.Operations {
		out[o.Method+" "+o.Path] = o
	}
	return out
}

func names(o Operation) string {
	parts := make([]string, 0, len(o.Params))
	for _, p := range o.Params {
		parts = append(parts, p.Location+":"+p.Name)
	}
	return strings.Join(parts, ",")
}

const openapi3 = `
openapi: 3.0.3
info: {title: Shop, version: "2"}
paths:
  /users/{userId}:
    parameters:
      - {name: userId, in: path, required: true}
    get:
      parameters:
        - $ref: '#/components/parameters/Page'
        - $ref: 'https://evil.example/remote.yaml#/x'
    delete:
      deprecated: true
  /orders:
    post:
      requestBody:
        content:
          application/json:
            schema: {$ref: '#/components/schemas/Order'}
components:
  parameters:
    Page: {name: page, in: query}
  schemas:
    Order:
      required: [sku]
      properties:
        sku: {type: string, example: SECRET-EXAMPLE}
        note: {type: string}
`

func TestParse_OpenAPI3(t *testing.T) {
	s, err := Parse([]byte(openapi3), "")
	if err != nil {
		t.Fatal(err)
	}
	if s.Format != FormatOpenAPI3 || s.Title != "Shop" || len(s.Operations) != 3 {
		t.Fatalf("spec = %+v", s)
	}
	m := ops(t, s)
	if got := names(m["GET /users/{userId}"]); got != "path:userId,query:page" {
		t.Errorf("GET params = %s (a remote $ref must never be read)", got)
	}
	if !m["DELETE /users/{userId}"].Deprecated {
		t.Error("deprecated lost")
	}
	if got := names(m["POST /orders"]); got != "json:/note,json:/sku" {
		t.Errorf("body params = %s", got)
	}
	for _, o := range s.Operations {
		if strings.Contains(names(o), "SECRET") {
			t.Fatal("an example value was read")
		}
	}
}

func TestParse_Swagger2BasePathAndBody(t *testing.T) {
	doc := `{"swagger":"2.0","basePath":"/api/v1","info":{"title":"Old"},"paths":{"/pets/{id}":{
		"put":{"parameters":[{"in":"path","name":"id"},{"in":"formData","name":"photo"},
		{"in":"body","name":"b","schema":{"properties":{"name":{}}}}]}}}}`
	s, err := Parse([]byte(doc), "")
	if err != nil {
		t.Fatal(err)
	}
	m := ops(t, s)
	if got := names(m["PUT /api/v1/pets/{id}"]); got != "path:id,form:photo,json:/name" {
		t.Fatalf("ops = %+v", s.Operations)
	}
}

func TestParse_PostmanVariablesAndNamesOnly(t *testing.T) {
	doc := `{"info":{"name":"Coll","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
	"item":[{"name":"folder","item":[{"name":"get","request":{"method":"GET","url":{"raw":"{{baseUrl}}/users/:id?token=SECRET",
	"path":["users",":id"],"query":[{"key":"token","value":"SECRET"}]}}}]},
	{"name":"login","request":{"method":"POST","url":"https://api.example.com/login","body":{"mode":"urlencoded",
	"urlencoded":[{"key":"password","value":"SECRET"}]}}}]}`
	s, err := Parse([]byte(doc), "")
	if err != nil {
		t.Fatal(err)
	}
	m := ops(t, s)
	if names(m["GET /users/{id}"]) != "query:token" || names(m["POST /login"]) != "form:password" {
		t.Fatalf("ops = %+v", s.Operations)
	}
}

func TestParse_HARNeverKeepsValues(t *testing.T) {
	doc := `{"log":{"entries":[{"request":{"method":"POST","url":"https://a.example.com/api/session?sid=SECRET",
	"queryString":[{"name":"sid","value":"SECRET"}],"headers":[{"name":"Authorization","value":"Bearer SECRET"}],
	"cookies":[{"name":"s","value":"SECRET"}],"postData":{"mimeType":"application/x-www-form-urlencoded",
	"params":[{"name":"user","value":"SECRET"}],"text":"user=SECRET"}}}]}}`
	s, err := Parse([]byte(doc), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Operations) != 1 || names(s.Operations[0]) != "query:sid,form:user" || s.Operations[0].Path != "/api/session" {
		t.Fatalf("ops = %+v", s.Operations)
	}
}

func TestParse_GraphQLIntrospection(t *testing.T) {
	doc := `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},
	"types":[{"name":"Query","fields":[{"name":"user"},{"name":"orders"}]},{"name":"Mutation","fields":[{"name":"deleteUser"}]},
	{"name":"User","fields":[{"name":"email"}]}]}}}`
	s, err := Parse([]byte(doc), "/api/graphql")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Operations) != 1 || s.Operations[0].Path != "/api/graphql" || names(s.Operations[0]) != "graphql_arg:user,graphql_arg:orders,graphql_arg:deleteUser" {
		t.Fatalf("ops = %+v", s.Operations)
	}
}

func TestParse_Hostile(t *testing.T) {
	bomb := "a: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n"
	prev := "a"
	for i := 0; i < 12; i++ {
		n := string(rune('b' + i))
		bomb += n + ": &" + n + " [*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + "]\n"
		prev = n
	}
	if _, err := Parse([]byte(bomb), ""); err == nil {
		t.Error("a YAML alias bomb was accepted")
	}
	if _, err := Parse([]byte(`{"hello":"world"}`), ""); err == nil {
		t.Error("an unknown document was accepted")
	}
	if _, err := Parse(make([]byte, MaxSpecBytes+1), ""); err == nil {
		t.Error("an oversized document was accepted")
	}
	big := `{"openapi":"3.0.0","paths":{`
	for i := 0; i < MaxOperations+10; i++ {
		if i > 0 {
			big += ","
		}
		big += `"/p` + strings.Repeat("x", 1) + string(rune('a'+i%26)) + `/` + strings.Repeat("y", i%7) + `/` + strconv.Itoa(i) + `":{"get":{}}`
	}
	big += "}}"
	s, err := Parse([]byte(big), "")
	if err != nil || len(s.Operations) != MaxOperations || s.Truncated != 10 {
		t.Fatalf("cap: %d ops, %d truncated, err %v", len(s.Operations), s.Truncated, err)
	}
}

func TestMatchKey(t *testing.T) {
	if MatchKey("get", "/users/{userId}/orders") != MatchKey("GET", "/users/{int}/orders") {
		t.Fatal("a spec variable must match a scan variable")
	}
	if MatchKey("GET", "/users/me") == MatchKey("GET", "/users/{int}") {
		t.Fatal("a literal segment matched a variable")
	}
}
