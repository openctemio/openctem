package middleware

import (
	"encoding/json"
	"flag"
	"os"
	"reflect"
	"testing"
)

var updateAccountRoutes = flag.Bool("update", false, "rewrite api/account-routes.json from the allow-list")

const accountRoutesFile = "../../../../api/account-routes.json"

type accountRoutesDoc struct {
	Comment string   `json:"_comment"`
	Routes  []string `json:"routes"`
}

// The account allow-list is published as api/account-routes.json for the web
// (it proxies only these for the account space). The file and the list the
// middleware enforces never differ.
func TestAccountRoutesFile_MatchesTheAllowList(t *testing.T) {
	raw, err := os.ReadFile(accountRoutesFile)
	if err != nil {
		t.Fatal(err)
	}
	var doc accountRoutesDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	want := TenantlessRoutes()
	if *updateAccountRoutes {
		doc.Routes = want
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(accountRoutesFile, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !reflect.DeepEqual(doc.Routes, want) {
		t.Fatalf("api/account-routes.json differs from the allow-list: run go test ./internal/infra/http/middleware -run TestAccountRoutesFile -update\nfile: %v\nlist: %v", doc.Routes, want)
	}
}
