package authzdoc

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func apiRoot(t *testing.T) string {
	t.Helper()
	return "../.."
}

func routeByKey(t *testing.T, routes []Route, key string) Route {
	t.Helper()
	for _, r := range routes {
		if r.Key() == key {
			return r
		}
	}
	t.Fatalf("route %s not parsed", key)
	return Route{}
}

// Spot checks pin how the walker reads each kind of gate.
func TestParseRoutes_ReadsEveryGateKind(t *testing.T) {
	routes, err := ParseRoutes(apiRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("AUTHZDOC_DUMP") != "" {
		b, _ := json.MarshalIndent(routes, "", " ")
		_ = os.WriteFile(os.Getenv("AUTHZDOC_DUMP"), b, 0o600)
	}
	cases := []struct {
		key  string
		want Gate
	}{
		// permission + team role
		{"DELETE /api/v1/tenants/{tenant}", Gate{Permissions: []string{"team:delete"}, MinRole: "owner", StepUp: true}},
		// step-up
		{"POST /api/v1/credentials/{id}/reveal", Gate{Permissions: []string{"findings:credentials:reveal"}, Modules: []string{"credentials"}, StepUp: true}},
		// module gate passed in as an argument
		{"POST /api/v1/pentest/campaigns", Gate{Permissions: []string{"pentest:campaigns:write"}, Modules: []string{"pentest"}}},
	}
	for _, c := range cases {
		got := routeByKey(t, routes, c.key).Gate
		if !reflect.DeepEqual(got, c.want) {
			gb, _ := json.Marshal(got)
			wb, _ := json.Marshal(c.want)
			t.Errorf("%s: gate %s, want %s", c.key, gb, wb)
		}
	}
}
