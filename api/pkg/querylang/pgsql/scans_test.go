package pgsql_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/querylang"
)

func scanReader(perms ...string) querylang.Principal {
	pr := memberOf(tenantA)
	pr.Has = func(p string) bool {
		for _, x := range perms {
			if x == p {
				return true
			}
		}
		return false
	}
	return pr
}

// The scans entity parses the short form, binds every value and renders a
// tenant-first statement over the scans table with the server's rules.
func TestScansEntity_RendersTenantFirstWithServerRules(t *testing.T) {
	pr := scanReader(permission.ScansRead.String())
	_, st := render(t, `scans where status = "active" and tag in ("prod", "edge") and total_runs >= 3 and not origin = "system" and name ~ "nightly"`, pr)
	if !strings.Contains(st.SQL, "FROM scans WHERE scans.tenant_id = $1") {
		t.Errorf("not tenant first: %s", st.SQL)
	}
	for _, rule := range []string{"scans.archived_at IS NOT NULL", "scans.ad_hoc"} {
		if !strings.Contains(st.SQL, rule) {
			t.Errorf("the server rule %q is missing: %s", rule, st.SQL)
		}
	}
	if st.Args[0] != tenantA.String() {
		t.Errorf("first argument is %v, want the caller's tenant", st.Args[0])
	}
	// a short-form text without the entity word runs on the same entity
	ent, _ := querylang.Lookup("scans")
	q, _, err := querylang.ParseFilter(ent, "status=active nightly")
	if err != nil {
		t.Fatal(err)
	}
	if got := querylang.FormatShort(ent, q); got != "status=active nightly" {
		t.Errorf("canonical short text = %q", got)
	}
}

// The visibility fields are the server's: a query naming them gets the
// answer a missing field gets.
func TestScansEntity_ServerFieldsAreUnknown(t *testing.T) {
	pr := scanReader(permission.ScansRead.String())
	opts := querylang.BuildOptions{Now: func() time.Time { return time.Now() }}
	msg := func(src string) string {
		t.Helper()
		_, err := querylang.Compile(src, pr, opts)
		if err == nil {
			t.Fatalf("%q compiled", src)
		}
		b, _ := json.Marshal(err.(*querylang.Error).Details)
		return string(b)
	}
	for _, name := range []string{"archived", "ad_hoc", "text_search"} {
		got := msg("scans where " + name + " = true")
		missing := strings.Repeat("z", len(name))
		want := msg("scans where " + missing + " = true")
		if strings.ReplaceAll(got, name, "X") != strings.ReplaceAll(want, missing, "X") {
			t.Errorf("%s answers differently from a missing field:\n%s\n%s", name, got, want)
		}
	}
}

func TestScansEntity_NeedsScansRead(t *testing.T) {
	_, err := querylang.Compile(`scans where status=active`, scanReader(permission.FindingsRead.String()), querylang.BuildOptions{})
	if err == nil || !strings.Contains(err.Error(), permission.ScansRead.String()) {
		t.Errorf("compile without scans:read = %v", err)
	}
}

func TestScansEntity_ValuesAreBound(t *testing.T) {
	pr := scanReader(permission.ScansRead.String())
	base := func(v string) string {
		_, st := render(t, `scans where name ~ "`+v+`" and tag = "`+v+`"`, pr)
		return ph.ReplaceAllString(ws.ReplaceAllString(st.SQL, " "), "$?")
	}
	if a, b := base("aaaa"), base(`x'; DROP TABLE scans; --`); a != b {
		t.Errorf("SQL text changed with the value:\n%s\n%s", a, b)
	}
}

// A refused scans query never quotes a value the caller typed.
func TestScansEntity_ErrorsDoNotEchoValues(t *testing.T) {
	const probe = "VALUE-PROBE-3"
	pr := scanReader(permission.ScansRead.String())
	for _, src := range []string{
		`scans where status = "` + probe + `"`,
		`scans where scan_type in ("` + probe + `")`,
		`scans where id = "` + probe + `"`,
		`scans where total_runs > "` + probe + `"`,
		`scans where created_at > "` + probe + `"`,
		`scans where origin = "` + probe + `"`,
		`scans where archived = "` + probe + `"`,
	} {
		_, err := querylang.Compile(src, pr, querylang.BuildOptions{})
		if err == nil {
			t.Errorf("%q compiled", src)
			continue
		}
		qe, ok := err.(*querylang.Error)
		if !ok {
			t.Errorf("%q: %v", src, err)
			continue
		}
		b, _ := json.Marshal(qe.Details)
		if strings.Contains(string(b), probe) {
			t.Errorf("%q: the error quotes the value: %s", src, b)
		}
	}
}
