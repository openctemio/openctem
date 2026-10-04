package filterspec

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// marker is in every payload; it must never reach the SQL text.
const marker = "PWNED"

var injectionPayloads = []string{
	`x' OR '1'='1' --` + marker,
	`x"; DROP TABLE findings; --` + marker,
	`$1) OR (1=1` + marker,
	`{arg}` + marker,
	`f.tenant_id` + marker,
	`1; SELECT pg_sleep(10)` + marker,
	`') UNION SELECT password FROM users --` + marker,
	`\'` + marker + `\`,
	`%` + marker + `_%`,
	`ＳＥＬＥＣＴ` + marker, // full-width confusable
	`critical` + marker,
	marker + `::text`,
	`-` + marker,
	`asset.tenant.users.password` + marker,
	`created_by__password__startswith=` + marker,
}

// TestInjectionNeverReachesSQL puts every payload in every position of
// both encodings: param names, field names, operators, values, sort keys
// and q. Each request either fails with *Error or compiles to SQL that
// does not contain the payload, with one bound argument per placeholder.
func TestInjectionNeverReachesSQL(t *testing.T) {
	reg := testRegistry(t)
	actors := map[string]Actor{"admin": adminActor(t), "member": memberActor(t)}
	params := reg.Params()

	check := func(t *testing.T, spec *Spec, err error) {
		t.Helper()
		if err != nil {
			if _, ok := AsError(err); !ok {
				t.Fatalf("parse error is not *Error: %v", err)
			}
			return
		}
		for name, a := range actors {
			w, cerr := Compile(spec, reg, a)
			if cerr != nil {
				if _, ok := AsError(cerr); !ok {
					t.Fatalf("%s: compile error is not *Error: %v", name, cerr)
				}
				continue
			}
			if strings.Contains(w.SQL, marker) || strings.Contains(strings.ToUpper(w.SQL), marker) {
				t.Fatalf("%s: payload reached SQL: %s", name, w.SQL)
			}
			assertPlaceholders(t, w, 1)
			assertValueIndependent(t, reg, spec, a, w)
		}
	}

	run := func(q url.Values, opts Options) {
		t.Helper()
		spec, err := ParseValues(q, reg, opts)
		check(t, spec, err)
	}

	for _, p := range injectionPayloads {
		for _, mode := range []UnknownMode{UnknownWarn, UnknownStrict} {
			opts := testOpts()
			opts.Unknown = mode
			// As a param name.
			run(url.Values{p: {"x"}}, opts)
			// As a value of every param, a sort key and q.
			for _, name := range params {
				run(url.Values{name: {p}}, opts)
				run(url.Values{name: {"high," + p}}, opts)
			}
			run(url.Values{"sort": {p}}, opts)
			run(url.Values{"sort": {"-" + p}}, opts)
		}

		js, _ := json.Marshal(p)
		docs := []string{
			`{"filter":{"field":` + string(js) + `,"op":"in","value":["x"]}}`,
			`{"filter":{"field":"severity","op":` + string(js) + `,"value":["high"]}}`,
			`{"filter":{` + string(js) + `:["x"]}}`,
			`{"sort":[` + string(js) + `]}`,
			`{"q":` + string(js) + `}`,
			`{` + string(js) + `:1}`,
		}
		for _, f := range reg.Fields() {
			for _, op := range f.Ops {
				fj, _ := json.Marshal(f.Name)
				docs = append(docs,
					`{"filter":{"field":`+string(fj)+`,"op":"`+string(op)+`","value":`+string(js)+`}}`,
					`{"filter":{"all":[{"field":`+string(fj)+`,"op":"`+string(op)+`","value":[`+string(js)+`]}]}}`,
				)
			}
		}
		for _, d := range docs {
			spec, err := ParseDocument([]byte(d), reg, testOpts())
			check(t, spec, err)
		}
	}
}

// TestEveryFieldOperatorBindsValues compiles every field × operator with a
// sentinel value and checks the value is only in Args, never in SQL.
func TestEveryFieldOperatorBindsValues(t *testing.T) {
	reg := testRegistry(t)
	sentinel := map[Type]string{
		TypeEnum: "", TypeString: "sentinel" + marker, TypeID: "44444444-4444-4444-4444-444444444444",
		TypeInt: "424242", TypeNumber: "0.4242", TypeBool: "true", TypeTime: "2026-04-24T04:24:42Z",
	}
	for _, f := range reg.Fields() {
		for _, op := range f.Ops {
			v := sentinel[f.Type]
			if f.Type == TypeEnum {
				v = f.Enum[len(f.Enum)-1]
			}
			if op == OpIsNull {
				v = "true"
			}
			name := f.Name
			for _, s := range suffixOps {
				if s.op == op {
					name = f.Name + s.suffix
				}
			}
			if op == OpEq && !f.allows(OpIn) || op == OpIn {
				name = f.Name
			}
			spec, err := ParseValues(url.Values{name: {v}}, reg, Options{Unknown: UnknownStrict, Now: testOpts().Now})
			if err != nil {
				t.Fatalf("%s %s: %v", f.Name, op, err)
			}
			w, err := Compile(spec, reg, SystemActor(tenantA, "test"))
			if err != nil {
				t.Fatalf("%s %s: %v", f.Name, op, err)
			}
			if op != OpIsNull && f.Type != TypeEnum && f.Type != TypeBool && strings.Contains(w.SQL, v) {
				t.Fatalf("%s %s: value in SQL: %s", f.Name, op, w.SQL)
			}
			assertPlaceholders(t, w, 1)
		}
	}
}
