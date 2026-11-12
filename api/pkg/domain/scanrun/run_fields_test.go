package scanrun

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

var strictRuns = filterspec.Options{Unknown: filterspec.UnknownStrict, Extra: []string{"include_system"}}

func compileRuns(t *testing.T, q string, includeSystem, hideFindingRuns bool) *filterspec.Where {
	t.Helper()
	vals, err := url.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := filterspec.ParseValues(vals, RunFields, strictRuns)
	if err != nil {
		t.Fatalf("parse %q: %v", q, err)
	}
	a, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: shared.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	w, err := filterspec.Compile(RunListRules(spec, includeSystem, hideFindingRuns), RunFields, a)
	if err != nil {
		t.Fatalf("compile %q: %v", q, err)
	}
	return w
}

func TestRunsListCompile_TenantFirstAndRules(t *testing.T) {
	for _, c := range []struct {
		name, query     string
		includeSystem   bool
		hideFindingRuns bool
		want, notWant   []string
	}{
		{"system runs hidden by default", "", false, false, []string{"system"}, []string{"retest"}},
		{"include_system lists them", "", true, false, nil, []string{"system", "retest"}},
		{"naming a kind lists them", "kind=system", false, false, []string{"system"}, []string{"retest"}},
		{"kind_not is not naming a kind", "kind_not=scan", false, false, []string{"system", "scan"}, nil},
		{"finding runs hidden for a caller without findings", "", true, true, []string{"retest", "validation"}, []string{"system"}},
		{"both", "", false, true, []string{"system", "retest", "validation"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := compileRuns(t, c.query, c.includeSystem, c.hideFindingRuns)
			if !strings.HasPrefix(w.SQL, "scan_runs.tenant_id = $1") {
				t.Errorf("tenant predicate not first: %s", w.SQL)
			}
			args := fmt.Sprint(w.Args...)
			for _, v := range c.want {
				if !strings.Contains(args, v) {
					t.Errorf("%q is not bound: %v", v, w.Args)
				}
			}
			for _, v := range c.notWant {
				if strings.Contains(args, v) {
					t.Errorf("%q is bound: %v", v, w.Args)
				}
			}
		})
	}
}

func TestRunsOrigin_PinsTenantOnBothSides(t *testing.T) {
	if !strings.Contains(managedScanSQL, "ms.tenant_id = scan_runs.tenant_id") {
		t.Errorf("origin template does not pin the scan to the run's tenant: %s", managedScanSQL)
	}
}

func TestRunsValuesAreBound(t *testing.T) {
	seeds := []string{`'; DROP TABLE scan_runs; --`, `" OR 1=1`, "x'); SELECT pg_sleep(10); --"}
	for _, s := range seeds {
		vals := url.Values{"status": {s}}
		_, err := filterspec.ParseValues(vals, RunFields, strictRuns)
		if err == nil {
			t.Errorf("status=%q was accepted", s)
			continue
		}
		fe, ok := filterspec.AsError(err)
		if !ok {
			t.Fatal(err)
		}
		if strings.Contains(fe.Error(), s) {
			t.Errorf("error echoes the value: %v", fe)
		}
	}
}

func TestRunsSortFieldsKeepOldNames(t *testing.T) {
	for _, n := range RunListSortFields() {
		f, ok := RunFields.Field(n)
		if !ok || !f.Sortable {
			t.Errorf("sort field %s of the old list is not sortable in the registry", n)
		}
	}
}
