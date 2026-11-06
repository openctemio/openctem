package citrustscopeplan

import (
	"strings"
	"testing"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestRender(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	out := render([]cirunapp.ScopePlanTenant{
		{TenantID: a, Trusts: 2, ManagedTrusts: 1, AdoptableTrust: 1, Managed: map[string]int{"kept": 1},
			Adoptable: map[string]int{"created": 1, "linked": 1}, Refused: []string{"z: no", "a: no"}},
		{TenantID: b, Trusts: 1, AdoptableTrust: 1, Managed: map[string]int{}, Adoptable: map[string]int{"created": 2}},
	})
	for _, want := range []string{
		"tenant " + a.String() + ": trusts 2",
		"  managing scope 1: created 0, linked 0, kept 1, retired 0, removed 0, refused 0",
		"  if turned on 1: created 1, linked 1, kept 0",
		"  refused a: no\n  refused z: no",
		"total (dry run): tenants 2, trusts 3\n  managing scope 1:",
		"  if turned on 2: created 3, linked 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render lacks %q:\n%s", want, out)
		}
	}
	if got := splitList(" a.example , ,b.example"); len(got) != 2 || got[0] != "a.example" {
		t.Errorf("splitList = %v", got)
	}
	if u := readOnlyURL("postgres://u:p@h:5432/db?sslmode=disable"); !strings.Contains(u, "default_transaction_read_only=on") {
		t.Errorf("readOnlyURL = %s", u)
	}
}
