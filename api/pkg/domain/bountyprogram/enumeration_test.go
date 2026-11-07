package bountyprogram

import "testing"

func TestJobRules_EnumerationRefusal(t *testing.T) {
	var none *JobRules
	if none.EnumerationRefusal() != "" {
		t.Fatal("no rules refused enumeration")
	}
	r, err := MergeJobRules([]*Program{
		{Name: "A", Rules: Rules{Forbidden: []string{ForbidDoS}}},
		{Name: "B", Rules: Rules{Forbidden: []string{ForbidBruteforce}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.EnumerationRefusal() == "" {
		t.Fatal("the union of the programs' forbidden techniques must refuse enumeration")
	}
	r, _ = MergeJobRules([]*Program{{Name: "A", Rules: Rules{Forbidden: []string{ForbidDoS, ForbidPhysical}}}})
	if r.EnumerationRefusal() != "" {
		t.Fatal("dos and physical do not forbid enumeration")
	}
}
