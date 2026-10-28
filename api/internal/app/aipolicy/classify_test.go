package aipolicy

import (
	"context"
	"errors"
	"testing"

	pentestdom "github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestClass_Ordering(t *testing.T) {
	if !ClassPublic.AtMost(ClassInternal) || !ClassInternal.AtMost(ClassInternal) || ClassRestricted.AtMost(ClassInternal) {
		t.Fatal("class ordering broken")
	}
	if Class("bogus").AtMost(ClassTenantOnly) || ClassPublic.AtMost(Class("bogus")) {
		t.Fatal("an unknown class must fail closed")
	}
	if _, err := ParseClass("secret"); err == nil {
		t.Fatal("unknown class parsed")
	}
}

func TestClassify_WithholdsAboveCeiling(t *testing.T) {
	fields := []Field{FieldFindingCVE, FieldFindingTitle, FieldFindingSnippet, Field("finding.raw_http")}
	allowed, withheld, class := Classify(fields, ClassInternal)
	if len(allowed) != 2 || class != ClassInternal {
		t.Fatalf("allowed %v class %s", allowed, class)
	}
	if len(withheld) != 2 || withheld[0] != Field("finding.raw_http") || withheld[1] != FieldFindingSnippet {
		t.Fatalf("withheld %v", withheld)
	}
	_, _, class = Classify([]Field{FieldFindingCVE}, ClassInternal)
	if class != ClassPublic {
		t.Fatalf("public-only bundle classed %s", class)
	}
	// An unregistered field is tenant-only: never sent, whatever the ceiling.
	if Allowed(Field("finding.new_thing"), ClassRestricted) {
		t.Fatal("unregistered field allowed")
	}
	for _, f := range AllowedFields(ClassPublic) {
		if ClassOf(f) != ClassPublic {
			t.Fatalf("%s is not public", f)
		}
	}
}

// The class ceiling does not replace the campaign policy: a TLP:RED or
// AI-off campaign finding is refused before any bundle is built, even under
// the highest ceiling.
func TestClassify_CampaignRefusalStillApplies(t *testing.T) {
	tenantID := shared.NewID()
	for _, tc := range []struct {
		tlp   pentestdom.TLP
		aiOff bool
	}{{pentestdom.TLPRed, false}, {pentestdom.TLPClear, true}} {
		c := campaign(t, tenantID, tc.tlp, tc.aiOff)
		id := c.ID()
		f := finding(t, tenantID, vulnerability.FindingSourcePentest, &id)
		e := New(fakePolicies{maxTLP: "amber"}, &fakeCampaigns{byID: map[shared.ID]*pentestdom.Campaign{id: c}})
		if err := e.CheckFinding(context.Background(), tenantID, f); !errors.Is(err, ErrRestricted) {
			t.Fatalf("tlp %s aiOff %v: want refusal, got %v", tc.tlp, tc.aiOff, err)
		}
		if !Allowed(FieldFindingSnippet, ClassRestricted) {
			t.Fatal("restricted ceiling allows the snippet field")
		}
	}
}
