package tenant

import (
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

func TestMembersWithoutGroupSee(t *testing.T) {
	for _, v := range []string{MembersWithoutGroupSeeEverything, MembersWithoutGroupSeeNothing} {
		if err := ValidateMembersWithoutGroupSee(v); err != nil {
			t.Errorf("%q rejected: %v", v, err)
		}
	}
	for _, v := range []string{"", "all", "Nothing", "none"} {
		if err := ValidateMembersWithoutGroupSee(v); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%q accepted (err %v)", v, err)
		}
	}
	if RestrictsMembersWithoutGroup(MembersWithoutGroupSeeEverything) {
		t.Error("everything must not restrict")
	}
	if !RestrictsMembersWithoutGroup(MembersWithoutGroupSeeNothing) || !RestrictsMembersWithoutGroup("garbage") {
		t.Error("nothing, and any unexpected value, must restrict (fail closed)")
	}
}
