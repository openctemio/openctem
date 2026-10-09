package scope

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestTarget_SetAuthorization(t *testing.T) {
	tgt, err := NewTarget(shared.NewID(), TargetTypeDomain, "*.example.com", "", "u")
	if err != nil {
		t.Fatal(err)
	}
	if tgt.AuthorizationSource() != AuthOwnership || tgt.ProgramID() != nil || tgt.IsProgramEntry() {
		t.Fatal("a new entry is an ownership entry")
	}
	pid := shared.NewID()
	if err := tgt.SetAuthorization(AuthOwnership, &pid); err == nil {
		t.Fatal("an ownership entry must not carry a program")
	}
	if err := tgt.SetAuthorization(AuthProgram, nil); err == nil {
		t.Fatal("a program entry needs its program")
	}
	zero := shared.ID{}
	if err := tgt.SetAuthorization(AuthProgram, &zero); err == nil {
		t.Fatal("a zero program id is no program")
	}
	if err := tgt.SetAuthorization("letterhead", nil); err == nil {
		t.Fatal("an unknown source must be refused")
	}
	if err := tgt.SetAuthorization(AuthProgram, &pid); err != nil {
		t.Fatal(err)
	}
	if !tgt.IsProgramEntry() || !tgt.ProgramID().Equals(pid) || tgt.Origin() != OriginProgram {
		t.Fatalf("program entry: %v %v %v", tgt.AuthorizationSource(), tgt.ProgramID(), tgt.Origin())
	}
	if err := tgt.SetAuthorization(AuthSelfAttestation, nil); err != nil || tgt.ProgramID() != nil {
		t.Fatal("switching away from program clears the program")
	}
}

func TestParseGeneralSource(t *testing.T) {
	for in, want := range map[string]AuthorizationSource{"": AuthOwnership, "ownership": AuthOwnership, "self_attestation": AuthSelfAttestation} {
		if got, err := ParseGeneralSource(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseGeneralSource("program"); !errors.Is(err, ErrProgramEntryViaPrograms) {
		t.Errorf("program entries come only from the programs service: %v", err)
	}
	if _, err := ParseGeneralSource("authorization_letter"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("letters are not open yet: %v", err)
	}
}
