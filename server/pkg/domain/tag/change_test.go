package tag

import (
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestApply_KeepsEveryTagTheChangeDoesNotName(t *testing.T) {
	stored := []string{"team:web", "scanner:nuclei", "pci"}
	got := Apply(stored, Change{Add: []string{"prod", "pci"}, Remove: []string{"team:web", "not-there"}})
	if want := []string{"scanner:nuclei", "pci", "prod"}; !slices.Equal(got, want) {
		t.Fatalf("Apply = %v, want %v", got, want)
	}
	if got := Apply(stored, Change{}); !slices.Equal(got, stored) {
		t.Fatalf("empty change = %v, want %v", got, stored)
	}
}

func TestApply_RemovesByStoredOrNormalizedForm(t *testing.T) {
	got := Apply([]string{"Café", "x"}, Change{Remove: []string{" Café "}})
	if !slices.Equal(got, []string{"x"}) {
		t.Fatalf("Apply = %v, want [x]", got)
	}
}

func TestChangeCheck_RefusesAddAndRemoveOfOneTag(t *testing.T) {
	if err := (Change{Add: []string{"a"}, Remove: []string{" a "}}).Check(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("Check = %v, want a validation error", err)
	}
	if err := (Change{Add: []string{"a"}, Remove: []string{"b"}}).Check(); err != nil {
		t.Fatalf("Check = %v, want nil", err)
	}
}

func TestDiff(t *testing.T) {
	added, removed := Diff([]string{"a", "b"}, []string{"b", "c"})
	if !slices.Equal(added, []string{"c"}) || !slices.Equal(removed, []string{"a"}) {
		t.Fatalf("Diff = %v %v", added, removed)
	}
}
