package sla

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestPolicy_KEVCapDays(t *testing.T) {
	p, err := NewPolicy(shared.NewID(), "p")
	if err != nil {
		t.Fatal(err)
	}
	if p.KEVCapDays() != DefaultKEVCapDays {
		t.Fatalf("new policy cap = %d, want %d", p.KEVCapDays(), DefaultKEVCapDays)
	}
	for _, ok := range []int{0, 1, 14, MaxSLADays} {
		if err := p.UpdateKEVCapDays(ok); err != nil || p.KEVCapDays() != ok {
			t.Fatalf("UpdateKEVCapDays(%d) = %v, cap %d", ok, err, p.KEVCapDays())
		}
	}
	for _, bad := range []int{-1, MaxSLADays + 1} {
		if err := p.UpdateKEVCapDays(bad); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("UpdateKEVCapDays(%d) = %v, want a validation error", bad, err)
		}
	}
	// A reconstituted policy keeps its persisted value, 0 (off) included.
	r := Reconstitute(shared.NewID(), shared.NewID(), nil, "r", "", true, 2, 15, 30, 60, 0, 80, true, nil, true, p.CreatedAt(), p.UpdatedAt())
	if r.KEVCapDays() != DefaultKEVCapDays {
		t.Fatalf("reconstitute default cap = %d", r.KEVCapDays())
	}
	if r.WithKEVCapDays(0).KEVCapDays() != 0 {
		t.Fatal("persisted 0 (off) must be kept")
	}
}
