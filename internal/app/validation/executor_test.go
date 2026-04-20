package validation

import (
	"errors"
	"testing"
)

// Q2/WS-D (post-refactor): tests the API-side selection policy.
// No in-process executor runs here — Select picks the ExecutorKind
// string that the dispatcher will queue for the agent.

func TestDefaultSelector_PrefersSafeCheck(t *testing.T) {
	s := DefaultSelector{}
	got, err := s.Select("T1046", nil, []ExecutorKind{KindSafeCheck, KindNuclei})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if got != KindSafeCheck {
		t.Fatalf("got %q, want safe-check (preferred)", got)
	}
}

func TestDefaultSelector_FallsBackToNuclei(t *testing.T) {
	// Technique not in safe-check's curated list → fall through.
	s := DefaultSelector{}
	got, err := s.Select("T1190", nil, []ExecutorKind{KindSafeCheck, KindNuclei})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if got != KindNuclei {
		t.Fatalf("got %q, want nuclei", got)
	}
}

func TestDefaultSelector_ART_RequiresProfile(t *testing.T) {
	s := DefaultSelector{}
	_, err := s.Select("T1059", nil, []ExecutorKind{KindAtomicRedTeam})
	if !errors.Is(err, ErrNoExecutor) {
		t.Fatalf("nil profile must refuse ART: %v", err)
	}
	got, err := s.Select("T1059",
		&AttackerProfile{Capabilities: []string{"credentialed"}},
		[]ExecutorKind{KindAtomicRedTeam})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if got != KindAtomicRedTeam {
		t.Fatalf("got %q, want atomic-red-team", got)
	}
}

func TestDefaultSelector_Caldera_RequiresProfile(t *testing.T) {
	s := DefaultSelector{}
	_, err := s.Select("T1059", &AttackerProfile{}, []ExecutorKind{KindCaldera})
	if !errors.Is(err, ErrNoExecutor) {
		t.Fatal("empty capabilities must refuse caldera")
	}
}

func TestDefaultSelector_EmptyTechniqueRejects(t *testing.T) {
	s := DefaultSelector{}
	_, err := s.Select("", nil, []ExecutorKind{KindSafeCheck})
	if !errors.Is(err, ErrNoExecutor) {
		t.Fatalf("empty technique must fail: %v", err)
	}
}

func TestDefaultSelector_NoAvailable(t *testing.T) {
	s := DefaultSelector{}
	_, err := s.Select("T1046", nil, nil)
	if !errors.Is(err, ErrNoExecutor) {
		t.Fatalf("want ErrNoExecutor, got %v", err)
	}
}

func TestEvidence_LegacyExecutorAccessor(t *testing.T) {
	ev := Evidence{ExecutorKind: "safe-check"}
	if ev.Executor() != "safe-check" {
		t.Fatalf("legacy Executor() getter broken")
	}
}
