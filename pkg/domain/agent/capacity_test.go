package agent

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// An agent with max_concurrent_jobs = 0 is not "unconfigured" — it is
// permanently unschedulable. FindAvailableWithCapacity selects on
//
//	current_jobs < max_concurrent_jobs
//
// so 0 < 0 is false on every pass. The agent registers, heartbeats, reports
// healthy and shows online in the UI, and is never handed a single job. Nothing
// errors, because nothing went wrong — it simply never matches.
//
// This was found by creating an agent through the public API without naming the
// field: the trigger came back "No tenant agent available" while the agent was
// sitting there online with the right tool.
//
// The database already had the right answer: agents.max_concurrent_jobs carries
// DEFAULT 5. It was never reached, because the repository writes the field
// explicitly on INSERT — so a zero from the Go layer overrides the schema's own
// default instead of falling back to it. These tests pin the Go side to the same
// number so the two stop disagreeing.

func newTestAgent(t *testing.T) *Agent {
	t.Helper()
	a, err := NewAgent(shared.NewID(), "probe", AgentTypeRunner, "", nil, []string{"gitleaks"}, ExecutionModeDaemon)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	return a
}

// The defect itself: a freshly constructed agent must be schedulable.
func TestNewAgent_IsSchedulableByDefault(t *testing.T) {
	a := newTestAgent(t)

	if a.MaxConcurrentJobs <= 0 {
		t.Fatalf("a new agent has capacity %d; the scheduler requires "+
			"current_jobs < max_concurrent_jobs, so it would never be given work",
			a.MaxConcurrentJobs)
	}
	// The exact condition the availability query applies.
	if !(a.CurrentJobs < a.MaxConcurrentJobs) {
		t.Errorf("current_jobs=%d max_concurrent_jobs=%d fails the availability test",
			a.CurrentJobs, a.MaxConcurrentJobs)
	}
}

// The Go default must equal the column default, or the two layers disagree about
// what an unspecified capacity means and the mismatch resurfaces elsewhere.
func TestNewAgent_DefaultMatchesTheColumnDefault(t *testing.T) {
	const columnDefault = 5 // agents.max_concurrent_jobs DEFAULT 5

	if DefaultMaxConcurrentJobs != columnDefault {
		t.Errorf("DefaultMaxConcurrentJobs = %d but the agents column defaults to %d; "+
			"pick one number or the schema and the code will keep contradicting each other",
			DefaultMaxConcurrentJobs, columnDefault)
	}
	if a := newTestAgent(t); a.MaxConcurrentJobs != DefaultMaxConcurrentJobs {
		t.Errorf("new agent capacity = %d, want %d", a.MaxConcurrentJobs, DefaultMaxConcurrentJobs)
	}
}

// An explicit capacity must still win — the default is a floor for the
// unspecified case, not an override.
func TestSetMaxConcurrentJobs_ExplicitValueWins(t *testing.T) {
	a := newTestAgent(t)
	a.SetMaxConcurrentJobs(12)
	if a.MaxConcurrentJobs != 12 {
		t.Errorf("capacity = %d, want the explicitly set 12", a.MaxConcurrentJobs)
	}
}

// The setter must not be able to put the entity back into the unschedulable
// state. The HTTP layer validates min=1, but the domain should not depend on a
// caller upstream getting it right.
func TestSetMaxConcurrentJobs_RefusesNonPositive(t *testing.T) {
	for _, bad := range []int{0, -1, -100} {
		a := newTestAgent(t)
		before := a.MaxConcurrentJobs

		a.SetMaxConcurrentJobs(bad)

		if a.MaxConcurrentJobs != before {
			t.Errorf("SetMaxConcurrentJobs(%d) stored %d; a non-positive capacity makes the "+
				"agent permanently unschedulable with no error reported anywhere",
				bad, a.MaxConcurrentJobs)
		}
		if !(a.CurrentJobs < a.MaxConcurrentJobs) {
			t.Errorf("after SetMaxConcurrentJobs(%d) the agent fails the availability test", bad)
		}
	}
}
